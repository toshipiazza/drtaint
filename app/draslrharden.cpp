#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "droption.h"

#include "../drtaint.h"
#include "../drtaint_helper.h"
#include "../utils.h"

#include <iostream>
#include <unistd.h>
#include <asm-generic/ioctls.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syscall.h>
#include <termios.h>
#include <time.h>

/* This sample tries to prevent address leaks in an active exploitation
 * scenario. We identify 3 types of leaks (stack, heap, and libc or .text). If
 * we taint all areas on where pointers are introduced, then we can determine
 * if an address leak has occurred on `send`.
 *
 * - all stck addresses are relative to SP, and argv/envp
 * - all heap addresses are relative to `brk` or `mmap2` syscalls
 * - code leaks come in .text and libc leaks
 *   - .text leaks occur when PC is used as an operand
 *   - libc leaks occur via relocations to the GOT
 *     - mmap2 is used to load libraries
 */

#define STCK_POINTER_TAINT 0x41
#define TEXT_POINTER_TAINT 0x42
#define HEAP_POINTER_TAINT 0x43

static void
exit_event(void);

static void
event_thread_init(void *drcontext);

static bool
event_filter_syscall(void *drcontext, int sysnum);

static bool
event_pre_syscall(void *drcontext, int sysnum);

static void
event_post_syscall(void *drcontext, int sysnum);

static dr_emit_flags_t
event_bb_analysis_start(void *drcontext, void *tag, instrlist_t *bb,
                        bool for_trace, bool translating, void **user_data);

static dr_emit_flags_t
event_app_instruction_start(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                            bool for_trace, bool translating, void *user_data);

static dr_emit_flags_t
event_app_instruction_pc(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                           bool for_trace, bool translating, void *user_data);

static void
taint_stack(int argc, char *argv[], char *envp[]);

static droption_t<bool> fail_address_leaks
(DROPTION_SCOPE_CLIENT, "fail_address_leaks", false,
 "Fail all address leaks",
 "If an address leak is about to occur, i.e. via send() or write() system calls,"
 "fail the leaky system call to prevent the leak");

static app_pc exe_start;
static bool tainted_argv;

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL);
    /* get main module address */
    module_data_t *exe = dr_get_main_module();
    DR_ASSERT(exe != NULL);
    if (exe != NULL)
        exe_start = exe->start;
    dr_free_module_data(exe);

    drtaint_init(id);
    drmgr_init();
    drmgr_register_bb_instrumentation_event(event_bb_analysis_start,
                                            event_app_instruction_start,
                                            NULL);

    /* we want the pc instru pass to come before the taint instru pass */
    drmgr_priority_t pri = { sizeof(pri), "drtaint.pc",
                             DRMGR_PRIORITY_NAME_DRTAINT, NULL,
                             DRMGR_PRIORITY_INSERT_DRTAINT };
    drmgr_register_bb_instrumentation_event(NULL,
                                            event_app_instruction_pc,
                                            &pri);

    drreg_options_t drreg_ops = {sizeof(drreg_ops), 3, false};
    auto drreg_ret = drreg_init(&drreg_ops);
    DR_ASSERT(drreg_ret == DRREG_SUCCESS);

    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);

    drmgr_register_thread_init_event(event_thread_init);
    dr_register_exit_event(exit_event);
}

static void
exit_event(void)
{
    void *drcontext = dr_get_current_drcontext();
    drmgr_unregister_bb_instrumentation_event(event_bb_analysis_start);
    drmgr_unregister_bb_insertion_event(event_app_instruction_start);
    drmgr_unregister_bb_insertion_event(event_app_instruction_pc);
    drmgr_unregister_thread_init_event(event_thread_init);
    drtaint_exit();
    drmgr_exit();
    drreg_exit();
}

/****************************************************************************
 * Introduce taint sources
 */

static void
event_thread_init(void *drcontext)
{
    drtaint_set_reg_taint(drcontext, DR_REG_SP,
                          STCK_POINTER_TAINT);
}

static dr_emit_flags_t
event_bb_analysis_start(void *drcontext, void *tag, instrlist_t *bb,
                        bool for_trace, bool translating, void **user_data)
{
    *user_data = (void *)false;
    if (!tainted_argv) {
        module_data_t *mod = dr_lookup_module(dr_fragment_app_pc(tag));
        if (mod != NULL && mod->start == exe_start)
            *user_data = (void *)true;
        dr_free_module_data(mod);
    }
    return DR_EMIT_DEFAULT;
}

static dr_emit_flags_t
event_app_instruction_start(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                            bool for_trace, bool translating, void *user_data)
{
    if (!user_data ||
        !drmgr_is_first_instr(drcontext, instr))
        return DR_EMIT_DEFAULT;

    /* Emit the following instrumentation:
     * ldr r0, [sp]
     * add r1, sp, #4
     * add r2, r1, r0, lsl #2
     * add r2, 4
     * call clean_call
     */
    auto argc = drreg_reservation { bb, instr };
    auto argv = drreg_reservation { bb, instr };
    auto envp = drreg_reservation { bb, instr };

#define MINSERT instrlist_meta_preinsert
    drmgr_disable_auto_predication(drcontext, bb);
    MINSERT(bb, instr, XINST_CREATE_load
            (drcontext,
             opnd_create_reg(argc),
             OPND_CREATE_MEM32(DR_REG_SP, 0)));
    MINSERT(bb, instr, INSTR_CREATE_add
            (drcontext,
             opnd_create_reg(argv),
             opnd_create_reg(DR_REG_SP),
             OPND_CREATE_INT(4)));
    MINSERT(bb, instr, INSTR_CREATE_add_shimm
            (drcontext,
             opnd_create_reg(envp),
             opnd_create_reg(argv),
             opnd_create_reg(argc),
             OPND_CREATE_INT(DR_SHIFT_LSL),
             OPND_CREATE_INT(2)));
    MINSERT(bb, instr, XINST_CREATE_add
            (drcontext,
             opnd_create_reg(envp),
             OPND_CREATE_INT(4)));
    dr_insert_clean_call(drcontext, bb, instr,
                         (void *)taint_stack,
                         false, 3,
                         opnd_create_reg(argc),
                         opnd_create_reg(argv),
                         opnd_create_reg(envp));
#undef MINSERT
    /* Since we're no longer idempotent, we request that this
     * block's translations are stored permanently.
     */
    tainted_argv = true;
    return DR_EMIT_STORE_TRANSLATIONS;
}

static void
taint_stack(int argc, char *argv[], char *envp[])
{
    void *drcontext = dr_get_current_drcontext();

    /* taint argv on the stack */
    for (int i = 0; i < argc; ++i) {
        drtaint_set_app_taint(drcontext, (app_pc)argv+i,
                              STCK_POINTER_TAINT);
    }
    /* taint envp on the stack */
    for (int i = 0; envp[i]; ++i) {
        drtaint_set_app_taint(drcontext, (app_pc)envp+i,
                              STCK_POINTER_TAINT);
    }
}

static dr_emit_flags_t
event_app_instruction_pc(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                         bool for_trace, bool translating, void *user_data)
{
    if (!instr_reads_from_reg(instr, DR_REG_PC,
                              DR_QUERY_INCLUDE_ALL))
        return DR_EMIT_DEFAULT;

    /* If PC is read, we taint it so that the following app instruction
     * spreads its taint accordingly.
     */
    auto sreg1 = drreg_reservation { bb, instr };
    auto sreg2 = drreg_reservation { bb, instr };
    instrlist_meta_preinsert(bb, instr, XINST_CREATE_move
                             (drcontext,
                              opnd_create_reg(sreg2),
                              OPND_CREATE_INT(TEXT_POINTER_TAINT)));
    drtaint_insert_reg_to_taint(drcontext, bb, instr, DR_REG_PC, sreg1);
    instrlist_meta_preinsert(bb, instr, XINST_CREATE_store_1byte
                             (drcontext,
                              OPND_CREATE_MEM8(sreg1, 0),
                              opnd_create_reg(sreg2)));
    return DR_EMIT_DEFAULT;
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    dr_syscall_result_info_t info = { sizeof(info), };
    dr_syscall_get_result_ex(drcontext, &info);

    if (!info.succeeded) {
        /* We only care about tainting if the syscall
         * succeeded.
         */
        return;
    }

    if (sysnum == SYS_mmap2 || sysnum == SYS_brk) {
        /* we want to taint the return value here */
        drtaint_set_reg_taint(drcontext, DR_REG_R0,
                              HEAP_POINTER_TAINT);
        return;
    }
}

/****************************************************************************
 * Introduce taint sinks
 */

static bool
handle_address_leak(void *drcontext)
{
    dr_fprintf(STDERR, "[ASLR] Address leak\n");
    if (fail_address_leaks.get_value()) {
        dr_syscall_set_result(drcontext, -1);
        return false;
    } else
        return true;
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    if (sysnum == SYS_write || sysnum == SYS_send) {
        /* we want to check these for taint */
        char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
        size_t len   = dr_syscall_get_param(drcontext, 2);

        for (int i = 0; i < len; ++i) {
            byte result;
            if (drtaint_get_app_taint(drcontext, (app_pc)&buffer[i],
                                      &result) && result != 0)
                return handle_address_leak(drcontext);
        }
    }
    return true;
}
