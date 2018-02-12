#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drtaint.h"
#include "droption.h"
#include "drtaint_helper.h"

#include <syscall.h>

/* This sample tries to prevent address leaks in an active exploitation
 * scenario. We identify 3 types of leaks (stack, heap, and libc or .text). If
 * we taint all areas on process startup that are "randomized" or protected,
 * then we can determine if an address leak has occurred on `send`.
 *
 * - all stck addresses are relative to SP, and argv/envp
 * - all heap addresses are relative to `brk` or `mmap2` syscalls
 * - all libc leaks must be PC-relative (?)
 *
 * We also consider exposing an annotations library; if one wishes to modify
 * libc, i.e. to taint `__stack_chk_guard` (stack cookie) or to taint
 * `__pointer_chk_guard` (pointer encryption)
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
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
                  bool for_trace, bool translating, void **user_data);

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data);

static void
taint_argv_envp(int argc, char *argv[], char *envp[]);

static droption_t<bool> dump_taint_on_exit
(DROPTION_SCOPE_CLIENT, "dump_taint_on_exit", false,
 "Dump taint profile to file on exit",
 "On exit of app, dump taint profile that can be parsed into a bitmap by vis.py "
 "to visualize taint introduced via the taint source API");

static app_pc exe_start;
static bool tainted_argv;

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t  ops = {sizeof(ops), 3, false};
    module_data_t *exe;

    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL))
        DR_ASSERT(false);
    /* get main module address */
    exe = dr_get_main_module();
    DR_ASSERT(exe != NULL);
    if (exe != NULL)
        exe_start = exe->start;
    dr_free_module_data(exe);

    drmgr_init();
    drmgr_register_bb_instrumentation_event(event_bb_analysis,
                                            event_app_instruction,
                                            NULL);
    drreg_init(&ops);

    drtaint_init(id);
    drmgr_register_thread_init_event(event_thread_init);
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    dr_register_exit_event(exit_event);
}

static void
exit_event(void)
{
    void *drcontext = dr_get_current_drcontext();
    if (dump_taint_on_exit.get_value())
        drtaint_dump_taint_to_log(drcontext);
    drmgr_unregister_bb_instrumentation_event(event_bb_analysis);
    drmgr_unregister_bb_insertion_event(event_app_instruction);
    drmgr_unregister_thread_init_event(event_thread_init);
    drtaint_exit();
    drmgr_exit();
    drreg_exit();
}

static void
event_thread_init(void *drcontext)
{
    drtaint_set_reg_taint(drcontext, DR_REG_SP, STCK_POINTER_TAINT);
    drtaint_set_reg_taint(drcontext, DR_REG_PC, TEXT_POINTER_TAINT);
}

static dr_emit_flags_t
event_bb_analysis(void *drcontext, void *tag, instrlist_t *bb,
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
event_app_instruction(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                      bool for_trace, bool translating, void *user_data)
{
    if (!user_data ||
        !drmgr_is_first_instr(drcontext, instr))
        return DR_EMIT_DEFAULT;

    drmgr_disable_auto_predication(drcontext, bb);
    /* Emit the following instrumentation:
     * ldr r0, [sp]
     * add r1, sp, #4
     * add r2, r1, r0, LSL #2
     * call clean_call
     */
    auto argc = drreg_reservation { bb, instr };
    auto argv = drreg_reservation { bb, instr };
    auto envp = drreg_reservation { bb, instr };

#define MINSERT instrlist_meta_preinsert
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
    dr_insert_clean_call(drcontext, bb, instr,
                         (void *)taint_argv_envp,
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

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return
        /* taint sources */
        sysnum == SYS_brk   ||
        sysnum == SYS_mmap2 ||
        /* taint sinks */
        sysnum == SYS_write ||
        sysnum == SYS_send;
}

static bool
event_pre_syscall(void *drcontext, int sysnum)
{
    /* check for taint sinks */
    if (sysnum == SYS_write || sysnum == SYS_send) {
        char *buffer = (char *)dr_syscall_get_param(drcontext, 1);
        size_t len   = dr_syscall_get_param(drcontext, 2);
        int i;

        /* TODO: We can probably make this faster by translating
         * from app to shadow, then using dr_safe_read() to read
         * until a fault, though we currently don't expose a
         * function to do this.
         */
        for (i = 0; i < len; ++i) {
            byte result;
            if (drtaint_get_app_taint(drcontext, (app_pc)&buffer[i],
                                      &result) && result != 0) {
                dr_printf("Detected address leak: %c\n", result);
                /* fail the syscall to prevent the leak */
                return false;
            }
        }
    }
    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    /* check for taint sources */
    if (sysnum == SYS_mmap2 || sysnum == SYS_brk) {
        /* we want to taint the return value here */
        drtaint_set_reg_taint(drcontext, DR_REG_R0, HEAP_POINTER_TAINT);
    }
}

static void
taint_argv_envp(int argc, char *argv[], char *envp[])
{
    void *drcontext = dr_get_current_drcontext();
    int i;

    /* taint argv on the stack */
    for (i = 0; i < argc; ++i) {
        drtaint_set_app_taint(drcontext, (app_pc)argv[i],
                              STCK_POINTER_TAINT);
    }
    /* taint envp on the stack */
    for (i = 0; envp[i]; ++i) {
        drtaint_set_app_taint(drcontext, (app_pc)envp[i],
                              STCK_POINTER_TAINT);
    }
}
