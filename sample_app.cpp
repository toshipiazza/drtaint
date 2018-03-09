#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drtaint.h"
#include "droption.h"
#include "drtaint_helper.h"

#include <iostream>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <syscall.h>
#include <time.h>

/* This sample tries to prevent address leaks in an active exploitation
 * scenario. We identify 3 types of leaks (stack, heap, and libc or .text). If
 * we taint all areas on where pointers are introduced, then we can determine
 * if an address leak has occurred on `send`.
 *
 * - all stck addresses are relative to SP, and argv/envp
 * - all heap addresses are relative to `brk` or `mmap2` syscalls
 * - libc leaks occur through the dyn.plt or dyn.rel sections; we can taint them
 *   up front assuming LD_BIND_NOW=1
 * - other .text leaks occur when PC is used as an operand to some arithmetic or
 *   data movement instruction
 *
 * We also consider exposing an annotations library (TODO); if one wishes to
 * modify libc, i.e. to taint `__stack_chk_guard` (stack cookie) or to taint
 * `__pointer_chk_guard` (pointer encryption)
 *
 * TODO: we still have to handle periodic failures in coreutils because syscalls
 * (i.e. uname) write out to a buffer. We need to clear taint for these buffers.
 */

#define STCK_POINTER_TAINT 0x41
#define TEXT_POINTER_TAINT 0x42
#define HEAP_POINTER_TAINT 0x43

static void
exit_event(void);

static void
event_thread_init(void *drcontext);

static void
event_thread_context_init(void *drcontext, bool new_depth);

static void
event_thread_context_exit(void *drcontext, bool process_exit);

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

static droption_t<bool> dump_taint_on_exit
(DROPTION_SCOPE_CLIENT, "dump_taint_on_exit", false,
 "Dump taint profile to file on exit",
 "On exit of app, dump taint profile that can be parsed into a bitmap by vis.py "
 "to visualize taint introduced via the taint source API");

typedef struct {
    /* {recv,read,uname} parameter */
    char  *buf;
} per_thread_t;

static app_pc exe_start;
static bool tainted_argv;
static int tcls_idx;

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

    drreg_options_t  ops = {sizeof(ops), 3, false};
    drreg_init(&ops);

    drmgr_register_thread_init_event(event_thread_init);
    dr_register_filter_syscall_event(event_filter_syscall);
    drmgr_register_pre_syscall_event(event_pre_syscall);
    drmgr_register_post_syscall_event(event_post_syscall);
    tcls_idx = drmgr_register_cls_field(event_thread_context_init,
                                        event_thread_context_exit);
    DR_ASSERT(tcls_idx != -1);
    dr_register_exit_event(exit_event);
}

static void
exit_event(void)
{
    void *drcontext = dr_get_current_drcontext();
    if (dump_taint_on_exit.get_value())
        drtaint_dump_taint_to_log(drcontext);
    drmgr_unregister_cls_field(event_thread_context_init,
                               event_thread_context_exit,
                               tcls_idx);
    drmgr_unregister_bb_instrumentation_event(event_bb_analysis_start);
    drmgr_unregister_bb_insertion_event(event_app_instruction_start);
    drmgr_unregister_bb_insertion_event(event_app_instruction_pc);
    drmgr_unregister_thread_init_event(event_thread_init);
    drtaint_exit();
    drmgr_exit();
    drreg_exit();
}

/****************************************************************************
 * Taint everything we can on process startup
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

    drmgr_disable_auto_predication(drcontext, bb);
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
    dr_fprintf(STDERR, "[argv] Tainting argv\n");
    for (int i = 0; i < argc; ++i) {
        drtaint_set_app_taint(drcontext, (app_pc)argv+i,
                              STCK_POINTER_TAINT);
    }
    /* taint envp on the stack */
    dr_fprintf(STDERR, "[envp] Tainting envp\n");
    for (int i = 0; envp[i]; ++i) {
        drtaint_set_app_taint(drcontext, (app_pc)envp+i,
                              STCK_POINTER_TAINT);
    }
}

/****************************************************************************
 * Introduce taint sinks and sources
 */

static dr_emit_flags_t
event_app_instruction_pc(void *drcontext, void *tag, instrlist_t *bb, instr_t *instr,
                         bool for_trace, bool translating, void *user_data)
{
    int i;
    bool should_taint = false;

    /* If PC is read, we taint it so that the following app instruction spreads its
     * taint accordingly.
     * TODO: for performance, instead of tainting PC, we should taint the destination
     * operand directly, and only if this was an arithmetic or data movement
     * instruction at that.
     */
    for (i = 0; i < instr_num_srcs(instr); ++i) {
        should_taint |= opnd_uses_reg(
                instr_get_src(instr, i), DR_REG_PC);
    }
    if (should_taint) {
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
    }
    return DR_EMIT_DEFAULT;
}

static void
event_thread_context_init(void *drcontext, bool new_depth)
{
    per_thread_t *data;
    if (new_depth) {
        data = (per_thread_t *) dr_thread_alloc(drcontext, sizeof(per_thread_t));
        drmgr_set_cls_field(drcontext, tcls_idx, data);
    } else
        data = (per_thread_t *) drmgr_get_cls_field(drcontext, tcls_idx);
    memset(data, 0, sizeof(*data));
}

static void
event_thread_context_exit(void *drcontext, bool thread_exit)
{
    if (thread_exit) {
        per_thread_t *data = (per_thread_t *) drmgr_get_cls_field(drcontext, tcls_idx);
        dr_thread_free(drcontext, data, sizeof(per_thread_t));
    }
}

static bool
event_filter_syscall(void *drcontext, int sysnum)
{
    return
        /* check these for taint */
        sysnum == SYS_write      ||
        sysnum == SYS_send       ||
        /* taint return values */
        sysnum == SYS_mmap2      ||
        sysnum == SYS_brk        ||
        /* clear taint written */
        sysnum == SYS_recv       ||
        sysnum == SYS_read       ||
        sysnum == SYS_uname      ||
        sysnum == SYS_lstat      ||
        sysnum == SYS_lstat64    ||
        sysnum == SYS_fstat      ||
        sysnum == SYS_fstat64    ||
        sysnum == SYS_stat       ||
        sysnum == SYS_stat64     ||
        sysnum == SYS_statfs     ||
        sysnum == SYS_statfs64   ||
        sysnum == SYS_clock_gettime;
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
                                      &result) && result != 0) {
                /* TODO: fail the syscall to prevent the leak */
                dr_fprintf(STDERR, "[ASLR] Detected address leak\n");
                return true;
            }
        }
        return true;
    }

    per_thread_t *data = (per_thread_t *)
        drmgr_get_cls_field(drcontext, tcls_idx);

    if (sysnum == SYS_uname) {
        /* Save this information for later, so we can handle the
         * uname *only* if it didn't fail.
         */
        data->buf = (char *)dr_syscall_get_param(drcontext, 0);
    } else if (sysnum == SYS_recv ||
               sysnum == SYS_read ||
               sysnum == SYS_lstat ||
               sysnum == SYS_lstat64 ||
               sysnum == SYS_fstat ||
               sysnum == SYS_fstat64 ||
               sysnum == SYS_stat ||
               sysnum == SYS_stat64 ||
               sysnum == SYS_statfs ||
               sysnum == SYS_statfs64 ||
               sysnum == SYS_clock_gettime) {
        /* Save this information for later, so we can handle these
         * syscalls *only* if they didn't fail.
         */
        data->buf = (char *)dr_syscall_get_param(drcontext, 1);
    }

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

    /* all other syscalls untaint rax */
    drtaint_set_reg_taint(drcontext, DR_REG_R0, 0);

#define TAINT_SYSNUM(sysnum_check, bufsz)               \
    if (sysnum == sysnum_check) {                       \
        per_thread_t *data = (per_thread_t *)           \
            drmgr_get_cls_field(drcontext, tcls_idx);   \
        for (int i = 0; i < bufsz; ++i) {               \
            if (!drtaint_set_app_taint(drcontext,       \
                        (app_pc)data->buf + i, 0))      \
                DR_ASSERT(false);                       \
        }                                               \
    }

    /* We need to clear taint on the field written
     * out by sysnum. All following syscalls do so.
     */
    TAINT_SYSNUM(SYS_recv,      info.value);
    TAINT_SYSNUM(SYS_read,      info.value);
    TAINT_SYSNUM(SYS_uname,     sizeof(utsname));
    TAINT_SYSNUM(SYS_lstat,     sizeof(struct stat));
    TAINT_SYSNUM(SYS_fstat,     sizeof(struct stat));
    TAINT_SYSNUM(SYS_stat,      sizeof(struct stat));
    TAINT_SYSNUM(SYS_statfs,    sizeof(struct stat));
    TAINT_SYSNUM(SYS_lstat64,   sizeof(struct stat64));
    TAINT_SYSNUM(SYS_fstat64,   sizeof(struct stat64));
    TAINT_SYSNUM(SYS_stat64,    sizeof(struct stat64));
    TAINT_SYSNUM(SYS_statfs64,  sizeof(struct stat64));
    TAINT_SYSNUM(SYS_clock_gettime, sizeof(struct timespec));
    /* TODO: this is definitely not an exhaustive list */
#undef TAINT_SYSNUM
}
