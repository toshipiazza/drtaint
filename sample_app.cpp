#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drtaint.h"
#include "droption.h"
#include "drtaint_helper.h"

#include <sys/utsname.h>
#include <sys/stat.h>
#include <syscall.h>
#include <time.h>

/* This sample tries to prevent address leaks in an active exploitation
 * scenario. We identify 3 types of leaks (stack, heap, and libc or .text). If
 * we taint all areas on process startup that are "randomized" or protected,
 * then we can determine if an address leak has occurred on `send`.
 *
 * - all stck addresses are relative to SP, and argv/envp
 * - all heap addresses are relative to `brk` or `mmap2` syscalls
 * - TODO: all libc references must go through the GOT and thus through
 *   _dl_runtime_resolve()
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
    drmgr_unregister_bb_instrumentation_event(event_bb_analysis);
    drmgr_unregister_bb_insertion_event(event_app_instruction);
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

static void
taint_argv_envp(int argc, char *argv[], char *envp[])
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

/****************************************************************************
 * Introduce taint sinks and sources
 */

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
    return true;
}

static const char *
taint2leak(char a)
{
    switch (a) {
    case STCK_POINTER_TAINT:
        return "STACK";
    case HEAP_POINTER_TAINT:
        return "HEAP";
    case TEXT_POINTER_TAINT:
        /* N.B. Currently tainting PC is pretty much a "hack", and in fact
         * probably doesn't really work, especially when calling into a
         * libc function. However, intuitively this *should* cause all .text
         * leaks to fail.
         */
        return "TEXT";
    default:
        return "UNKNOWN"; 
    }
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
                dr_fprintf(STDERR, "Detected address leak %s@" PFX "\n",
                           taint2leak(result),
                           buffer + i);
                /* fail the syscall to prevent the leak */
                return false;
            }
        }
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

    /* We need to clear taint on the field written
     * out by sysnum. All following syscalls do so.
     */
    if (sysnum == SYS_recv || sysnum == SYS_read) {
        per_thread_t *data = (per_thread_t *)
            drmgr_get_cls_field(drcontext, tcls_idx);
        for (int i = 0; i < info.value; ++i) {
            if (!drtaint_set_app_taint(drcontext,
                        (app_pc)data->buf + i, 0))
                DR_ASSERT(false);
        }
    } else if (sysnum == SYS_uname) {
        per_thread_t *data = (per_thread_t *)
            drmgr_get_cls_field(drcontext, tcls_idx);
        for (int i = 0; i < sizeof(utsname); ++i) {
            if (!drtaint_set_app_taint(drcontext,
                        (app_pc)data->buf + i, 0))
                DR_ASSERT(false);
        }
    } else if (sysnum == SYS_lstat ||
               sysnum == SYS_fstat ||
               sysnum == SYS_stat) {
        per_thread_t *data = (per_thread_t *)
            drmgr_get_cls_field(drcontext, tcls_idx);
        for (int i = 0; i < sizeof(struct stat); ++i) {
            if (!drtaint_set_app_taint(drcontext,
                        (app_pc)data->buf + i, 0))
                DR_ASSERT(false);
        }
    } else if (sysnum == SYS_lstat64 ||
               sysnum == SYS_fstat64 ||
               sysnum == SYS_stat64) {
        per_thread_t *data = (per_thread_t *)
            drmgr_get_cls_field(drcontext, tcls_idx);
        for (int i = 0; i < sizeof(struct stat64); ++i) {
            if (!drtaint_set_app_taint(drcontext,
                        (app_pc)data->buf + i, 0))
                DR_ASSERT(false);
        }
    } else if (sysnum == SYS_clock_gettime) {
        per_thread_t *data = (per_thread_t *)
            drmgr_get_cls_field(drcontext, tcls_idx);
        for (int i = 0; i < sizeof(struct timespec); ++i) {
            if (!drtaint_set_app_taint(drcontext,
                        (app_pc)data->buf + i, 0))
                DR_ASSERT(false);
        }
    }
}
