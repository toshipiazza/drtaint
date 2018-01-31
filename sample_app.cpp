#include "dr_api.h"
#include "drmgr.h"
#include "drtaint.h"
#include "droption.h"

#include <syscall.h>

static droption_t<bool> dump_taint_on_exit
(DROPTION_SCOPE_CLIENT, "dump_taint_on_exit", false,
 "Dump taint profile to file on exit",
 "On exit of app, dump taint profile that can be parsed into a bitmap by vis.py "
 "to visualize taint introduced via the taint source API");

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

/* TODO:
 * - taint argv and envp pointers
 */

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{

    if (!droption_parser_t::parse_argv(DROPTION_SCOPE_CLIENT, argc, argv, NULL, NULL))
        DR_ASSERT(false);
    drmgr_init();
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
    drmgr_unregister_thread_init_event(event_thread_init);
    drtaint_exit();
    drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
    drtaint_set_reg_taint(drcontext, DR_REG_SP, 0x01);
    drtaint_set_reg_taint(drcontext, DR_REG_PC, 0x01);
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

        /* We want to make sure that the buffer has
         * no tainted values.
         */
        /* TODO */
    }
    return true;
}

static void
event_post_syscall(void *drcontext, int sysnum)
{
    /* check for taint sources */
    if (sysnum == SYS_mmap2 || sysnum == SYS_brk) {
        /* we want to taint the return value here */
        drtaint_set_reg_taint(drcontext, DR_REG_R0, 0x01);
    }
}
