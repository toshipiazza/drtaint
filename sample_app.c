#include "dr_api.h"
#include "drmgr.h"
#include "drtaint.h"

static void
exit_event(void);

static void
event_thread_init(void *drcontext);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drmgr_init();
    drtaint_init(id);
    drmgr_register_thread_init_event(event_thread_init);
    dr_register_exit_event(exit_event);
}

static void
exit_event(void)
{
    void *drcontext = dr_get_current_drcontext();
    drmgr_unregister_thread_init_event(event_thread_init);
    drtaint_exit();
    drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
   drtaint_set_reg_taint(drcontext, DR_REG_SP, 0x41);
}
