#include "dr_api.h"
#include "drmgr.h"
#include "drtaint.h"
#include "utils.h"

static client_id_t client_id;

static void
exit_event(void);

static void
nudge_event(void *drcontext, uint64 argument);

static void
dump_taint_to_log(void *drcontext);

static void
event_thread_init(void *drcontext);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    client_id = id;
    drmgr_init();
    drtaint_init(id);
    drmgr_register_thread_init_event(event_thread_init);
    dr_register_nudge_event(nudge_event, id);
    dr_register_exit_event(exit_event);
}

static void
exit_event(void)
{
    void *drcontext = dr_get_current_drcontext();
    drmgr_unregister_thread_init_event(event_thread_init);
    dump_taint_to_log(drcontext);
    drtaint_exit();
    drmgr_exit();
}

static void
dump_taint_to_log(void *drcontext)
{
    file_t nudge_file = log_file_open(client_id, drcontext, NULL,
                                      "drtaint_dump",
                                      DR_FILE_ALLOW_LARGE);
    FILE  *nudge_file_fp = log_stream_from_file(nudge_file);
    drtaint_write_shadow_values(nudge_file_fp);
    log_stream_close(nudge_file_fp);
}

static void
nudge_event(void *drcontext, uint64 arg)
{
    dump_taint_to_log(drcontext);
}

static void
event_thread_init(void *drcontext)
{
   drtaint_set_reg_taint(drcontext, DR_REG_SP, 0x41);
}
