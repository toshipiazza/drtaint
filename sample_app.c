#include "dr_api.h"
#include "drmgr.h"
#include "drtaint.h"

static void
exit_event(void);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drmgr_init();
    drtaint_init(id);
    dr_register_exit_event(exit_event);
}

static void
exit_event(void)
{
    drtaint_exit();
    drmgr_exit();
}
