#include "dr_api.h"
#include "drmgr.h"
#include "drreg.h"
#include "drtaint.h"
#include "droption.h"
#include "drtaint_helper.h"

#include <iostream>
#include <unistd.h>
#include <asm-generic/ioctls.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <syscall.h>
#include <termios.h>
#include <time.h>

static void
exit_event(void);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drtaint_init(id);
    dr_register_exit_event(exit_event);
}

static void
exit_event(void)
{
    drtaint_exit();
}
