#ifndef DRTAINT_H_
#define DRTAINT_H_

#include "dr_api.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    DRMGR_PRIORITY_INSERT_DRTAINT      = -7500,
    DRMGR_PRIORITY_THREAD_INIT_DRTAINT = -7500,
    DRMGR_PRIORITY_THREAD_EXIT_DRTAINT =  7500,
};

#define DRMGR_PRIORITY_NAME_DRTAINT "drtaint"
#define DRMGR_PRIORITY_NAME_DRTAINT_EXIT "drtaint.exit"
#define DRMGR_PRIORITY_NAME_DRTAINT_INIT "drtaint.init"

bool
drtaint_init(client_id_t id);

void
drtaint_exit(void);

bool
drtaint_insert_app_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t reg_addr, reg_id_t scratch);

bool
drtaint_insert_reg_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t shadow, reg_id_t regaddr);

bool
drtaint_write_shadow_values(FILE *fp);

#ifdef __cplusplus
}
#endif

#endif
