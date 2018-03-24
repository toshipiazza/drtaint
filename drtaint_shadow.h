#ifndef SHADOW_H_
#define SHADOW_H_

#include "dr_api.h"

#ifdef __cplusplus
extern "C" {
#endif

bool
drtaint_shadow_init(int id);

void
drtaint_shadow_exit(void);

bool
drtaint_shadow_insert_app_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                                    reg_id_t regaddr, reg_id_t scratch);

bool
drtaint_shadow_insert_reg_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                                    reg_id_t shadow,  reg_id_t regaddr);

bool
drtaint_shadow_insert_reg_to_shadow_load(void *drcontext, instrlist_t *ilist,
                                         instr_t *where, reg_id_t shadow,
                                         reg_id_t regaddr);

bool
drtaint_shadow_get_reg_taint(void *drcontext, reg_id_t reg, byte *result);

bool
drtaint_shadow_set_reg_taint(void *drcontext, reg_id_t reg, byte value);

bool
drtaint_shadow_get_app_taint(void *drcontext, app_pc app, byte *result);

bool
drtaint_shadow_set_app_taint(void *drcontext, app_pc app, byte result);

#ifdef __cplusplus
}
#endif

#endif
