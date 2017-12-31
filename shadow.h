#ifndef SHADOW_H_
#define SHADOW_H_

#include "dr_api.h"

bool
shadow_init(int id);

void
shadow_exit(void);

bool
shadow_insert_app_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t regaddr, reg_id_t scratch);

bool
shadow_insert_reg_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t shadow,  reg_id_t regaddr);

#endif
