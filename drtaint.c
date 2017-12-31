#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drreg.h"
#include "drutil.h"
#include "shadow.h"
#include "drtaint.h"

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data);

static int drtaint_init_count;

bool
drtaint_init(client_id_t id)
{
    drreg_options_t  ops = {sizeof(ops), 4, false};
    drmgr_priority_t pri = {sizeof(pri),
        DRMGR_PRIORITY_NAME_DRTAINT, NULL, NULL,
        DRMGR_PRIORITY_INSERT_DRTAINT};

    int count = dr_atomic_add32_return_sum(&drtaint_init_count, 1);
    if (count > 1)
        return true;

    drmgr_init();
    if (!shadow_init(id) ||
        drreg_init(&ops) != DRREG_SUCCESS)
        return false;
    if (!drmgr_register_bb_instrumentation_event(NULL,
                event_app_instruction, &pri))
        return false;
    return true;
}

void
drtaint_exit(void)
{
    int count = dr_atomic_add32_return_sum(&drtaint_init_count, -1);
    if (count != 0)
        return;

    shadow_exit();
    drmgr_exit();
    drreg_exit();
}

bool
drtaint_insert_app_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t reg_addr, reg_id_t scratch)
{
    return shadow_insert_app_to_shadow(drcontext, ilist, where,
                                       reg_addr, scratch);
}

bool
drtaint_insert_reg_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t shadow, reg_id_t regaddr)
{
    return shadow_insert_reg_to_shadow(drcontext, ilist, where,
                                       shadow, regaddr);
}

void unimplemented_opcode(int opcode)
{
    char buf[20];
    dr_snprintf(buf, sizeof(buf), "Opcode '%s' NYI",
                decode_opcode_name(opcode));
    DR_ASSERT_MSG(false, buf);
}

/* ======================================================================================
 * main implementation, taint propagation step
 * ==================================================================================== */
static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    switch (instr_get_opcode(where)) {
    default:
        unimplemented_opcode(instr_get_opcode(where));
        break;
    }
    return DR_EMIT_DEFAULT;
}
