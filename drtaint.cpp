#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drreg.h"
#include "drutil.h"
#include "shadow.h"
#include "drtaint.h"
#include "drtaint_helper.h"

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

/* ======================================================================================
 * main implementation, taint propagation step
 * ==================================================================================== */
static void
propagate_ldr(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* ldr [mem2], reg1 */
    auto sreg1 = drreg_reservation { ilist, where };
    auto sapp2 = drreg_reservation { ilist, where };
    reg_id_t reg1 = opnd_get_reg(instr_get_dst(where, 0));
    opnd_t   mem2 = instr_get_src(where, 0);

    drutil_insert_get_mem_addr(drcontext, ilist, where, mem2, sapp2, sreg1);
    drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2, sreg1);
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg1, sreg1);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_load_1byte
                             (drcontext,
                              opnd_create_reg(sreg1),
                              OPND_CREATE_MEM8(sreg1, 0)));
    instrlist_meta_preinsert_xl8(ilist, where, XINST_CREATE_store_1byte
                                 (drcontext,
                                  OPND_CREATE_MEM8(sapp2, 0),
                                  opnd_create_reg(sreg1)));
}

static void
propagate_mov_reg_src(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* mov reg2, reg1 */
    auto sreg2 = drreg_reservation { ilist, where };
    auto sreg1 = drreg_reservation { ilist, where };
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));

    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg1, sreg1);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_load_1byte
                             (drcontext,
                              opnd_create_reg(sreg1),
                              OPND_CREATE_MEM8(sreg1, 0)));
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_store_1byte
                             (drcontext,
                              OPND_CREATE_MEM8(sreg2, 0),
                              opnd_create_reg(sreg1)));
}

static void
propagate_mov_imm_src(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* mov reg2, reg1 */
    auto sreg2 = drreg_reservation { ilist, where };
    auto sreg1 = drreg_reservation { ilist, where };
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));

    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_store_1byte
                             (drcontext,
                              OPND_CREATE_MEM8(sreg2, 0),
                              opnd_create_immed_int(0, OPSZ_1)));
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    switch (instr_get_opcode(where)) {
    case OP_ldr:
        propagate_ldr(drcontext, tag, ilist, where);
        break;
    case OP_mov:
        if (opnd_is_reg(instr_get_src(where, 0)))
            propagate_mov_reg_src(drcontext, tag, ilist, where);
        else
            propagate_mov_imm_src(drcontext, tag, ilist, where);
        break;
    case OP_blx:
        break;
    default:
        unimplemented_opcode(where);
        break;
    }
    return DR_EMIT_DEFAULT;
}
