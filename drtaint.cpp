#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drreg.h"
#include "drutil.h"
#include "drtaint.h"
#include "drtaint_shadow.h"
#include "drtaint_helper.h"
#include "utils.h"

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data);

static void
nudge_event(void *drcontext, uint64 argument);

static int drtaint_init_count;

static client_id_t client_id;

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

    client_id = id;
    drmgr_init();
    if (!drtaint_shadow_init(id) ||
        drreg_init(&ops) != DRREG_SUCCESS)
        return false;
    if (!drmgr_register_bb_instrumentation_event(NULL,
                event_app_instruction, &pri))
        return false;
    dr_register_nudge_event(nudge_event, id);
    return true;
}

void
drtaint_exit(void)
{
    int count = dr_atomic_add32_return_sum(&drtaint_init_count, -1);
    if (count != 0)
        return;

    drtaint_shadow_exit();
    drmgr_exit();
    drreg_exit();
}

bool
drtaint_insert_app_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t reg_addr, reg_id_t scratch)
{
    return drtaint_shadow_insert_app_to_shadow(drcontext, ilist, where,
                                               reg_addr, scratch);
}

bool
drtaint_insert_reg_to_taint(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t shadow, reg_id_t regaddr)
{
    return drtaint_shadow_insert_reg_to_shadow(drcontext, ilist, where,
                                               shadow, regaddr);
}

bool
drtaint_get_reg_taint(void *drcontext, reg_id_t reg, byte *result)
{
    return drtaint_shadow_get_reg_taint(drcontext, reg, result);
}

bool
drtaint_set_reg_taint(void *drcontext, reg_id_t reg, byte value)
{
    return drtaint_shadow_set_reg_taint(drcontext, reg, value);
}

bool
drtaint_get_app_taint(void *drcontext, app_pc app, byte *result)
{
    return drtaint_shadow_get_app_taint(drcontext, app, result);
}

bool
drtaint_set_app_taint(void *drcontext, app_pc app, byte result)
{
    return drtaint_shadow_set_app_taint(drcontext, app, result);
}

bool
drtaint_write_shadow_values(FILE *fp)
{
    return drtaint_shadow_write_shadow_values(fp);
}

void
drtaint_dump_taint_to_log(void *drcontext)
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
    drtaint_dump_taint_to_log(drcontext);
}

/* ======================================================================================
 * main implementation, taint propagation step
 * ==================================================================================== */
static void
propagate_ldr(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* ldr reg1, [mem2] */
    auto sreg1 = drreg_reservation { ilist, where };
    auto sapp2 = drreg_reservation { ilist, where };
    reg_id_t reg1 = opnd_get_reg(instr_get_dst(where, 0));
    opnd_t   mem2 = instr_get_src(where, 0);

    drutil_insert_get_mem_addr(drcontext, ilist, where, mem2, sapp2, sreg1);
    drtaint_insert_app_to_taint(drcontext, ilist, where, sapp2, sreg1);
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg1, sreg1);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_load_1byte
                             (drcontext,
                              opnd_create_reg(sapp2),
                              OPND_CREATE_MEM8(sapp2, 0)));
    instrlist_meta_preinsert_xl8(ilist, where, XINST_CREATE_store_1byte
                                 (drcontext,
                                  OPND_CREATE_MEM8(sreg1, 0),
                                  opnd_create_reg(sapp2)));
}

static void
propagate_str(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* str [mem2], reg1 */
    auto sreg1 = drreg_reservation { ilist, where };
    auto sapp2 = drreg_reservation { ilist, where };
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));
    opnd_t   mem2 = instr_get_dst(where, 0);

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
propagate_mov_regs(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                   reg_id_t reg1, reg_id_t reg2)
{
    /* mov reg2, reg1 */
    auto sreg2 = drreg_reservation { ilist, where };
    auto sreg1 = drreg_reservation { ilist, where };

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
propagate_mov_reg_src(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* mov reg2, reg1 */
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 0));
    propagate_mov_regs(drcontext, tag, ilist, where, reg1, reg2);
}

static void
propagate_mov_imm_src(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* mov reg2, imm1 */
    auto sreg2 = drreg_reservation { ilist , where };
    auto simm2 = drreg_reservation { ilist , where };
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));

    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_move
                             (drcontext,
                              opnd_create_reg(simm2),
                              opnd_create_immed_int(0, OPSZ_1)));
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_store_1byte
                             (drcontext,
                              OPND_CREATE_MEM8(sreg2, 0),
                              opnd_create_reg(simm2)));
}

static void
propagate_arith_imm_reg(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* add reg2, imm, reg1 */
    auto sreg2 = drreg_reservation { ilist, where };
    auto sreg1 = drreg_reservation { ilist, where };
    reg_id_t reg2 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 1));

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
propagate_arith_reg_imm(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* add reg2, reg1, imm */
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
propagate_arith_reg_reg(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where)
{
    /* add reg3, reg2, reg1 */
    auto sreg2 = drreg_reservation { ilist, where };
    auto sreg1 = drreg_reservation { ilist, where };
    reg_id_t sreg3 = sreg2; /* we reuse a register for this */
    reg_id_t reg3 = opnd_get_reg(instr_get_dst(where, 0));
    reg_id_t reg2 = opnd_get_reg(instr_get_src(where, 0));
    reg_id_t reg1 = opnd_get_reg(instr_get_src(where, 1));

    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg1, sreg1);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_load_1byte
                             (drcontext,
                              opnd_create_reg(sreg1),
                              OPND_CREATE_MEM8(sreg1, 0)));
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg2, sreg2);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_load_1byte
                             (drcontext,
                              opnd_create_reg(sreg2),
                              OPND_CREATE_MEM8(sreg2, 0)));
    instrlist_meta_preinsert(ilist, where, INSTR_CREATE_orr
                             (drcontext,
                              opnd_create_reg(sreg1),
                              opnd_create_reg(sreg2),
                              opnd_create_reg(sreg1)));
    drtaint_insert_reg_to_taint(drcontext, ilist, where, reg3, sreg3);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_store_1byte
                             (drcontext,
                              OPND_CREATE_MEM8(sreg3, 0),
                              opnd_create_reg(sreg1)));
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    switch (instr_get_opcode(where)) {
    case OP_LABEL:
        break;
    case OP_ldr:
    case OP_ldrb:
    case OP_ldrd:
    case OP_ldrh:
        propagate_ldr(drcontext, tag, ilist, where);
        break;
    case OP_str:
    case OP_strb:
    case OP_strd:
    case OP_strh:
        propagate_str(drcontext, tag, ilist, where);
        break;
    case OP_mov:
    case OP_mvn:
    case OP_mvns:
    case OP_movw:
    case OP_movt:
    case OP_movs:
        if (opnd_is_reg(instr_get_src(where, 0)))
            propagate_mov_reg_src(drcontext, tag, ilist, where);
        else
            propagate_mov_imm_src(drcontext, tag, ilist, where);
        break;
    case OP_adc:
    case OP_adcs:
    case OP_add:
    case OP_adds:
    case OP_addw:
    case OP_rsb:
    case OP_rsbs:
    case OP_rsc:
    case OP_sbc:
    case OP_sbcs:
    case OP_sub:
    case OP_subw:
    case OP_subs:
    case OP_and:
    case OP_ands:
    case OP_bic:
    case OP_bics:
    case OP_eor:
    case OP_eors:
    case OP_mul:
    case OP_orr:
    case OP_orrs:
    case OP_lsl:
    case OP_lsls:
    case OP_lsr:
    case OP_lsrs:
    case OP_asr:
    case OP_asrs:
    case OP_orn:
    case OP_uadd8:
    case OP_uqsub8:
        /* Some of these also write to eflags. If we taint eflags
         * we should do it here.
         */
        DR_ASSERT(instr_num_srcs(where) == 2 || instr_num_srcs(where) == 4);
        DR_ASSERT(instr_num_dsts(where) == 1);
        if (opnd_is_reg(instr_get_src(where, 0))) {
            if (opnd_is_reg(instr_get_src(where, 1)))
                propagate_arith_reg_reg(drcontext, tag, ilist, where);
            else
                propagate_arith_reg_imm(drcontext, tag, ilist, where);
        } else if (opnd_is_reg(instr_get_src(where, 1)))
            propagate_arith_imm_reg(drcontext, tag, ilist, where);
        else
            DR_ASSERT(false); /* add reg, imm, imm does not make sense */
        break;
    case OP_bl:
    case OP_blx:
    case OP_blx_ind:
        propagate_mov_regs(drcontext, tag, ilist, where,
                           DR_REG_PC, DR_REG_LR);
        /* fallthrough, we could have a register dest */
    case OP_bxj:
    case OP_bx:
    case OP_b:
    case OP_b_short:
        /* could have register destination */
        if (opnd_is_reg(instr_get_src(where, 0))) {
            propagate_mov_regs(drcontext, tag, ilist, where,
                               opnd_get_reg(instr_get_src(where, 0)),
                               DR_REG_PC);
        } else {
            /* Technically, we're performing the operation
             * PC = PC + off
             */
        }
        break;
    case OP_cbz:
    case OP_cbnz:
        /* Nothing to do here, unless we want to support tainting
         * eflags.
         */
        break;
    case OP_cmn:
    case OP_cmp:
    case OP_tst:
    case OP_it:
        /* Nothing to do here, unless we want to support tainting
         * eflags.
         */
        break;
    case OP_svc:
        break;
    case OP_nop:
        break;
    case OP_pld:
        break;
    case OP_dmb:
        break;
    default:
        unimplemented_opcode(where);
        break;
    }
    return DR_EMIT_DEFAULT;
}
