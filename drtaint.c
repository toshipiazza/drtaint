#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drreg.h"
#include "drutil.h"
#include "shadow.h"

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data);

static void
exit_event(void);

DR_EXPORT void
dr_client_main(client_id_t id, int argc, const char *argv[])
{
    drreg_options_t ops = {sizeof(ops), 4, true};

    drmgr_init();
    drreg_init(&ops);
    shadow_init(id);

    drmgr_register_bb_instrumentation_event(
            NULL, event_app_instruction, NULL);
    dr_register_exit_event(exit_event);
}

static void
instrument_mem(void *drcontext, instrlist_t *ilist, instr_t *where, opnd_t ref)
{
    reg_id_t regaddr;
    reg_id_t scratch;
    bool ok;

    if (drreg_reserve_register(drcontext, ilist, where, NULL, &regaddr)
        != DRREG_SUCCESS ||
        drreg_reserve_register(drcontext, ilist, where, NULL, &scratch)
        != DRREG_SUCCESS) {
        DR_ASSERT(false); /* can't recover */
        return;
    }

    ok = drutil_insert_get_mem_addr(drcontext, ilist, where, ref, regaddr, scratch);
    DR_ASSERT(ok);
    ok = shadow_insert_app_to_shadow(drcontext, ilist, where, regaddr, scratch);
    DR_ASSERT(ok);

    /* trigger a fault to the shared readonly shadow page */
    instrlist_meta_preinsert(ilist, where, INSTR_XL8
            (XINST_CREATE_store_1byte
             (drcontext,
              OPND_CREATE_MEM8(regaddr, 0),
              opnd_create_reg(
                  reg_resize_to_opsz(scratch, OPSZ_1))),
             instr_get_app_pc(where)));

    if (drreg_unreserve_register(drcontext, ilist, where, regaddr) != DRREG_SUCCESS ||
        drreg_unreserve_register(drcontext, ilist, where, scratch) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

static void
instrument_reg(void *drcontext, instrlist_t *ilist, instr_t *where, reg_id_t reg)
{
    reg_id_t regaddr;
    reg_id_t scratch;
    bool ok;

    if (reg == DR_REG_PC)
        return;
    if (reg - DR_REG_R0 >= DR_NUM_GPR_REGS)
        return;

    if (drreg_reserve_register(drcontext, ilist, where, NULL, &regaddr)
        != DRREG_SUCCESS) {
        DR_ASSERT(false); /* can't recover */
        return;
    }

    ok = shadow_insert_reg_to_shadow(drcontext, ilist, where, reg, regaddr);
    DR_ASSERT(ok);

    if (drreg_unreserve_register(drcontext, ilist, where, regaddr) != DRREG_SUCCESS)
        DR_ASSERT(false);
}

static dr_emit_flags_t
event_app_instruction(void *drcontext, void *tag, instrlist_t *ilist, instr_t *where,
                      bool for_trace, bool translating, void *user_data)
{
    int i;

    for (i = 0; i < instr_num_srcs(where); i++) {
        if (opnd_is_memory_reference(instr_get_src(where, i)))
            instrument_mem(drcontext, ilist, where, instr_get_src(where, i));
    }
    for (i = 0; i < instr_num_dsts(where); i++) {
        if (opnd_is_memory_reference(instr_get_dst(where, i)))
            instrument_mem(drcontext, ilist, where, instr_get_dst(where, i));
    }
    for (i = 0; i < instr_num_srcs(where); i++) {
        if (opnd_is_reg(instr_get_src(where, i))) {
            reg_id_t reg = opnd_get_reg(instr_get_src(where, i));
            instrument_reg(drcontext, ilist, where, reg);
        }
    }
    for (i = 0; i < instr_num_dsts(where); i++) {
        if (opnd_is_reg(instr_get_dst(where, i))) {
            reg_id_t reg = opnd_get_reg(instr_get_dst(where, i));
            instrument_reg(drcontext, ilist, where, reg);
        }
    }

    return DR_EMIT_DEFAULT;
}

static void
exit_event(void)
{
    drmgr_exit();
    drreg_exit();
}
