#include "drtaint_helper.h"

drreg_reservation::
drreg_reservation(instrlist_t *ilist, instr_t *where)
    : drcontext_(dr_get_current_drcontext()),
      ilist_(ilist), where_(where)
{
   if (drreg_reserve_register(drcontext_, ilist_, where_, NULL, &reg_)
       != DRREG_SUCCESS)
       DR_ASSERT(false);
}

drreg_reservation::
~drreg_reservation()
{
    if (drreg_unreserve_register(drcontext_, ilist_, where_, reg_)
        != DRREG_SUCCESS)
        DR_ASSERT(false);
}

void
unimplemented_opcode(instr_t *where)
{
    char buf[20];
    int opcode = instr_get_opcode(where);
    dr_snprintf(buf, sizeof(buf), "Opcode '%s' NYI",
                decode_opcode_name(opcode));
    DR_ASSERT_MSG(false, buf);
}

void
instrlist_meta_preinsert_xl8(instrlist_t *ilist, instr_t *where, instr_t *insert)
{
    instrlist_meta_preinsert(ilist, where, INSTR_XL8
                             (insert, instr_get_app_pc(where)));
}

void
print_instr(instr_t *instr)
{
    void *drcontext = dr_get_current_drcontext();
    instr_disassemble(drcontext, instr, STDOUT);
    dr_printf("\n");
}

void
insert_debug(instrlist_t *ilist, instr_t *where)
{
    void *drcontext = dr_get_current_drcontext();
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_debug_instr
                             (drcontext));
}
