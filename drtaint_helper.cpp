#include <iostream>
#include <unordered_set>
#include <exception>

#include "drtaint_helper.h"

drreg_reservation::
drreg_reservation(instrlist_t *ilist, instr_t *where)
    : drcontext_(dr_get_current_drcontext()),
      ilist_(ilist), where_(where)
{
    if (drreg_reserve_register(drcontext_, ilist_, where_, NULL, &reg_) != DRREG_SUCCESS)
        throw std::exception();
}

drreg_reservation::
~drreg_reservation()
{
    drreg_unreserve_register(drcontext_, ilist_, where_, reg_);
}

void
unimplemented_opcode(instr_t *where)
{
    /* N/A */
#if 0
    void *drcontext = dr_get_current_drcontext();
    dr_fprintf(STDERR, "NYI %p: ", instr_get_app_pc(where));
    instr_disassemble(drcontext, where, STDERR);
    dr_fprintf(STDERR, "\n");
#endif
}

void
instrlist_meta_preinsert_xl8(instrlist_t *ilist, instr_t *where, instr_t *insert)
{
    instrlist_meta_preinsert(ilist, where, INSTR_XL8
                             (insert, instr_get_app_pc(where)));
}
