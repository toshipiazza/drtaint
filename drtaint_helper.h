#ifndef DRTAINT_HELPER_H_
#define DRTAINT_HELPER_H_

#include "dr_api.h"
#include "drreg.h"

#ifdef __cplusplus
extern "C" {
#endif

class drreg_reservation {
public:
    drreg_reservation(instrlist_t *ilist, instr_t *where);
    ~drreg_reservation();
    operator reg_id_t() const { return reg_; }
private:
    instrlist_t *ilist_;
    instr_t *where_;
    reg_id_t reg_;
    void *drcontext_;
};

void
unimplemented_opcode(instr_t *where);

void
instrlist_meta_preinsert_xl8(instrlist_t *ilist, instr_t *where, instr_t *insert);

#ifdef __cplusplus
}
#endif

#endif
