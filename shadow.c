#include <string.h>
#include <signal.h>

#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"

static umbra_map_t *umbra_map;
static int num_umbra_count;

static reg_id_t
get_faulting_shadow_reg(void *drcontext, dr_mcontext_t *mc)
{
    instr_t inst;
    reg_id_t reg;

    instr_init(drcontext, &inst);
    decode(drcontext, mc->pc, &inst);
    reg = opnd_get_base(instr_get_dst(&inst, 0));
    instr_free(drcontext, &inst);
    return reg;
}

static bool
handle_special_shadow_fault(void *drcontext, dr_mcontext_t *raw_mc,
                            app_pc app_shadow)
{
    umbra_shadow_memory_type_t shadow_type;
    app_pc app_target;
    reg_id_t reg;

    /* If a fault occured, it is probably because we computed the
     * address of shadow memory which was initialized to a shared
     * readonly shadow block. We allocate a shadow page there and
     * replace the reg value used by the faulting instr.
     */
    /* handle faults from writes to special shadow blocks */
    if (umbra_shadow_memory_is_shared(umbra_map, app_shadow,
                                      &shadow_type) != DRMF_SUCCESS) {
        DR_ASSERT(false);
        return true;
    }
    if (shadow_type != UMBRA_SHADOW_MEMORY_TYPE_SHARED)
        return true;

    /* Grab the original app target out of the spill slot so we
     * don't have to compute the app target ourselves (this is
     * difficult).
     */
    app_target = (app_pc)dr_read_saved_reg(drcontext, SPILL_SLOT_2);
    /* replace the shared block, and record the new app shadow */
    if (umbra_replace_shared_shadow_memory(umbra_map, app_target,
                                           &app_shadow) != DRMF_SUCCESS) {
        DR_ASSERT(false);
        return true;
    }

    /* Replace the faulting register value to reflect the new shadow
     * memory.
     */
    reg = get_faulting_shadow_reg(drcontext, raw_mc);
    reg_set_value(reg, raw_mc, (reg_t)app_shadow);
    return false;
}

static dr_signal_action_t
event_signal_instrumentation(void *drcontext, dr_siginfo_t *info)
{
    if (info->sig != SIGSEGV && info->sig != SIGBUS)
        return DR_SIGNAL_DELIVER;
    DR_ASSERT(info->raw_mcontext_valid);
    return handle_special_shadow_fault(drcontext, info->raw_mcontext,
                                       info->access_address) ?
        DR_SIGNAL_DELIVER : DR_SIGNAL_SUPPRESS;
}

bool
shadow_init(int id)
{
    umbra_map_options_t umbra_map_ops;

    /* XXX: we only support a single umbra mapping */
    if (dr_atomic_add32_return_sum(&num_umbra_count, 1) > 1)
        return false;

    drmgr_init();

    memset(&umbra_map_ops, 0, sizeof(umbra_map_ops));
    umbra_map_ops.scale              = UMBRA_MAP_SCALE_DOWN_4X;
    umbra_map_ops.flags              = UMBRA_MAP_CREATE_SHADOW_ON_TOUCH |
                                       UMBRA_MAP_SHADOW_SHARED_READONLY;
    umbra_map_ops.default_value      = 0;
    umbra_map_ops.default_value_size = 1;

    if (umbra_init(id) != DRMF_SUCCESS)
        return false;
    if (umbra_create_mapping(&umbra_map_ops, &umbra_map) != DRMF_SUCCESS)
        return false;
    drmgr_register_signal_event(event_signal_instrumentation);
    return true;
}

bool
shadow_exit(void)
{
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        return false;
    umbra_exit();
    drmgr_exit();
}

bool
shadow_insert_app_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                            reg_id_t regaddr, reg_id_t scratch)
{
    /* XXX: we shouldn't have to do this */
    /* Save the app address to a well-known spill slot, so that the fault handler
     * can recover if no shadow memory was installed yet.
     */
    dr_save_reg(drcontext, ilist, where, regaddr, SPILL_SLOT_2);
    if (umbra_insert_app_to_shadow(drcontext, umbra_map, ilist, where, regaddr,
                                   &scratch, 1) != DRMF_SUCCESS)
        return false;
    return true;
}
