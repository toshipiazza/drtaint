#include <string.h>
#include <signal.h>
#include <stddef.h> /* for offsetof */

#include "dr_api.h"
#include "drmgr.h"
#include "umbra.h"
#include "drtaint.h"

static int num_shadow_count;
static umbra_map_t *umbra_map;
static int tls_index;

/* shadow memory */
static reg_id_t
get_faulting_shadow_reg(void *drcontext, dr_mcontext_t *mc);

static bool
handle_special_shadow_fault(void *drcontext, dr_mcontext_t *raw_mc,
                            app_pc app_shadow);

static dr_signal_action_t
event_signal_instrumentation(void *drcontext, dr_siginfo_t *info);

static bool
drtaint_shadow_mem_init(int id);

static void
drtaint_shadow_mem_exit(void);

/* shadow regs */
static bool
drtaint_shadow_reg_init(void);

static void
drtaint_shadow_reg_exit(void);

static void
event_thread_init(void *drcontext);

static void
event_thread_exit(void *drcontext);

typedef struct _per_thread_t {
    /* Holds shadow values for general purpose registers. The shadow memory
     * currently uses UMBRA_MAP_SCALE_DOWN_4X, which implies that each 4-byte
     * aligned location is represented as one byte. We imitate this here.
     */
    byte shadow_gprs[DR_NUM_GPR_REGS];
} per_thread_t;

bool
drtaint_shadow_init(int id)
{
    /* XXX: we only support a single umbra mapping */
    if (dr_atomic_add32_return_sum(&num_shadow_count, 1) > 1)
        return false;
    if (!drtaint_shadow_mem_init(id) || !drtaint_shadow_reg_init())
        return false;
    return true;
}

void
drtaint_shadow_exit(void)
{
    drtaint_shadow_mem_exit();
    drtaint_shadow_reg_exit();
}

bool
drtaint_shadow_insert_app_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
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

bool
drtaint_shadow_get_app_taint(void *drcontext, app_pc app, byte *result)
{
    size_t sz = 1;
    bool ret = umbra_read_shadow_memory(umbra_map, app, 4,
                                        &sz, result) != DRMF_ERROR_INVALID_ADDRESS;
    DR_ASSERT(sz == 1);
    return ret;
}

bool
drtaint_shadow_set_app_taint(void *drcontext, app_pc app, byte result)
{
    size_t sz = 1;
    bool ret = umbra_write_shadow_memory(umbra_map, app, 4,
                                         &sz, &result) != DRMF_ERROR_INVALID_ADDRESS;
    DR_ASSERT(sz == 1);
    return ret;
}

/* ======================================================================================
 * shadow memory implementation
 * ==================================================================================== */
static bool
drtaint_shadow_mem_init(int id)
{
    umbra_map_options_t umbra_map_ops;

    drmgr_init();

    /* initialize umbra and lazy page handling */
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

static void
drtaint_shadow_mem_exit(void)
{
    if (umbra_destroy_mapping(umbra_map) != DRMF_SUCCESS)
        DR_ASSERT(false);
    drmgr_unregister_signal_event(event_signal_instrumentation);
    umbra_exit();
    drmgr_exit();
}

static reg_id_t
get_faulting_shadow_reg(void *drcontext, dr_mcontext_t *mc)
{
    instr_t inst;
    reg_id_t reg;

    instr_init(drcontext, &inst);
    decode(drcontext, mc->pc, &inst);
    DR_ASSERT_MSG(opnd_is_base_disp(instr_get_dst(&inst, 0)),
                  "Emulation error");
    reg = opnd_get_base(instr_get_dst(&inst, 0));
    DR_ASSERT_MSG(reg != DR_REG_NULL, "Emulation error");
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

/* ======================================================================================
 * shadow registers implementation
 * ==================================================================================== */
static bool
drtaint_shadow_reg_init(void)
{
    drmgr_priority_t exit_priority = {
        sizeof(exit_priority), DRMGR_PRIORITY_NAME_DRTAINT_EXIT, NULL, NULL,
        DRMGR_PRIORITY_THREAD_EXIT_DRTAINT};
    drmgr_priority_t init_priority = {
        sizeof(init_priority), DRMGR_PRIORITY_NAME_DRTAINT_INIT, NULL, NULL,
        DRMGR_PRIORITY_THREAD_INIT_DRTAINT};

    drmgr_init();
    drmgr_register_thread_init_event_ex(event_thread_init, &init_priority);
    drmgr_register_thread_exit_event_ex(event_thread_exit, &exit_priority);

    /* initialize tls for per-thread data */
    tls_index = drmgr_register_tls_field();
    if (tls_index == -1)
        return false;
    return true;
}

bool
drtaint_shadow_insert_reg_to_shadow(void *drcontext, instrlist_t *ilist, instr_t *where,
                                    reg_id_t shadow,  reg_id_t regaddr)
{
    unsigned int offs = offsetof(per_thread_t, shadow_gprs[shadow - DR_REG_R0]);
    DR_ASSERT(shadow - DR_REG_R0 < DR_NUM_GPR_REGS);
    /* Load the per_thread data structure holding the thread-local taint
     * values of each register.
     */
    drmgr_insert_read_tls_field(drcontext, tls_index, ilist, where, regaddr);
    instrlist_meta_preinsert(ilist, where, XINST_CREATE_add
                             (drcontext,
                              opnd_create_reg(regaddr),
                              OPND_CREATE_INT8(offs)));
    return true;
}

bool
drtaint_shadow_get_reg_taint(void *drcontext, reg_id_t reg, byte *result)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    if (reg - DR_REG_R0 >= DR_NUM_GPR_REGS)
        return false;
    *result = data->shadow_gprs[reg - DR_REG_R0];
    return true;
}

bool
drtaint_shadow_set_reg_taint(void *drcontext, reg_id_t reg, byte value)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    if (reg - DR_REG_R0 >= DR_NUM_GPR_REGS)
        return false;
    data->shadow_gprs[reg - DR_REG_R0] = value;
    return true;
}

static void
drtaint_shadow_reg_exit(void)
{
    drmgr_unregister_tls_field(tls_index);
    drmgr_unregister_thread_init_event(event_thread_init);
    drmgr_unregister_thread_exit_event(event_thread_exit);
    drmgr_exit();
}

static void
event_thread_init(void *drcontext)
{
    per_thread_t *data = dr_thread_alloc(drcontext, sizeof(per_thread_t));
    memset(data, 0, sizeof(per_thread_t));
    drmgr_set_tls_field(drcontext, tls_index, data);
}

static void
event_thread_exit(void *drcontext)
{
    per_thread_t *data = drmgr_get_tls_field(drcontext, tls_index);
    dr_thread_free(drcontext, data, sizeof(per_thread_t));
}

static bool
shadow_memory_iter_func(umbra_map_t *map, umbra_shadow_memory_info_t *info,
                        void *user_data)
{
    if (info->shadow_type == UMBRA_SHADOW_MEMORY_TYPE_NORMAL) {
        FILE *fp = (FILE *)user_data;
        fprintf(fp, "APP %08x SHADOW %08x ",
                info->app_base,
                info->shadow_base);
        fwrite(info->shadow_base, 1, info->shadow_size, fp);
        fprintf(fp, "\n");
    }
    return true;
}

bool
drtaint_shadow_write_shadow_values(FILE *fp)
{
    fprintf(fp, "TAINT DUMP\n");
    return umbra_iterate_shadow_memory(
            umbra_map, fp, shadow_memory_iter_func) == DRMF_SUCCESS;
}
