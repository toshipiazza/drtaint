# Dr. Taint

A *very* WIP DynamoRIO module built on the Dr. Memory Framework to implement taint
analysis on ARM. Core functionality is still unfinished. Very raw, still has hardcoded
paths to my hard drive in CMakeLists.txt, etc.

# Expected API

The initial API will look something like below, but will be modified later with
controllable taint propagation rules:

```c
drmf_status_t drtaint_init(void);
drmf_status_t drtaint_exit(void);

drmf_status_t drtaint_insert_app_to_taint(reg_id_t reg_addr, reg_id_t scratch);
drmf_status_t drtaint_insert_reg_to_taint(reg_id_t reg,      reg_id_t scratch);

drmf_status_t drtaint_get_taint_app(void *target, void **shadow);
drmf_status_t drtaint_get_taint_reg(reg_it_t reg, void **shadow);
```

The `drtaint` module makes use of `drmgr`, and so `drmgr` pass priority constants will
also be exposed so a user of this library can target instrumentation pre-taint and
post-taint.
