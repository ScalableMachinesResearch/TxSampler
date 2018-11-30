#ifndef HTM_H
#define HTM_H

#include "cct/cct.h"
#include "sample-sources/perf/perf-util.h"

typedef struct {
  int weight_metric_id;
  int conflict_metric_id;
  int conflict_weight_metric_id;
  int capacity_read_metric_id;
  int capacity_read_weight_metric_id;
  int capacity_write_metric_id;
  int capacity_write_weight_metric_id;
  int sync_metric_id;
  int sync_weight_metric_id;
  int async_metric_id;
  int async_weight_metric_id;
} htm_metric_abort_t;

typedef struct {
  int in_htm_metric_id;
  int in_fallback_metric_id;
  int in_lockwaiting_metric_id;
  int in_other_metric_id;
} htm_metric_cyc_t;

typedef struct {
  int false_sharing_id;
  int load_metric_id;
  int store_metric_id;
} htm_metric_mem_t;

extern htm_metric_abort_t htm_metric_abort;
extern htm_metric_cyc_t htm_metric_cyc;
extern htm_metric_mem_t htm_metric_mem;

#ifdef __cplusplus
extern "C" {
#endif
// Interface to read the status of transaction from RTM library.
unsigned int get_tsx_status(int opt);
#ifdef __cplusplus
}
#endif

int htm_get_call_chain_from_lbr(struct perf_branch_entry lbr[], uint64_t bnr,
                            uint64_t current_ip, uint64_t call_chain[]);

cct_node_t *htm_add_missing_call_path_from_lbr(uint64_t call_chain[], int depth,
                                               uint64_t current_ip, cct_node_t *node);

void htm_attribute_derived_metrics(char *event_name, perf_mmap_data_t *mmap_data,
                                   cct_node_t *node, double increment);

#endif /* HTM_H */
