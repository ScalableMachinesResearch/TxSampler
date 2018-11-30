#include "htm.h"

#include "fnbounds/fnbounds_interface.h"
#include "sample-sources/perf/perf-util.h"
#include "sample-sources/shadow-memory.h"
#include "unwind/x86-family/x86-decoder.h"

htm_metric_abort_t htm_metric_abort = {-1,-1,-1,-1,-1,-1,-1,-1,-1,-1,-1};
htm_metric_cyc_t htm_metric_cyc = {-1,-1,-1,-1};
htm_metric_mem_t htm_metric_mem = {-1,-1,-1};

/*
 * Returns the address of next instruction.
 * It only supports x86 and xed_tables_init() should be called in advance.
 * If error, returns 0.
 */
static uint64_t get_next_ip(uint64_t ip) {
  xed_decoded_inst_t  xedd;
  xed_decoded_inst_zero_set_mode(&xedd, &(x86_decoder_settings.xed_settings));
  if(XED_ERROR_NONE == xed_decode(&xedd, (const xed_uint8_t*) (ip), 15)) {
    xed_uint_t len = xed_decoded_inst_get_length(&xedd);
    return ip + len;
  }
  return 0;
}

/*
 * Constructs a call path from LBRs.
 * input: lbr, bnr, current_ip (IP of the current sample)
 * output: call_chain, an array of IPs of call instructions
 * return: -2, no lbr
 *         -1, not in TX
 *         other non-negative integer, the number of IPs in call_chain
 */
int htm_get_call_chain_from_lbr
(
  struct perf_branch_entry lbr[],
  uint64_t bnr,
  uint64_t current_ip,
  uint64_t call_chain[]
){
  if (bnr == 0 || bnr > MAX_LBR_ENTRIES) {
    return -2;
  }
  if (lbr[0].abort == 0) {
    // not from an HTM abort, thus no need to use LBRs
    return -1;
  }
  uint64_t last_call_ip = current_ip; // TODO(jqswang): remove current_ip
  uint32_t depth = 0;
  for (int i = 1 ; i < bnr; i++){ // i = 2,3,4,...
    if (lbr[i].in_tx == 0) {
      break;
    }
    uint64_t function_start, function_end;
    fnbounds_enclosing_addr( (void *)last_call_ip , (void **)&function_start, (void **)&function_end, NULL);
    if (function_start == lbr[i].to){
      call_chain[depth++] = last_call_ip = lbr[i].from;
    }
  }
  return depth;
}

/*
 * Pseudo node connecting in-HTM and out-of-HTM.
 */
void begin_in_tx(void)
{}

/*
 * Add the missing call path inside transactions according to LBRs.
 */
cct_node_t * htm_add_missing_call_path_from_lbr(
  uint64_t call_chain[],
  int depth,
  uint64_t current_ip,
  cct_node_t *node
){
  if (depth > 1) {
    // Insert a pseudo node to indicate that the call is recovered from the LBR in HTM
    node = hpcrun_cct_append_node(node, (void *)((uint64_t)begin_in_tx+1));
    // Insert LBR nodes, omit the last call in the lbr call chain
    for (int i = depth-2; i >=0 ; i--) {
      uint64_t next_ip = get_next_ip(call_chain[i]);
      if (next_ip == 0) {
        next_ip = call_chain[i]+1;
      }
      node = hpcrun_cct_append_node(node, (void *)(next_ip));
    }
    // Insert the sampled IP
    node = hpcrun_cct_append_node(node, (void *)current_ip);
    hpcrun_cct_terminate_path(node);
  }
  else if (depth == 0 || depth == 1){
     node = hpcrun_cct_append_node(node, (void *)((uint64_t)begin_in_tx+1));
     // log the sampled IP and its metric
     node = hpcrun_cct_append_node(node, (void *)current_ip);
     hpcrun_cct_terminate_path(node);
  }
  return node;
}

void htm_attribute_derived_metrics(
  char *event_name,
  perf_mmap_data_t *mmap_data,
  cct_node_t *node,
  double increment
){
  if (strstr(event_name, "cycles")) {
    unsigned int status_id = get_tsx_status(0);
    if (mmap_data->bnr > 0 && mmap_data->bnr <= MAX_LBR_ENTRIES) {
      if (mmap_data->lbr[0].abort == 1) {
        cct_metric_data_increment(htm_metric_cyc.in_htm_metric_id, node, (hpcrun_metricVal_t){.r = increment});
        return;
      }
    } else {
      if ((status_id & 0b11) == 0b11 ) {
        cct_metric_data_increment(htm_metric_cyc.in_htm_metric_id, node, (hpcrun_metricVal_t){.r = increment});
        return;
      }
    }
    if ((status_id & 0b101) == 0b101){
      cct_metric_data_increment(htm_metric_cyc.in_fallback_metric_id, node, (hpcrun_metricVal_t){.r = increment});
      return;
    }
    if ((status_id & 0b1001) == 0b1001){
      cct_metric_data_increment(htm_metric_cyc.in_lockwaiting_metric_id, node, (hpcrun_metricVal_t){.r = increment});
      return;
    }
    if ( (status_id & 0b1) == 0b1 ) {
      cct_metric_data_increment(htm_metric_cyc.in_other_metric_id, node, (hpcrun_metricVal_t){.r = increment});
      return;
    }
  }
    
  if (strstr(event_name, "RTM_RETIRED:ABORTED")) {
    // update the weight metric of the transaction
    cct_metric_data_increment(htm_metric_abort.weight_metric_id, node, (hpcrun_metricVal_t){.r = increment * mmap_data->weight});
    // attribute based on the abort reason
    if (mmap_data->transaction & PERF_TXN_CONFLICT) {
      cct_metric_data_increment(htm_metric_abort.conflict_metric_id, node, (hpcrun_metricVal_t) {.r = increment});
      cct_metric_data_increment(htm_metric_abort.conflict_weight_metric_id, node, (hpcrun_metricVal_t) {.r = increment * mmap_data->weight});
    }
    if (mmap_data->transaction & PERF_TXN_CAPACITY_READ) {
      cct_metric_data_increment(htm_metric_abort.capacity_read_metric_id, node, (hpcrun_metricVal_t) {.r = increment});
      cct_metric_data_increment(htm_metric_abort.capacity_read_weight_metric_id, node, (hpcrun_metricVal_t) {.r = increment * mmap_data->weight});
    }
    if (mmap_data->transaction & PERF_TXN_CAPACITY_WRITE) {
      cct_metric_data_increment(htm_metric_abort.capacity_write_metric_id, node, (hpcrun_metricVal_t) {.r = increment});
      cct_metric_data_increment(htm_metric_abort.capacity_write_weight_metric_id, node, (hpcrun_metricVal_t) {.r = increment * mmap_data->weight});
    }
    if (mmap_data->transaction & PERF_TXN_SYNC) {
      cct_metric_data_increment(htm_metric_abort.sync_metric_id, node, (hpcrun_metricVal_t) {.r = increment});
      cct_metric_data_increment(htm_metric_abort.sync_weight_metric_id, node, (hpcrun_metricVal_t) {.r = increment * mmap_data->weight});
    }
    if (mmap_data->transaction & PERF_TXN_ASYNC) {
      cct_metric_data_increment(htm_metric_abort.async_metric_id, node, (hpcrun_metricVal_t) {.r = increment});
      cct_metric_data_increment(htm_metric_abort.async_weight_metric_id, node, (hpcrun_metricVal_t) {.r = increment * mmap_data->weight});
    }
  }
     
  if (strstr(event_name, "MEM_UOPS_RETIRED:ALL_LOADS")) {
    int count = htm_record_and_get_contention(mmap_data->addr, mmap_data->tid, 0 /*is_write*/);
    cct_metric_data_increment(htm_metric_mem.false_sharing_id, node, (hpcrun_metricVal_t) {.r = increment * count});
    return;
  }

  if (strstr(event_name, "MEM_UOPS_RETIRED:ALL_STORES")) {
    int count = htm_record_and_get_contention(mmap_data->addr, mmap_data->tid, 1 /*is_write*/);
    cct_metric_data_increment(htm_metric_mem.false_sharing_id, node, (hpcrun_metricVal_t) {.r = increment * count});
    return;
  }
} 


