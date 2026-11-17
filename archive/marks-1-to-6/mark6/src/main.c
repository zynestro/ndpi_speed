#include "benchmark_internal.h"

/*
 * mark6/src/main.c
 *
 * 本文件负责：
 * 1) 解析 8E -> 8P 回放拓扑与 lookup 配置
 * 2) 初始化全局 nDPI / worker runtime / dispatch context
 * 3) 启动 worker 与 reader，执行离线回放 + cost-aware 调度
 * 4) 汇总并打印 mark3 风格的时间与吞吐结果
 */

#define DEFAULT_WORKERS 16
#define DEFAULT_DISPATCHERS 8
#define DEFAULT_LOOKUP_FILE "/home/zync/WORKSPACE/ndpi_speed/mark6/offline_costs/lookup_table.json"
#define DEFAULT_COST_PROFILE_FILE "/home/zync/WORKSPACE/ndpi_speed/mark6/offline_costs/cost_profile.csv"
#define DEFAULT_P_WORKER_CORES 8
#define DEFAULT_E_WORKER_CORES 8
#define DEFAULT_DISPATCHER_CORE_BASE 16

#ifdef MARK6_DISPATCH_HASH_ONLY
#define MARK6_POLICY_NAME "hash-only"
#else
#define MARK6_POLICY_NAME "cost-aware-jsw"
#endif

void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                             uint64_t total_cycles, double elapsed_sec,
                             uint64_t preprocess_ns,
                             uint64_t preprocess_pcap_read_ns,
                             uint64_t preprocess_normalize_ns,
                             uint64_t preprocess_hash_ns,
                             uint64_t preprocess_dispatch_rss_ns,
                             uint64_t preprocess_store_ns,
                             uint64_t preprocess_schedule_ns,
                             uint64_t preprocess_other_ns,
                             uint64_t dispatch_time_ns,
                             uint64_t dispatch_rss_lookup_ns,
                             uint64_t dispatch_enqueue_ns,
                             uint64_t dispatch_other_ns) {
  double preprocess_sec = (double)preprocess_ns / 1000000000.0;
  double effective_elapsed_sec = elapsed_sec - preprocess_sec;
  if (effective_elapsed_sec <= 0.0) effective_elapsed_sec = elapsed_sec;

  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t total_flows = 0;
  uint64_t total_flows_with_proto = 0;
  uint64_t total_process_ns = 0;
  uint64_t total_parse_ns = 0;
  uint64_t total_keybuild_ns = 0;
  uint64_t total_flow_lookup_ns = 0;
  uint64_t total_flow_init_ns = 0;
  uint64_t total_flow_ns = 0;
  uint64_t total_ndpi_call_ns = 0;
  uint64_t total_proto_check_ns = 0;
  uint64_t total_ndpi_ns = 0;
  uint64_t total_classified_fastpath_ns = 0;
  uint64_t total_other_ns = 0;
  uint64_t per_core_process_ns[PROCESS_TIME_CORE_SLOTS] = {0};

  for (uint32_t i = 0; i < num_workers; i++) {
    total_packets += workers[i].packets_processed;
    total_bytes += workers[i].bytes_processed;
    total_flows += workers[i].flows_created_total;
    total_flows_with_proto += workers[i].flows_with_protocol_total;
    if (workers[i].processing_time_ns > total_process_ns) {
      total_process_ns = workers[i].processing_time_ns;
    }
    if (workers[i].cpu_core < PROCESS_TIME_CORE_SLOTS) {
      per_core_process_ns[workers[i].cpu_core] += workers[i].processing_time_ns;
    }
    total_parse_ns += workers[i].parse_time_ns;
    total_keybuild_ns += workers[i].keybuild_time_ns;
    total_flow_lookup_ns += workers[i].flow_lookup_time_ns;
    total_flow_init_ns += workers[i].flow_init_time_ns;
    total_flow_ns += workers[i].flow_time_ns;
    total_ndpi_call_ns += workers[i].ndpi_call_time_ns;
    total_proto_check_ns += workers[i].proto_check_time_ns;
    total_ndpi_ns += workers[i].ndpi_time_ns;
    total_classified_fastpath_ns += workers[i].classified_fastpath_ns;
    total_other_ns += workers[i].other_time_ns;
  }

  double pps = (effective_elapsed_sec > 0.0) ? (double)total_packets / effective_elapsed_sec : 0.0;
  double gbps = (effective_elapsed_sec > 0.0) ? ((double)total_bytes * 8.0) / effective_elapsed_sec / 1e9 : 0.0;
  double cycles_per_packet = (total_packets > 0) ? (double)total_cycles / (double)total_packets : 0.0;

  uint64_t total_flowkey_lookup_ns = total_keybuild_ns + total_flow_lookup_ns;

  printf("\n========================================\n");
  printf("Benchmark Results\n");
  printf("========================================\n");
  printf("Total Elapsed Time: %.6f seconds\n", elapsed_sec);
  printf("Preprocess Time: %.6f seconds\n", preprocess_sec);
  printf("  Preprocess pcap_next_ex: %.6f seconds\n", (double)preprocess_pcap_read_ns / 1000000000.0);
  printf("  Preprocess normalize: %.6f seconds\n", (double)preprocess_normalize_ns / 1000000000.0);
  printf("  Preprocess hash: %.6f seconds\n", (double)preprocess_hash_ns / 1000000000.0);
  printf("  Preprocess flow->dispatcher map: %.6f seconds\n", (double)preprocess_dispatch_rss_ns / 1000000000.0);
  printf("  Preprocess packet_store: %.6f seconds\n", (double)preprocess_store_ns / 1000000000.0);
  printf("  Preprocess schedule_build: %.6f seconds\n", (double)preprocess_schedule_ns / 1000000000.0);
  printf("  Preprocess other: %.6f seconds\n", (double)preprocess_other_ns / 1000000000.0);
  printf("Elapsed Time (No Preprocess): %.6f seconds\n", effective_elapsed_sec);
  printf("Dispatch(Read) Time: %.6f seconds\n", (double)dispatch_time_ns / 1000000000.0);
  printf("  Dispatch flow->worker map: %.6f seconds\n", (double)dispatch_rss_lookup_ns / 1000000000.0);
  printf("  Dispatch enqueue: %.6f seconds\n", (double)dispatch_enqueue_ns / 1000000000.0);
  printf("  Dispatch other: %.6f seconds\n", (double)dispatch_other_ns / 1000000000.0);
  printf("Process Time: %.6f seconds\n", (double)total_process_ns / 1000000000.0);
  printf("  Process parse: %.6f seconds\n", (double)total_parse_ns / 1000000000.0);
  printf("  Process flowkey_lookup: %.6f seconds\n", (double)total_flowkey_lookup_ns / 1000000000.0);
  printf("  Process flow_init: %.6f seconds\n", (double)total_flow_init_ns / 1000000000.0);
  printf("  Process flow: %.6f seconds\n", (double)total_flow_ns / 1000000000.0);
  printf("  Process nDPI call: %.6f seconds\n", (double)total_ndpi_call_ns / 1000000000.0);
  printf("  Process proto_check: %.6f seconds\n", (double)total_proto_check_ns / 1000000000.0);
  printf("  Process nDPI: %.6f seconds\n", (double)total_ndpi_ns / 1000000000.0);
  printf("  Process classified_fastpath: %.6f seconds\n", (double)total_classified_fastpath_ns / 1000000000.0);
  printf("  Process other: %.6f seconds\n", (double)total_other_ns / 1000000000.0);
  printf("Per-Core Process Time (sec): ");
  for (uint32_t c = 0; c < PROCESS_TIME_CORE_SLOTS; c++) {
    if (c > 0) printf(",");
    printf("%.6f", (double)per_core_process_ns[c] / 1000000000.0);
  }
  printf("\n");
  printf("Total Packets: %lu\n", (unsigned long)total_packets);
  printf("Total Bytes: %.2f MB\n", (double)total_bytes / 1024.0 / 1024.0);
  printf("\nPerformance:\n");
  printf("  Throughput: %.2f Mpps\n", pps / 1e6);
  printf("  Bandwidth: %.2f Gbps\n", gbps);
  printf("  Cycles per packet: %.2f\n", cycles_per_packet);

  printf("\nProtocol Detection Verification:\n");
  printf("  Total flows created: %lu\n", (unsigned long)total_flows);
  printf("  Flows with detected protocol: %lu (%.1f%%)\n",
         (unsigned long)total_flows_with_proto,
         total_flows ? (double)total_flows_with_proto * 100.0 / (double)total_flows : 0.0);
  if (total_flows_with_proto > 0) {
    printf("  ✓ nDPI is actively detecting protocols!\n");
  } else {
    printf("  ✗ WARNING: No protocols detected!\n");
  }

  if (num_workers > 1) {
    uint64_t core_type_packets[COST_CORE_TYPES] = {0};
    uint64_t core_type_bytes[COST_CORE_TYPES] = {0};
    uint64_t core_type_flows[COST_CORE_TYPES] = {0};
    uint64_t core_type_process_ns[COST_CORE_TYPES] = {0};
    uint32_t core_type_workers[COST_CORE_TYPES] = {0};
    double min_worker_pps = 0.0;
    double max_worker_pps = 0.0;
    uint32_t min_worker_pps_id = 0;
    uint32_t max_worker_pps_id = 0;
    double min_worker_avg_pkt = 0.0;
    double max_worker_avg_pkt = 0.0;
    uint32_t min_worker_avg_pkt_id = 0;
    uint32_t max_worker_avg_pkt_id = 0;
    bool have_worker_load = false;

    printf("\nPer-Worker Statistics:\n");
    for (uint32_t i = 0; i < num_workers; i++) {
      double w_pps = (effective_elapsed_sec > 0.0) ? (double)workers[i].packets_processed / effective_elapsed_sec : 0.0;
      double w_gbps = (effective_elapsed_sec > 0.0) ? ((double)workers[i].bytes_processed * 8.0) / effective_elapsed_sec / 1e9 : 0.0;
      double w_avg_pkt = workers[i].packets_processed
                             ? (double)workers[i].bytes_processed / (double)workers[i].packets_processed
                             : 0.0;
      uint8_t type = core_type_from_core_id(workers[i].cpu_core);
      if (type >= COST_CORE_TYPES) type = CORE_TYPE_P;
      core_type_packets[type] += workers[i].packets_processed;
      core_type_bytes[type] += workers[i].bytes_processed;
      core_type_flows[type] += workers[i].flows_created_total;
      core_type_workers[type]++;
      if (workers[i].processing_time_ns > core_type_process_ns[type]) {
        core_type_process_ns[type] = workers[i].processing_time_ns;
      }
      if (workers[i].packets_processed > 0) {
        if (!have_worker_load || w_pps < min_worker_pps) {
          min_worker_pps = w_pps;
          min_worker_pps_id = i;
        }
        if (!have_worker_load || w_pps > max_worker_pps) {
          max_worker_pps = w_pps;
          max_worker_pps_id = i;
        }
        if (!have_worker_load || w_avg_pkt < min_worker_avg_pkt) {
          min_worker_avg_pkt = w_avg_pkt;
          min_worker_avg_pkt_id = i;
        }
        if (!have_worker_load || w_avg_pkt > max_worker_avg_pkt) {
          max_worker_avg_pkt = w_avg_pkt;
          max_worker_avg_pkt_id = i;
        }
        have_worker_load = true;
      }
      printf("  Worker %2u [Core %2u]: %.2f Mpps, %.2f Gbps, %lu flows, %.3f s proc "
             "(parse %.3f, flow %.3f, ndpi %.3f)\n",
             i, workers[i].cpu_core,
             w_pps / 1e6, w_gbps,
             (unsigned long)workers[i].flows_created_total,
             (double)workers[i].processing_time_ns / 1000000000.0,
             (double)workers[i].parse_time_ns / 1000000000.0,
             (double)workers[i].flow_time_ns / 1000000000.0,
             (double)workers[i].ndpi_time_ns / 1000000000.0);
    }

    printf("\nPer-Worker Load Details:\n");
    printf("  Worker Core Type Packets Pkt%% Bytes(MB) Byte%% AvgB/Pkt Flows Flow%% Pkts/Flow Proc(ns/pkt)\n");
    for (uint32_t i = 0; i < num_workers; i++) {
      uint64_t packets = workers[i].packets_processed;
      uint64_t bytes = workers[i].bytes_processed;
      uint64_t flows = workers[i].flows_created_total;
      double pkt_pct = total_packets ? (double)packets * 100.0 / (double)total_packets : 0.0;
      double byte_pct = total_bytes ? (double)bytes * 100.0 / (double)total_bytes : 0.0;
      double flow_pct = total_flows ? (double)flows * 100.0 / (double)total_flows : 0.0;
      double avg_pkt = packets ? (double)bytes / (double)packets : 0.0;
      double pkts_per_flow = flows ? (double)packets / (double)flows : 0.0;
      double proc_ns_per_pkt = packets
                                   ? (double)workers[i].processing_time_ns / (double)packets
                                   : 0.0;
      const char *type_name =
          (core_type_from_core_id(workers[i].cpu_core) == CORE_TYPE_P) ? "P" : "E";
      printf("  %6u %4u %4s %7lu %5.1f %9.2f %5.1f %8.1f %5lu %5.1f %9.1f %12.1f\n",
             i,
             workers[i].cpu_core,
             type_name,
             (unsigned long)packets,
             pkt_pct,
             (double)bytes / 1024.0 / 1024.0,
             byte_pct,
             avg_pkt,
             (unsigned long)flows,
             flow_pct,
             pkts_per_flow,
             proc_ns_per_pkt);
    }

    printf("\nCore-Type Load Summary:\n");
    printf("  Type Workers Packets Pkt%% Bytes(MB) Byte%% AvgB/Pkt Flows Flow%% Throughput(Mpps) Bandwidth(Gbps) MaxProc(s)\n");
    for (uint32_t type = 0; type < COST_CORE_TYPES; type++) {
      uint64_t packets = core_type_packets[type];
      uint64_t bytes = core_type_bytes[type];
      uint64_t flows = core_type_flows[type];
      double pkt_pct = total_packets ? (double)packets * 100.0 / (double)total_packets : 0.0;
      double byte_pct = total_bytes ? (double)bytes * 100.0 / (double)total_bytes : 0.0;
      double flow_pct = total_flows ? (double)flows * 100.0 / (double)total_flows : 0.0;
      double avg_pkt = packets ? (double)bytes / (double)packets : 0.0;
      double type_pps = effective_elapsed_sec > 0.0 ? (double)packets / effective_elapsed_sec : 0.0;
      double type_gbps = effective_elapsed_sec > 0.0 ? (double)bytes * 8.0 / effective_elapsed_sec / 1e9 : 0.0;
      printf("  %4s %7u %7lu %5.1f %9.2f %5.1f %8.1f %5lu %5.1f %16.2f %15.2f %10.3f\n",
             type == CORE_TYPE_P ? "P" : "E",
             core_type_workers[type],
             (unsigned long)packets,
             pkt_pct,
             (double)bytes / 1024.0 / 1024.0,
             byte_pct,
             avg_pkt,
             (unsigned long)flows,
             flow_pct,
             type_pps / 1e6,
             type_gbps,
             (double)core_type_process_ns[type] / 1000000000.0);
    }

    if (have_worker_load) {
      double pps_ratio = min_worker_pps > 0.0 ? max_worker_pps / min_worker_pps : 0.0;
      double avg_pkt_ratio = min_worker_avg_pkt > 0.0 ? max_worker_avg_pkt / min_worker_avg_pkt : 0.0;
      printf("\nLoad Imbalance Hints:\n");
      printf("  Worker PPS min/max: worker %u %.2f Mpps, worker %u %.2f Mpps (%.2fx)\n",
             min_worker_pps_id,
             min_worker_pps / 1e6,
             max_worker_pps_id,
             max_worker_pps / 1e6,
             pps_ratio);
      printf("  Avg packet size min/max: worker %u %.1f B, worker %u %.1f B (%.2fx)\n",
             min_worker_avg_pkt_id,
             min_worker_avg_pkt,
             max_worker_avg_pkt_id,
             max_worker_avg_pkt,
             avg_pkt_ratio);
    }

    double base_pps = (effective_elapsed_sec > 0.0) ? (double)workers[0].packets_processed / effective_elapsed_sec : 0.0;
    double scaling = (num_workers > 0 && base_pps > 0.0) ? (pps / num_workers) / base_pps : 0.0;
    printf("\nScaling Efficiency: %.1f%%\n", scaling * 100.0);
  }

  printf("========================================\n");
}

static void usage(void) {
  printf("ndpiBenchmarkMark6 - offline nDPI benchmark with simulated RSS and cost-aware dispatch\n\n");
  printf("Usage: ndpiBenchmarkMark6 -i <pcap> [options]\n\n");
  printf("Required:\n");
  printf("  -i <file>          PCAP file to process\n\n");
  printf("Options:\n");
  printf("  -n <num>           Number of worker threads (default: %d)\n", DEFAULT_WORKERS);
  printf("  -c <list>          Worker core list (default: 0,2,4,6,8,10,12,14,24-31)\n");
  printf("  -d <list>          Dispatcher(E-core) list (default: %d-%d)\n",
         DEFAULT_DISPATCHER_CORE_BASE,
         DEFAULT_DISPATCHER_CORE_BASE + DEFAULT_DISPATCHERS - 1);
  printf("  -m <file>          Lookup table JSON (default: %s)\n", DEFAULT_LOOKUP_FILE);
  printf("  -C <file>          Offline P/E bucket cost CSV (default: %s)\n",
         DEFAULT_COST_PROFILE_FILE);
  printf("  -p <file>          Protocol configuration file\n");
  printf("  -q                 Quiet mode\n");
  printf("  -h                 Show this help\n\n");
  printf("Example:\n");
  printf("  ndpiBenchmarkMark6 -i input/Monday-WorkingHours.pcap\n\n");
}

static uint32_t *parse_core_list(const char *s, uint32_t *out_count) {
  *out_count = 0;
  if (!s || !s[0]) return NULL;

  char *tmp = strdup(s);
  if (!tmp) return NULL;

  uint32_t count = 0;
  char *saveptr = NULL;
  char *tok = strtok_r(tmp, ",", &saveptr);
  while (tok) {
    count++;
    tok = strtok_r(NULL, ",", &saveptr);
  }
  free(tmp);

  if (count == 0 || count > MAX_WORKERS) return NULL;

  uint32_t *cores = (uint32_t *)calloc(count, sizeof(uint32_t));
  if (!cores) return NULL;

  tmp = strdup(s);
  if (!tmp) {
    free(cores);
    return NULL;
  }

  saveptr = NULL;
  tok = strtok_r(tmp, ",", &saveptr);
  uint32_t i = 0;
  while (tok && i < count) {
    cores[i++] = (uint32_t)atoi(tok);
    tok = strtok_r(NULL, ",", &saveptr);
  }
  free(tmp);

  *out_count = count;
  return cores;
}

static uint32_t *alloc_default_core_list(uint32_t base_core, uint32_t count) {
  uint32_t *cores = (uint32_t *)calloc(count, sizeof(uint32_t));
  if (!cores) return NULL;
  for (uint32_t i = 0; i < count; i++) {
    cores[i] = base_core + i;
  }
  return cores;
}

static uint32_t *alloc_default_worker_core_list(void) {
  uint32_t *cores = (uint32_t *)calloc(DEFAULT_WORKERS, sizeof(uint32_t));
  if (!cores) return NULL;

  for (uint32_t i = 0; i < DEFAULT_P_WORKER_CORES; i++) {
    cores[i] = i * 2U;
  }
  for (uint32_t i = 0; i < DEFAULT_E_WORKER_CORES; i++) {
    cores[DEFAULT_P_WORKER_CORES + i] = 24U + i;
  }

  return cores;
}

static worker_runtime_state_t *alloc_worker_runtime_states(const uint32_t *cores,
                                                           uint32_t num_workers) {
  worker_runtime_state_t *states = NULL;
  if (posix_memalign((void **)&states, 64, num_workers * sizeof(*states)) != 0) {
    return NULL;
  }
  memset(states, 0, num_workers * sizeof(*states));

  for (uint32_t i = 0; i < num_workers; i++) {
    states[i].core_id = (uint8_t)cores[i];
    states[i].core_type = core_type_from_core_id(cores[i]);
    states[i].speed_factor_x1000 = core_speed_factor_x1000(cores[i]);
    atomic_init(&states[i].added_cost_x1000, 0);
    atomic_init(&states[i].retired_cost_x1000, 0);
    atomic_init(&states[i].queue_depth, 0);
  }

  return states;
}

static void print_dispatch_summary(const dispatch_context_t *dispatch,
                                   worker_context_t *workers,
                                   uint32_t num_workers) {
  const dispatch_stats_t *stats = dispatch_get_stats(dispatch);
  if (!stats) return;

  printf("\nDispatch Summary:\n");
  printf("  New flow assignments: %lu\n", (unsigned long)stats->new_flow_assignments);
  printf("  Existing flow hits: %lu\n", (unsigned long)stats->existing_flow_hits);
  printf("  Bucket flows: Easy=%lu Middle=%lu Hard=%lu\n",
         (unsigned long)stats->bucket_flow_counts[COST_BUCKET_EASY],
         (unsigned long)stats->bucket_flow_counts[COST_BUCKET_MIDDLE],
         (unsigned long)stats->bucket_flow_counts[COST_BUCKET_HARD]);

  printf("  Per-worker dispatch view:\n");
  for (uint32_t i = 0; i < num_workers; i++) {
    worker_runtime_state_t *state = workers[i].runtime;
    uint64_t added = atomic_load_explicit(&state->added_cost_x1000, memory_order_relaxed);
    uint64_t retired = atomic_load_explicit(&state->retired_cost_x1000, memory_order_relaxed);
    uint32_t depth = atomic_load_explicit(&state->queue_depth, memory_order_relaxed);
    printf("    Worker %2u [Core %2u]: %lu flows, pending %.3f, queue_depth %u\n",
           i,
           workers[i].cpu_core,
           (unsigned long)stats->worker_flow_counts[i],
           (double)((added >= retired) ? (added - retired) : 0) / 1000.0,
           depth);
  }
}

static benchmark_config_t parse_args(int argc, char **argv) {
  /* 参数解析目标：
   * - 形成 benchmark_config_t（后续 main 全流程只依赖该配置）
   * - 对 worker 数量/核心列表做基础合法性检查
   */
  benchmark_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));

  cfg.num_workers = DEFAULT_WORKERS;
  cfg.num_dispatchers = DEFAULT_DISPATCHERS;
  cfg.lookup_file = DEFAULT_LOOKUP_FILE;
  cfg.cost_profile_file = DEFAULT_COST_PROFILE_FILE;

  char *worker_core_list_str = NULL;
  char *dispatcher_core_list_str = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "i:n:c:d:m:C:p:qh")) != -1) {
    switch (opt) {
      case 'i':
        cfg.pcap_file = optarg;
        break;
      case 'n':
        cfg.num_workers = (uint32_t)atoi(optarg);
        if (cfg.num_workers < 1 || cfg.num_workers > MAX_WORKERS) {
          fprintf(stderr, "Error: invalid number of workers (1-%d)\n", MAX_WORKERS);
          exit(1);
        }
        break;
      case 'c':
        worker_core_list_str = strdup(optarg);
        break;
      case 'd':
        dispatcher_core_list_str = strdup(optarg);
        break;
      case 'm':
        cfg.lookup_file = optarg;
        break;
      case 'C':
        cfg.cost_profile_file = optarg;
        break;
      case 'p':
        cfg.proto_file = optarg;
        break;
      case 'q':
        cfg.quiet_mode = true;
        break;
      case 'h':
        usage();
        exit(0);
      default:
        usage();
        exit(1);
    }
  }

  if (!cfg.pcap_file) {
    fprintf(stderr, "Error: PCAP file required (-i)\n\n");
    usage();
    exit(1);
  }

  if (worker_core_list_str) {
    uint32_t parsed_count = 0;
    cfg.core_list = parse_core_list(worker_core_list_str, &parsed_count);
    free(worker_core_list_str);
    if (!cfg.core_list || parsed_count != cfg.num_workers) {
      fprintf(stderr, "Error: worker core list must contain exactly %u cores\n", cfg.num_workers);
      exit(1);
    }
  } else {
    if (cfg.num_workers == DEFAULT_WORKERS) {
      cfg.core_list = alloc_default_worker_core_list();
    } else {
      cfg.core_list = alloc_default_core_list(0, cfg.num_workers);
    }
    if (!cfg.core_list) {
      fprintf(stderr, "Error: out of memory\n");
      exit(1);
    }
  }

  if (dispatcher_core_list_str) {
    cfg.dispatcher_core_list = parse_core_list(dispatcher_core_list_str,
                                               &cfg.num_dispatchers);
    free(dispatcher_core_list_str);
    if (!cfg.dispatcher_core_list || cfg.num_dispatchers == 0) {
      fprintf(stderr, "Error: invalid dispatcher core list\n");
      exit(1);
    }
  } else {
    cfg.dispatcher_core_list = alloc_default_core_list(DEFAULT_DISPATCHER_CORE_BASE,
                                                       cfg.num_dispatchers);
    if (!cfg.dispatcher_core_list) {
      fprintf(stderr, "Error: out of memory\n");
      exit(1);
    }
  }

  return cfg;
}

int main(int argc, char **argv) {
  /* 0) 读取运行配置并同步 quiet 标志到全局输出控制位。 */
  benchmark_config_t cfg = parse_args(argc, argv);
  g_quiet_mode = cfg.quiet_mode;

  printf("========================================\n");
  printf("Standalone nDPI Benchmark Tool (mark6)\n");
  printf("========================================\n\n");
  printf("Policy: %s\n\n", MARK6_POLICY_NAME);

  /* 1) 初始化 nDPI 全局上下文（供所有 worker 共享只读元数据）。 */
  printf("[1/4] Initializing nDPI...\n");
  struct ndpi_global_context *g_ctx = ndpi_global_init();
  if (!g_ctx) {
    fprintf(stderr, "Error: ndpi_global_init() failed\n");
    return 1;
  }

  cost_table_t cost_table;
  if (!cost_table_load(&cost_table, cfg.lookup_file)) {
    ndpi_global_deinit(g_ctx);
    free(cfg.core_list);
    free(cfg.dispatcher_core_list);
    return 1;
  }

  cost_profile_t cost_profile;
  if (!cost_profile_load_csv(&cost_profile, cfg.cost_profile_file)) {
    cost_table_destroy(&cost_table);
    ndpi_global_deinit(g_ctx);
    free(cfg.core_list);
    free(cfg.dispatcher_core_list);
    return 1;
  }

  worker_runtime_state_t *worker_states =
      alloc_worker_runtime_states(cfg.core_list, cfg.num_workers);
  if (!worker_states) {
    fprintf(stderr, "Error: failed to allocate worker runtime states\n");
    cost_table_destroy(&cost_table);
    ndpi_global_deinit(g_ctx);
    free(cfg.core_list);
    free(cfg.dispatcher_core_list);
    return 1;
  }

  /* 2) 构建 worker 上下文：
   * - 分配每 worker 队列
   * - 绑定核心、协议配置、全局上下文引用
   */
  printf("[2/4] Creating %u worker thread(s)...\n", cfg.num_workers);
  worker_context_t *workers = (worker_context_t *)calloc(cfg.num_workers, sizeof(worker_context_t));
  if (!workers) {
    fprintf(stderr, "Error: failed to allocate workers\n");
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    workers[i].worker_id = i;
    workers[i].cpu_core = cfg.core_list[i];
    workers[i].proto_file = cfg.proto_file;
    workers[i].g_ctx = g_ctx;
    workers[i].runtime = &worker_states[i];

    /* queue 是 reader/dispatcher -> worker 的唯一数据通道。 */
    workers[i].queue = packet_queue_create(QUEUE_CAPACITY);
    if (!workers[i].queue) {
      fprintf(stderr, "Error: failed to create packet queue for worker %u\n", i);
      for (uint32_t j = 0; j < i; j++) cleanup_worker(&workers[j]);
      free(workers);
      free(worker_states);
      cost_table_destroy(&cost_table);
      ndpi_global_deinit(g_ctx);
      free(cfg.core_list);
      free(cfg.dispatcher_core_list);
      return 1;
    }

#ifdef NDPI_BENCHMARK_CLASSIFIED
    workers[i].classified = classified_table_create(1u << 16);
    if (!workers[i].classified) {
      fprintf(stderr, "Error: failed to create classified table for worker %u\n", i);
      for (uint32_t j = 0; j <= i; j++) cleanup_worker(&workers[j]);
      free(workers);
      free(worker_states);
      cost_table_destroy(&cost_table);
      ndpi_global_deinit(g_ctx);
      free(cfg.core_list);
      free(cfg.dispatcher_core_list);
      return 1;
    }
#endif
  }

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    /* 每个 worker 独立初始化 nDPI module 与 flow table。 */
    init_worker_ndpi(&workers[i]);
  }

  dispatch_context_t *dispatch_ctx =
      dispatch_context_create(&cost_table, &cost_profile, workers, cfg.num_workers,
                              cfg.num_dispatchers);
  if (!dispatch_ctx) {
    fprintf(stderr, "Error: failed to create dispatch context\n");
    for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);
    free(workers);
    free(worker_states);
    cost_table_destroy(&cost_table);
    ndpi_global_deinit(g_ctx);
    free(cfg.core_list);
    free(cfg.dispatcher_core_list);
    return 1;
  }

  /* 3) 启动 benchmark：
   * - worker 先就绪并阻塞等包
   * - reader 再开始读包/预处理/分发
   */
  printf("[3/4] Starting streaming benchmark...\n");
  printf("      PCAP: %s\n", cfg.pcap_file);
  printf("      Lookup: %s\n", cfg.lookup_file);
  printf("      Cost profile: %s\n", cfg.cost_profile_file);
  printf("      Policy: %s\n", MARK6_POLICY_NAME);
  printf("      Workers: %u\n", cfg.num_workers);
  printf("      Dispatchers: %u\n", cfg.num_dispatchers);
  printf("\n----------------------------------------\n");
  printf("Protocol Detection Samples (first %lu flows):\n", (unsigned long)g_sample_limit);
  printf("----------------------------------------\n\n");

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    if (pthread_create(&workers[i].thread, NULL, worker_thread_entry, &workers[i]) != 0) {
      fprintf(stderr, "Error: pthread_create(worker=%u) failed\n", i);
      exit(1);
    }
  }

  reader_context_t reader_ctx = {
      .pcap_file = cfg.pcap_file,
      .lookup_file = cfg.lookup_file,
      .workers = workers,
      .num_workers = cfg.num_workers,
      .num_dispatchers = cfg.num_dispatchers,
      .dispatcher_cores = cfg.dispatcher_core_list,
      .dispatch = dispatch_ctx,
      .packets = NULL,
      .packet_count = 0,
      .dispatcher_offsets = NULL,
      .dispatcher_indices = NULL,
      .read_time_ns = 0,
      .pcap_read_ns = 0,
      .normalize_ns = 0,
      .hash_ns = 0,
      .rss_lookup_ns = 0,
      .enqueue_ns = 0,
      .read_other_ns = 0,
      .preprocess_ns = 0,
      .preprocess_dispatch_rss_ns = 0,
      .preprocess_store_ns = 0,
      .preprocess_schedule_ns = 0,
      .preprocess_other_ns = 0,
        .failed = false,
  };

  pthread_t reader;

  uint64_t wall_start_ns = 0, wall_end_ns = 0;
  /* cycles + wall-time 双轨计时：
   * - cycles 看微观代价
   * - wall-time 看端到端耗时
   */
  uint64_t cycles_start = rdtsc();
  wall_start_ns = get_time_ns();

  if (pthread_create(&reader, NULL, reader_thread_entry, &reader_ctx) != 0) {
    fprintf(stderr, "Error: pthread_create(dispatcher_controller) failed\n");
    exit(1);
  }

  /* reader 线程退出后，worker 也会在队列 finished 后自然退出。 */
  pthread_join(reader, NULL);
  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    pthread_join(workers[i].thread, NULL);
  }
  reader_context_cleanup(&reader_ctx);

  if (reader_ctx.failed) {
    fprintf(stderr, "Error: reader stage failed, benchmark aborted.\n");
    dispatch_context_destroy(dispatch_ctx);
    for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);
    free(workers);
    free(worker_states);
    cost_table_destroy(&cost_table);
    ndpi_global_deinit(g_ctx);
    free(cfg.core_list);
    free(cfg.dispatcher_core_list);
    return 1;
  }

  uint64_t cycles_end = rdtsc();
  wall_end_ns = get_time_ns();
  double elapsed = (wall_end_ns > wall_start_ns)
                       ? (double)(wall_end_ns - wall_start_ns) / 1000000000.0
                       : 0.0;

  /* 4) 汇总输出：
   * - preprocess / dispatch / process 三层时间
   * - 吞吐、带宽、flow 识别结果
   */
  printf("[4/4] Done.\n");
  print_benchmark_results(workers, cfg.num_workers, cycles_end - cycles_start, elapsed,
                          reader_ctx.preprocess_ns,
                          reader_ctx.pcap_read_ns,
                          reader_ctx.normalize_ns,
                          reader_ctx.hash_ns,
                          reader_ctx.preprocess_dispatch_rss_ns,
                          reader_ctx.preprocess_store_ns,
                          reader_ctx.preprocess_schedule_ns,
                          reader_ctx.preprocess_other_ns,
                          reader_ctx.read_time_ns,
                          reader_ctx.rss_lookup_ns,
                          reader_ctx.enqueue_ns,
                          reader_ctx.read_other_ns);
  print_dispatch_summary(dispatch_ctx, workers, cfg.num_workers);

  /* 按“创建反序”释放资源，避免悬空引用。 */
  dispatch_context_destroy(dispatch_ctx);
  for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);

  free(workers);
  free(worker_states);
  cost_table_destroy(&cost_table);
  ndpi_global_deinit(g_ctx);
  free(cfg.core_list);
  free(cfg.dispatcher_core_list);

  return 0;
}
