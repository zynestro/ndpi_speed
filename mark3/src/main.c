#include "benchmark_internal.h"

void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                             uint64_t total_cycles, double elapsed_sec,
                             uint64_t read_time_ns,
                             uint64_t pcap_read_ns,
                             uint64_t normalize_ns,
                             uint64_t hash_ns,
                             uint64_t rss_lookup_ns,
                             uint64_t enqueue_ns,
                             uint64_t read_other_ns) {
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

  double pps = (elapsed_sec > 0.0) ? (double)total_packets / elapsed_sec : 0.0;
  double gbps = (elapsed_sec > 0.0) ? ((double)total_bytes * 8.0) / elapsed_sec / 1e9 : 0.0;
  double cycles_per_packet = (total_packets > 0) ? (double)total_cycles / (double)total_packets : 0.0;

  uint64_t read_other_merged_ns = read_other_ns + normalize_ns;
  uint64_t total_flowkey_lookup_ns = total_keybuild_ns + total_flow_lookup_ns;

  printf("\n========================================\n");
  printf("Benchmark Results\n");
  printf("========================================\n");
  printf("Elapsed Time: %.6f seconds\n", elapsed_sec);
  printf("Read Time: %.6f seconds\n", (double)read_time_ns / 1000000000.0);
  printf("  Read pcap_next_ex: %.6f seconds\n", (double)pcap_read_ns / 1000000000.0);
  printf("  Read hash: %.6f seconds\n", (double)hash_ns / 1000000000.0);
  printf("  Read rss_lookup: %.6f seconds\n", (double)rss_lookup_ns / 1000000000.0);
  printf("  Read enqueue: %.6f seconds\n", (double)enqueue_ns / 1000000000.0);
  printf("  Read other: %.6f seconds\n", (double)read_other_merged_ns / 1000000000.0);
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
    printf("\nPer-Worker Statistics:\n");
    for (uint32_t i = 0; i < num_workers; i++) {
      double w_pps = (elapsed_sec > 0.0) ? (double)workers[i].packets_processed / elapsed_sec : 0.0;
      double w_gbps = (elapsed_sec > 0.0) ? ((double)workers[i].bytes_processed * 8.0) / elapsed_sec / 1e9 : 0.0;
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

    double base_pps = (elapsed_sec > 0.0) ? (double)workers[0].packets_processed / elapsed_sec : 0.0;
    double scaling = (num_workers > 0 && base_pps > 0.0) ? (pps / num_workers) / base_pps : 0.0;
    printf("\nScaling Efficiency: %.1f%%\n", scaling * 100.0);
  }

  printf("========================================\n");
}

static void usage(void) {
  printf("ndpiBenchmarkMark3 - nDPI benchmark with multi-dispatcher software RSS\n\n");
  printf("Usage: ndpiBenchmarkMark3 -i <pcap> [options]\n\n");
  printf("Required:\n");
  printf("  -i <file>          PCAP file to process\n\n");
  printf("Options:\n");
  printf("  -n <num>           Number of worker threads (default: 1)\n");
  printf("  -c <list>          Worker core list (e.g., 1,2,3,4; default: 0..n-1)\n");
  printf("  -d <list>          Dispatcher core list (e.g., 0,8; default: one unpinned dispatcher)\n");
  printf("  -p <file>          Protocol configuration file\n");
  printf("  -q                 Quiet mode\n");
  printf("  -h                 Show this help\n\n");
  printf("Example:\n");
  printf("  ndpiBenchmarkMark3 -i test.pcap -n 4 -c 2,3,4,5 -d 0,1\n\n");
}

static uint32_t *parse_dispatcher_core_list(const char *s, uint32_t *out_count) {
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

static benchmark_config_t parse_args(int argc, char **argv) {
  benchmark_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));

  cfg.num_workers = 1;
  cfg.num_dispatchers = 1;

  char *worker_core_list_str = NULL;
  char *dispatcher_core_list_str = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "i:n:c:d:p:qh")) != -1) {
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
    cfg.core_list = (uint32_t *)calloc(cfg.num_workers, sizeof(uint32_t));
    if (!cfg.core_list) {
      fprintf(stderr, "Error: out of memory\n");
      exit(1);
    }

    for (uint32_t i = 0; i < cfg.num_workers; i++) cfg.core_list[i] = i;

    char *saveptr = NULL;
    char *tok = strtok_r(worker_core_list_str, ",", &saveptr);
    uint32_t idx = 0;
    while (tok && idx < cfg.num_workers) {
      cfg.core_list[idx++] = (uint32_t)atoi(tok);
      tok = strtok_r(NULL, ",", &saveptr);
    }

    free(worker_core_list_str);
  }

  if (dispatcher_core_list_str) {
    cfg.dispatcher_core_list = parse_dispatcher_core_list(dispatcher_core_list_str,
                                                          &cfg.num_dispatchers);
    free(dispatcher_core_list_str);
    if (!cfg.dispatcher_core_list || cfg.num_dispatchers == 0) {
      fprintf(stderr, "Error: invalid dispatcher core list\n");
      exit(1);
    }
  }

  return cfg;
}

int main(int argc, char **argv) {
  benchmark_config_t cfg = parse_args(argc, argv);
  g_quiet_mode = cfg.quiet_mode;

  printf("========================================\n");
  printf("Standalone nDPI Benchmark Tool (mark3)\n");
  printf("========================================\n\n");

  printf("[1/4] Initializing nDPI...\n");
  struct ndpi_global_context *g_ctx = ndpi_global_init();
  if (!g_ctx) {
    fprintf(stderr, "Error: ndpi_global_init() failed\n");
    return 1;
  }

  printf("[2/4] Creating %u worker thread(s)...\n", cfg.num_workers);
  worker_context_t *workers = (worker_context_t *)calloc(cfg.num_workers, sizeof(worker_context_t));
  if (!workers) {
    fprintf(stderr, "Error: failed to allocate workers\n");
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    workers[i].worker_id = i;
    workers[i].cpu_core = cfg.core_list ? cfg.core_list[i] : i;
    workers[i].proto_file = cfg.proto_file;
    workers[i].g_ctx = g_ctx;

    workers[i].queue = packet_queue_create(QUEUE_CAPACITY);
    if (!workers[i].queue) {
      fprintf(stderr, "Error: failed to create packet queue for worker %u\n", i);
      for (uint32_t j = 0; j < i; j++) cleanup_worker(&workers[j]);
      free(workers);
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
      ndpi_global_deinit(g_ctx);
      free(cfg.core_list);
      free(cfg.dispatcher_core_list);
      return 1;
    }
#endif
  }

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    init_worker_ndpi(&workers[i]);
  }

  rss_table_t *rss = rss_table_create(RSS_TABLE_INIT_CAP);
  if (!rss) {
    fprintf(stderr, "Error: failed to create flow->worker map\n");
    for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);
    free(workers);
    ndpi_global_deinit(g_ctx);
    free(cfg.core_list);
    free(cfg.dispatcher_core_list);
    return 1;
  }

  printf("[3/4] Starting streaming benchmark...\n");
  printf("      PCAP: %s\n", cfg.pcap_file);
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
      .workers = workers,
      .num_workers = cfg.num_workers,
      .num_dispatchers = cfg.num_dispatchers,
      .dispatcher_cores = cfg.dispatcher_core_list,
      .rss = rss,
      .packets = NULL,
      .packet_count = 0,
      .next_packet_idx = 0,
      .read_time_ns = 0,
      .pcap_read_ns = 0,
      .normalize_ns = 0,
      .hash_ns = 0,
      .rss_lookup_ns = 0,
      .enqueue_ns = 0,
      .read_other_ns = 0,
  };

  pthread_t reader;

  uint64_t wall_start_ns = 0, wall_end_ns = 0;
  uint64_t cycles_start = rdtsc();
  wall_start_ns = get_time_ns();

  if (pthread_create(&reader, NULL, reader_thread_entry, &reader_ctx) != 0) {
    fprintf(stderr, "Error: pthread_create(dispatcher_controller) failed\n");
    exit(1);
  }

  pthread_join(reader, NULL);
  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    pthread_join(workers[i].thread, NULL);
  }

  uint64_t cycles_end = rdtsc();
  wall_end_ns = get_time_ns();
  double elapsed = (wall_end_ns > wall_start_ns)
                       ? (double)(wall_end_ns - wall_start_ns) / 1000000000.0
                       : 0.0;

  printf("[4/4] Done.\n");
  print_benchmark_results(workers, cfg.num_workers, cycles_end - cycles_start, elapsed,
                          reader_ctx.read_time_ns,
                          reader_ctx.pcap_read_ns,
                          reader_ctx.normalize_ns,
                          reader_ctx.hash_ns,
                          reader_ctx.rss_lookup_ns,
                          reader_ctx.enqueue_ns,
                          reader_ctx.read_other_ns);

  rss_table_destroy(rss);
  for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);

  free(workers);
  ndpi_global_deinit(g_ctx);
  free(cfg.core_list);
  free(cfg.dispatcher_core_list);

  return 0;
}
