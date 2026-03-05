#include "benchmark_internal.h"

/* 汇总 reader + worker 指标并输出最终结果。
 *
 * 注意这里有两类统计口径：
 * 1) 可累加项（包数、字节、parse/flow/ndpi 分段耗时）按 worker 求和
 * 2) 墙钟主导项（process wall time）取“最慢 worker”的处理时长
 *    因为并行 worker 是并发执行，总时延由慢者决定。
 */
void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                             uint64_t total_cycles, double elapsed_sec,
                             uint64_t read_time_us,
                             uint64_t pcap_read_us,
                             uint64_t enqueue_us,
                             uint64_t enqueue_hash_us,
                             uint64_t enqueue_queue_wait_us,
                             uint64_t enqueue_queue_write_us) {
  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t total_flows = 0;
  uint64_t total_flows_with_proto = 0;
  uint64_t total_process_us = 0;
  uint64_t total_parse_us = 0;
  uint64_t total_flow_us = 0;
  uint64_t total_ndpi_us = 0;
  uint64_t total_other_us = 0;
  uint64_t per_core_process_us[PROCESS_TIME_CORE_SLOTS] = {0};

  /* 聚合所有 worker 的包量、字节、flow 与阶段耗时。 */
  for (uint32_t i = 0; i < num_workers; i++) {
    total_packets += workers[i].packets_processed;
    total_bytes += workers[i].bytes_processed;
    total_flows += workers[i].flows_created_total;
    total_flows_with_proto += workers[i].flows_with_protocol_total;
    /* worker 间并行，处理阶段总耗时近似由最慢 worker 决定。 */
    if (workers[i].processing_time_us > total_process_us) {
      total_process_us = workers[i].processing_time_us;
    }
    if (workers[i].cpu_core < PROCESS_TIME_CORE_SLOTS) {
      per_core_process_us[workers[i].cpu_core] += workers[i].processing_time_us;
    }
    total_parse_us += workers[i].parse_time_us;
    total_flow_us += workers[i].flow_time_us;
    total_ndpi_us += workers[i].ndpi_time_us;
    total_other_us += workers[i].other_time_us;
  }

  /* 全局吞吐、带宽与 CPP（cycles per packet）。 */
  double pps = (elapsed_sec > 0.0) ? (double)total_packets / elapsed_sec : 0.0;
  double gbps = (elapsed_sec > 0.0) ? ((double)total_bytes * 8.0) / elapsed_sec / 1e9 : 0.0;
  double cycles_per_packet = (total_packets > 0) ? (double)total_cycles / (double)total_packets : 0.0;

  printf("\n========================================\n");
  printf("Benchmark Results\n");
  printf("========================================\n");
  printf("Elapsed Time: %.3f seconds\n", elapsed_sec);
  printf("Read Time: %.3f seconds\n", (double)read_time_us / 1000000.0);
  printf("  Read pcap_next_ex: %.3f seconds\n", (double)pcap_read_us / 1000000.0);
  printf("  Read enqueue: %.3f seconds\n", (double)enqueue_us / 1000000.0);
  printf("    Read enqueue hash/rss: %.3f seconds\n", (double)enqueue_hash_us / 1000000.0);
  printf("    Read enqueue queue_wait: %.3f seconds\n", (double)enqueue_queue_wait_us / 1000000.0);
  printf("    Read enqueue queue_write: %.3f seconds\n", (double)enqueue_queue_write_us / 1000000.0);
  printf("Process Time: %.3f seconds\n", (double)total_process_us / 1000000.0);
  printf("  Process parse: %.3f seconds\n", (double)total_parse_us / 1000000.0);
  printf("  Process flow: %.3f seconds\n", (double)total_flow_us / 1000000.0);
  printf("  Process nDPI: %.3f seconds\n", (double)total_ndpi_us / 1000000.0);
  printf("  Process other: %.3f seconds\n", (double)total_other_us / 1000000.0);
  printf("Per-Core Process Time (sec): ");
  for (uint32_t c = 0; c < PROCESS_TIME_CORE_SLOTS; c++) {
    if (c > 0) printf(",");
    printf("%.6f", (double)per_core_process_us[c] / 1000000.0);
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

  /* 多 worker 时输出每个 worker 的细分统计与缩放效率。
   * scaling 这里是“平均每 worker 吞吐”相对 worker0 的比值，
   * 用来快速观察扩展效率（不是严格线性扩展模型）。
   */
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
             (double)workers[i].processing_time_us / 1000000.0,
             (double)workers[i].parse_time_us / 1000000.0,
             (double)workers[i].flow_time_us / 1000000.0,
             (double)workers[i].ndpi_time_us / 1000000.0);
    }

    double base_pps = (elapsed_sec > 0.0) ? (double)workers[0].packets_processed / elapsed_sec : 0.0;
    double scaling = (num_workers > 0 && base_pps > 0.0) ? (pps / num_workers) / base_pps : 0.0;
    printf("\nScaling Efficiency: %.1f%%\n", scaling * 100.0);
  }

  printf("========================================\n");
}

/* CLI 帮助文本。 */
static void usage(void) {
  printf("ndpiBenchmark - Standalone high-performance nDPI throughput benchmark\n\n");
  printf("Usage: ndpiBenchmark -i <pcap> [options]\n\n");
  printf("Required:\n");
  printf("  -i <file>          PCAP file to process\n\n");
  printf("Options:\n");
  printf("  -n <num>           Number of worker threads (default: 1)\n");
  printf("  -c <list>          CPU core list (e.g., 0,1,2,3; default: 0..n-1)\n");
  printf("  -r <core>          Reader thread CPU core (default: 32)\n");
  printf("  -p <file>          Protocol configuration file\n");
  printf("  -q                 Quiet mode\n");
  printf("  -h                 Show this help\n\n");
  printf("Example:\n");
  printf("  ndpiBenchmark -i test.pcap -n 4 -c 1,2,3,4 -r 0\n\n");
}

/* 参数解析：
 * - 必选: pcap 文件
 * - 可选: worker 数、绑核、reader 核、协议文件、quiet 模式
 *
 * 约定：
 * - 未传 -c 时，worker 默认绑定到 0..n-1
 * - 传了 -c 但数量不足 n 时，剩余部分保留默认值
 */
static benchmark_config_t parse_args(int argc, char **argv) {
  benchmark_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));

  cfg.num_workers = 1;
  cfg.reader_core = 32;

  char *core_list_str = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "i:n:c:r:p:qh")) != -1) {
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
        core_list_str = strdup(optarg);
        break;
      case 'r':
        cfg.reader_core = (uint32_t)atoi(optarg);
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

  /* 如果用户显式给了 core list，则按传入顺序覆盖默认 0..n-1。 */
  if (core_list_str) {
    cfg.core_list = (uint32_t *)calloc(cfg.num_workers, sizeof(uint32_t));
    if (!cfg.core_list) {
      fprintf(stderr, "Error: out of memory\n");
      exit(1);
    }

    for (uint32_t i = 0; i < cfg.num_workers; i++) cfg.core_list[i] = i;

    char *saveptr = NULL;
    char *tok = strtok_r(core_list_str, ",", &saveptr);
    uint32_t idx = 0;
    while (tok && idx < cfg.num_workers) {
      cfg.core_list[idx++] = (uint32_t)atoi(tok);
      tok = strtok_r(NULL, ",", &saveptr);
    }

    free(core_list_str);
  }

  return cfg;
}

int main(int argc, char **argv) {
  /* [阶段 0] 解析参数并设置全局 quiet 开关。 */
  benchmark_config_t cfg = parse_args(argc, argv);
  g_quiet_mode = cfg.quiet_mode;

  printf("========================================\n");
  printf("Standalone nDPI Benchmark Tool\n");
#ifdef NDPI_BENCHMARK_MEMREADER
  printf("Mode: Memory-Buffered PCAP Reader\n");
#endif
  printf("========================================\n\n");

  /* [阶段 1] 初始化 nDPI 全局上下文。
   * g_ctx 是进程级共享对象，后续每个 worker 的 ndpi module 都基于它创建。
   */
  printf("[1/4] Initializing nDPI...\n");
  struct ndpi_global_context *g_ctx = ndpi_global_init();
  if (!g_ctx) {
    fprintf(stderr, "Error: ndpi_global_init() failed\n");
    return 1;
  }

  /* [阶段 2] 初始化 worker 上下文、队列、可选 classified 表。
   * 这里仅构造资源，不启动线程，便于失败时统一回滚。
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
    workers[i].cpu_core = cfg.core_list ? cfg.core_list[i] : i;
    workers[i].proto_file = cfg.proto_file;
    workers[i].g_ctx = g_ctx;

    workers[i].queue = packet_queue_create(QUEUE_CAPACITY);
    if (!workers[i].queue) {
      fprintf(stderr, "Error: failed to create packet queue for worker %u\n", i);
      for (uint32_t j = 0; j < i; j++) cleanup_worker(&workers[j]);
      free(workers);
      ndpi_global_deinit(g_ctx);
      return 1;
    }

#ifdef NDPI_BENCHMARK_CLASSIFIED
    workers[i].classified = classified_table_create(1u << 16);
    if (!workers[i].classified) {
      fprintf(stderr, "Error: failed to create classified table for worker %u\n", i);
      for (uint32_t j = 0; j <= i; j++) cleanup_worker(&workers[j]);
      free(workers);
      ndpi_global_deinit(g_ctx);
      return 1;
    }
#endif
  }

  /* 每个 worker 单独初始化 nDPI module + flow table。 */
  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    init_worker_ndpi(&workers[i]);
  }

  /* reader 侧共享 RSS 表：维护 flow -> worker 的粘性映射。
   * 该表只在 reader 线程访问，不需要额外锁。
   */
  rss_table_t *rss = rss_table_create(RSS_TABLE_INIT_CAP);
  if (!rss) {
    fprintf(stderr, "Error: failed to create RSS table\n");
    for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);
    free(workers);
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  /* [阶段 3] 拉起 worker + reader，并开始计时。 */
  printf("[3/4] Starting streaming benchmark...\n");
  printf("      PCAP: %s\n", cfg.pcap_file);
  printf("\n----------------------------------------\n");
  printf("Protocol Detection Samples (first %lu flows):\n", (unsigned long)g_sample_limit);
  printf("----------------------------------------\n\n");

  /* 先启动 worker 消费循环，再启动 reader 生产包。
   * 这样 reader 一投递就有人消费，避免启动瞬间队列堆积。
   */
  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    if (pthread_create(&workers[i].thread, NULL, worker_thread_entry, &workers[i]) != 0) {
      fprintf(stderr, "Error: pthread_create(worker=%u) failed\n", i);
      exit(1);
    }
  }

  /* reader 上下文携带输入路径、worker 列表与统计计数器。 */
  reader_context_t reader_ctx = {
      .pcap_file = cfg.pcap_file,
      .workers = workers,
      .num_workers = cfg.num_workers,
      .reader_core = cfg.reader_core,
      .rss = rss,
      .read_time_us = 0,
      .pcap_read_us = 0,
      .enqueue_us = 0,
      .enqueue_hash_us = 0,
      .enqueue_queue_wait_us = 0,
      .enqueue_queue_write_us = 0,
  };
  pthread_t reader;

  struct timeval tv_start, tv_end;
  uint64_t cycles_start = rdtsc();
  gettimeofday(&tv_start, NULL);

  if (pthread_create(&reader, NULL, reader_thread_entry, &reader_ctx) != 0) {
    fprintf(stderr, "Error: pthread_create(reader) failed\n");
    exit(1);
  }

  /* reader 结束后，等待所有 worker 把队列中的包消费完。
   * reader 结束只代表“不会再写入”，不代表队列已清空。
   */
  pthread_join(reader, NULL);
  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    pthread_join(workers[i].thread, NULL);
  }

  uint64_t cycles_end = rdtsc();
  gettimeofday(&tv_end, NULL);

  double elapsed = (tv_end.tv_sec - tv_start.tv_sec) +
                   (tv_end.tv_usec - tv_start.tv_usec) / 1000000.0;

  /* [阶段 4] 输出汇总结果并做完整资源回收。 */
  printf("[4/4] Done.\n");
  print_benchmark_results(workers, cfg.num_workers, cycles_end - cycles_start, elapsed,
                          reader_ctx.read_time_us,
                          reader_ctx.pcap_read_us,
                          reader_ctx.enqueue_us,
                          reader_ctx.enqueue_hash_us,
                          reader_ctx.enqueue_queue_wait_us,
                          reader_ctx.enqueue_queue_write_us);

  rss_table_destroy(rss);
  for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);

  free(workers);
  ndpi_global_deinit(g_ctx);
  free(cfg.core_list);

  return 0;
}
