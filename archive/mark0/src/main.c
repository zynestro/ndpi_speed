#include "ndpi_benchmark.h"
#include "flow_table.h"
#include "packet_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <unistd.h>

/*
 * This file re-implements the small subset of "workflow" logic needed by the
 * original ndpiBenchmark, but without depending on nDPI example/reader_util.
 */

static pthread_mutex_t g_print_mutex = PTHREAD_MUTEX_INITIALIZER;
static uint64_t g_samples_printed = 0;
static const uint64_t g_sample_limit = 10;
static bool g_quiet_mode = false;

/* ------------------------- Helpers ------------------------- */

static inline double elapsed_sec(const struct timeval *start, const struct timeval *end) {
  return (double)(end->tv_sec - start->tv_sec) +
         (double)(end->tv_usec - start->tv_usec) / 1000000.0;
}

static void endpoint_to_string(const endpoint_t *ep, char *buf, size_t buflen) {
  if (!ep || !buf || buflen == 0) return;

  char ip[INET6_ADDRSTRLEN] = {0};
  if (ep->ip_version == 4) {
    inet_ntop(AF_INET, ep->addr, ip, sizeof(ip));
  } else {
    inet_ntop(AF_INET6, ep->addr, ip, sizeof(ip));
  }

  snprintf(buf, buflen, "%s:%u", ip, (unsigned)ep->port);
}

static void maybe_print_flow_sample(worker_context_t *w, const bench_flow_t *f) {
  if (g_quiet_mode) return;

  pthread_mutex_lock(&g_print_mutex);
  if (g_samples_printed >= g_sample_limit) {
    pthread_mutex_unlock(&g_print_mutex);
    return;
  }

  uint16_t master = ndpi_get_flow_masterprotocol(f->ndpi_flow);
  uint16_t app = ndpi_get_flow_appprotocol(f->ndpi_flow);

  ndpi_master_app_protocol proto = {0};
  proto.master_protocol = master;
  proto.app_protocol = app;

  char proto_name[64];
  memset(proto_name, 0, sizeof(proto_name));
  ndpi_protocol2name(w->ndpi, proto, proto_name, (u_int)sizeof(proto_name));

  char c[128], s[128];
  endpoint_to_string(&f->client, c, sizeof(c));
  endpoint_to_string(&f->server, s, sizeof(s));

  printf("Flow sample #%lu\n", (unsigned long)(g_samples_printed + 1));
  printf("  Protocol: %s\n", proto_name[0] ? proto_name : "(unknown)");
  printf("  5-tuple:  %s  <->  %s\n", c, s);
  printf("  Packets:  %lu (c->s: %lu, s->c: %lu)\n",
         (unsigned long)(f->c2s_packets + f->s2c_packets),
         (unsigned long)f->c2s_packets,
         (unsigned long)f->s2c_packets);
  printf("  Bytes:    %lu (c->s: %lu, s->c: %lu)\n\n",
         (unsigned long)(f->c2s_bytes + f->s2c_bytes),
         (unsigned long)f->c2s_bytes,
         (unsigned long)f->s2c_bytes);

  g_samples_printed++;
  pthread_mutex_unlock(&g_print_mutex);
}

static void free_flow_cb(bench_flow_t *flow, void *user) {
  worker_context_t *w = (worker_context_t *)user;
  if (!flow) return;

  /* Final accounting: if it became detectable but we never counted it (rare). */
  if (!flow->protocol_counted && flow->ndpi_flow) {
    uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
    if (app != NDPI_PROTOCOL_UNKNOWN) {
      flow->protocol_counted = true;
      w->flows_with_protocol_total++;
      maybe_print_flow_sample(w, flow);
    }
  }

  if (flow->ndpi_flow) {
    ndpi_free_flow(flow->ndpi_flow);
    flow->ndpi_flow = NULL;
  }
  free(flow);
}

#ifdef __linux__
static void set_thread_affinity(uint32_t core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);
  int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
  if (rc != 0 && !g_quiet_mode) {
    fprintf(stderr, "Warning: pthread_setaffinity_np(core=%u) failed: %s\n", core, strerror(rc));
  }
}
#else
static void set_thread_affinity(uint32_t core) {
  (void)core;
}
#endif

/* ------------------------- nDPI init/cleanup ------------------------- */

void init_worker_ndpi(worker_context_t *worker) {
  if (!worker) return;

  worker->ndpi = ndpi_init_detection_module(worker->g_ctx);
  if (!worker->ndpi) {
    fprintf(stderr, "Error: ndpi_init_detection_module() failed for worker %u\n", worker->worker_id);
    exit(1);
  }

  /* Keep behavior similar to the original benchmark. */
  (void)ndpi_set_config(worker->ndpi, NULL, "tcp_ack_payload_heuristic", "enable");

  if (worker->proto_file && worker->proto_file[0]) {
    (void)ndpi_load_protocols_file(worker->ndpi, worker->proto_file);
  }

  ndpi_finalize_initialization(worker->ndpi);

  /* Initial flow-table capacity heuristic (will auto-grow). */
  size_t init_cap = (worker->num_packets > 0) ? (size_t)worker->num_packets / 4 : 16384;
  if (init_cap < 1024) init_cap = 1024;
  worker->flows = flow_table_create(init_cap);
  if (!worker->flows) {
    fprintf(stderr, "Error: flow_table_create() failed\n");
    exit(1);
  }
}

void cleanup_worker(worker_context_t *worker) {
  if (!worker) return;

  if (worker->flows) {
    flow_table_destroy(worker->flows, free_flow_cb, worker);
    worker->flows = NULL;
  }

  if (worker->ndpi) {
    ndpi_exit_detection_module(worker->ndpi);
    worker->ndpi = NULL;
  }

  free(worker->packet_indices);
  worker->packet_indices = NULL;
}

/* ------------------------- Packet processing ------------------------- */

static inline void set_ndpi_flow_tuple(struct ndpi_flow_struct *flow,
                                      const parsed_packet_t *p,
                                      const endpoint_t *client,
                                      const endpoint_t *server) {
  /* Best-effort. nDPI can parse the tuple from the packet, but filling these
   * fields helps some heuristics and mirrors common integrations.
   */
  flow->l4_proto = p->l4_proto;
  flow->is_ipv6 = (p->ip_version == 6);
  flow->c_port = client->port;
  flow->s_port = server->port;

  if (p->ip_version == 4) {
    memcpy(&flow->c_address, client->addr, 4);
    memcpy(&flow->s_address, server->addr, 4);
  } else {
    memcpy(&flow->c_address, client->addr, 16);
    memcpy(&flow->s_address, server->addr, 16);
  }
}

static inline void worker_process_packet(worker_context_t *w, mem_packet_t *pkt) {
  parsed_packet_t pp;
  if (parse_ethernet_frame(pkt->data, pkt->caplen, &pp) != PARSE_OK) return;

  flow_key_t key;
  endpoint_t src_ep, dst_ep;
  flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);

  uint64_t h = flow_key_hash(&key);
  bool is_new = false;
  bench_flow_t *flow = flow_table_get_or_create(w->flows, &key, h, NULL, NULL, &is_new);
  if (!flow) return;

  if (is_new) {
    w->flows_created_total++;

    flow->client = src_ep;
    flow->server = dst_ep;

    flow->ndpi_flow = (struct ndpi_flow_struct *)ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
    if (!flow->ndpi_flow) {
      fprintf(stderr, "Error: ndpi_calloc(flow) failed\n");
      exit(1);
    }

    set_ndpi_flow_tuple(flow->ndpi_flow, &pp, &flow->client, &flow->server);
  }

  /* Direction relative to (client,server) chosen by first packet */
  uint8_t dir = endpoint_equal(&src_ep, &flow->client) ? 0 : 1;

  /* Counters */
  if (dir == 0) {
    flow->c2s_packets++;
    flow->c2s_bytes += pkt->wirelen;
  } else {
    flow->s2c_packets++;
    flow->s2c_bytes += pkt->wirelen;
  }

  uint64_t ts_ms = pkt->timestamp_us / 1000ULL;
  flow->last_seen_ms = ts_ms;

  struct ndpi_flow_input_info in = {0};
  in.in_pkt_dir = dir;
  in.seen_flow_beginning = (flow->seen_packets == 0);

  (void)ndpi_detection_process_packet(w->ndpi, flow->ndpi_flow,
                                     pp.l3, pp.l3_len,
                                     ts_ms, &in);

  flow->seen_packets++;

  /* Verification: count a flow as soon as app protocol becomes known. */
  if (!flow->protocol_counted) {
    uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
    if (app != NDPI_PROTOCOL_UNKNOWN) {
      flow->protocol_counted = true;
      w->flows_with_protocol_total++;
      maybe_print_flow_sample(w, flow);
    }
  }

  w->packets_processed++;
  w->bytes_processed += pkt->wirelen;
}

/* ------------------------- Worker thread ------------------------- */

void *worker_thread(void *arg) {
  worker_context_t *w = (worker_context_t *)arg;

  set_thread_affinity(w->cpu_core);

  w->cycles_start = rdtsc();

  for (uint32_t loop = 0; loop < w->num_loops; loop++) {
    /* If we're generating new tuples each loop, clear old flows to avoid
     * unbounded table growth (mirrors the intent of the original "timestamp
     * jitter" option).
     */
    if (w->flow_randomization && w->timestamp_jitter && loop > 0) {
      flow_table_clear(w->flows, free_flow_cb, w);
    }

    for (uint32_t i = 0; i < w->num_packets; i++) {
      /* prefetch future packet pointers */
      if (i + PREFETCH_OFFSET < w->num_packets) {
        __builtin_prefetch(&w->packet_indices[i + PREFETCH_OFFSET], 0, 1);
      }

      uint32_t pkt_idx = w->packet_indices[i];
      mem_packet_t *pkt = w->pool->packets[pkt_idx];

      if (w->flow_randomization) randomize_packet_tuple(pkt, loop, w->worker_id);
      if (w->timestamp_jitter) adjust_packet_timestamp(pkt, loop);

      worker_process_packet(w, pkt);
    }
  }

  w->cycles_end = rdtsc();
  return NULL;
}

/* ------------------------- Reporting ------------------------- */

void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                             uint64_t total_cycles, double elapsed_sec) {
  uint64_t total_packets = 0;
  uint64_t total_bytes = 0;
  uint64_t total_flows = 0;
  uint64_t total_flows_with_proto = 0;

  for (uint32_t i = 0; i < num_workers; i++) {
    total_packets += workers[i].packets_processed;
    total_bytes += workers[i].bytes_processed;
    total_flows += workers[i].flows_created_total;
    total_flows_with_proto += workers[i].flows_with_protocol_total;
  }

  double pps = (elapsed_sec > 0.0) ? (double)total_packets / elapsed_sec : 0.0;
  double gbps = (elapsed_sec > 0.0) ? ((double)total_bytes * 8.0) / elapsed_sec / 1e9 : 0.0;

  printf("\n========================================\n");
  printf("Benchmark Results\n");
  printf("========================================\n");
  printf("Elapsed Time: %.3f seconds\n", elapsed_sec);
  printf("Total Packets: %lu\n", (unsigned long)total_packets);
  printf("Total Bytes: %.2f MB\n", (double)total_bytes / 1024.0 / 1024.0);
  printf("\nPerformance:\n");
  printf("  Throughput: %.2f Mpps\n", pps / 1e6);
  printf("  Bandwidth: %.2f Gbps\n", gbps);
  printf("  Cycles per packet: %.2f\n", (double)total_cycles / (double)total_packets);

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
      printf("  Worker %2u [Core %2u]: %.2f Mpps, %.2f Gbps, %lu flows\n",
             i, workers[i].cpu_core,
             w_pps / 1e6, w_gbps,
             (unsigned long)workers[i].flows_created_total);
    }

    double base_pps = (elapsed_sec > 0.0) ? (double)workers[0].packets_processed / elapsed_sec : 0.0;
    double scaling = (num_workers > 0 && base_pps > 0.0) ? (pps / num_workers) / base_pps : 0.0;
    printf("\nScaling Efficiency: %.1f%%\n", scaling * 100.0);
  }

  printf("========================================\n");
}

/* ------------------------- CLI ------------------------- */

static void usage(void) {
  printf("ndpiBenchmark - Standalone high-performance nDPI throughput benchmark\n\n");
  printf("Usage: ndpiBenchmark -i <pcap> [options]\n\n");
  printf("Required:\n");
  printf("  -i <file>          PCAP file to process\n\n");
  printf("Options:\n");
  printf("  -n <num>           Number of worker threads (default: 1)\n");
  printf("  -l <num>           Number of loops (default: 1)\n");
  printf("  -c <list>          CPU core list (e.g., 0,1,2,3)\n");
  printf("  -r                 Enable flow randomization (avoid cache cheating)\n");
  printf("  -t                 Enable timestamp jitter (avoid flow pollution)\n");
  printf("  -D <num>           Demo: process <num> packets of a single flow\n");
  printf("  -p <file>          Protocol configuration file\n");
  printf("  -q                 Quiet mode\n");
  printf("  -h                 Show this help\n\n");
  printf("Example:\n");
  printf("  ndpiBenchmark -i test.pcap -n 4 -l 1000 -r -t\n\n");
}

static benchmark_config_t parse_args(int argc, char **argv) {
  benchmark_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));

  cfg.num_workers = 1;
  cfg.num_loops = 1;

  /* We parse core list into a temp string first, because -c may appear before -n. */
  char *core_list_str = NULL;

  int opt;
  while ((opt = getopt(argc, argv, "i:n:l:c:p:rtqhd:D:")) != -1) {
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
      case 'l':
        cfg.num_loops = (uint32_t)atoi(optarg);
        if (cfg.num_loops < 1) {
          fprintf(stderr, "Error: invalid number of loops\n");
          exit(1);
        }
        break;
      case 'c':
        core_list_str = strdup(optarg);
        break;
      case 'r':
        cfg.flow_randomization = true;
        break;
      case 't':
        cfg.timestamp_jitter = true;
        break;
      case 'D':
        cfg.demo_packets = (uint32_t)atoi(optarg);
        if (cfg.demo_packets < 1) {
          fprintf(stderr, "Error: invalid demo packet count\n");
          exit(1);
        }
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

  if (core_list_str) {
    cfg.core_list = (uint32_t *)calloc(cfg.num_workers, sizeof(uint32_t));
    if (!cfg.core_list) {
      fprintf(stderr, "Error: out of memory\n");
      exit(1);
    }

    /* Default to sequential cores if list is shorter. */
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

static void print_demo_flow_state(worker_context_t *w,
                                  const bench_flow_t *flow,
                                  const parsed_packet_t *pp,
                                  uint32_t pkt_idx,
                                  uint8_t dir,
                                  uint64_t ts_ms) {
  uint16_t master = ndpi_get_flow_masterprotocol(flow->ndpi_flow);
  uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
  ndpi_master_app_protocol proto = {0};
  proto.master_protocol = master;
  proto.app_protocol = app;

  char proto_name[64] = {0};
  ndpi_protocol2name(w->ndpi, proto, proto_name, (u_int)sizeof(proto_name));

  printf("[demo] pkt=%u dir=%s ts_ms=%lu l4=%u len=%u\n",
         pkt_idx,
         (dir == 0) ? "c2s" : "s2c",
         (unsigned long)ts_ms,
         pp->l4_proto,
         (unsigned)pp->l3_len);
  printf("       proto=%s app=%u master=%u conf=%u\n",
         proto_name[0] ? proto_name : "(unknown)",
         app, master,
         (unsigned)flow->ndpi_flow->confidence);
  printf("       processed_pkts=%u packet_counter=%u all_packets=%u\n",
         (unsigned)flow->ndpi_flow->num_processed_pkts,
         (unsigned)flow->ndpi_flow->packet_counter,
         (unsigned)flow->ndpi_flow->all_packets_counter);
  if (flow->ndpi_flow->host_server_name[0]) {
    printf("       host=%s\n", flow->ndpi_flow->host_server_name);
  }
}

static int run_demo_single_flow(packet_pool_t *pool, struct ndpi_global_context *g_ctx,
                                const benchmark_config_t *cfg) {
  if (!pool || !g_ctx || !cfg) return 1;

  worker_context_t w;
  memset(&w, 0, sizeof(w));
  w.worker_id = 0;
  w.cpu_core = 0;
  w.pool = pool;
  w.num_loops = 1;
  w.flow_randomization = false;
  w.timestamp_jitter = false;
  w.proto_file = cfg->proto_file;
  w.g_ctx = g_ctx;
  w.flows = flow_table_create(1024);
  if (!w.flows) {
    fprintf(stderr, "Error: failed to create flow table for demo\n");
    return 1;
  }

  init_worker_ndpi(&w);

  parsed_packet_t first_pp;
  flow_key_t target_key;
  bool have_key = false;

  for (uint32_t i = 0; i < pool->num_packets; i++) {
    mem_packet_t *pkt = pool->packets[i];
    if (parse_ethernet_frame(pkt->data, pkt->caplen, &first_pp) != PARSE_OK) continue;
    endpoint_t tmp_src, tmp_dst;
    flow_key_from_packet(&first_pp, &target_key, &tmp_src, &tmp_dst);
    have_key = true;
    break;
  }

  if (!have_key) {
    fprintf(stderr, "Error: no parsable packets for demo\n");
    flow_table_destroy(w.flows, free_flow_cb, &w);
    cleanup_worker(&w);
    return 1;
  }

  printf("\n[demo] Running single-flow demo (packets=%u)\n", cfg->demo_packets);

  uint32_t matched = 0;
  bench_flow_t *last_flow = NULL;
  for (uint32_t i = 0; i < pool->num_packets && matched < cfg->demo_packets; i++) {
    mem_packet_t *pkt = pool->packets[i];
    parsed_packet_t pp;
    if (parse_ethernet_frame(pkt->data, pkt->caplen, &pp) != PARSE_OK) continue;

    flow_key_t key;
    endpoint_t src_ep, dst_ep;
    flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);
    if (memcmp(&key, &target_key, sizeof(key)) != 0) continue;

    uint64_t h = flow_key_hash(&key);
    bool is_new = false;
    bench_flow_t *flow = flow_table_get_or_create(w.flows, &key, h, NULL, NULL, &is_new);
    if (!flow) continue;

    if (is_new) {
      flow->client = src_ep;
      flow->server = dst_ep;
      flow->ndpi_flow = (struct ndpi_flow_struct *)ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
      if (!flow->ndpi_flow) {
        fprintf(stderr, "Error: ndpi_calloc(flow) failed\n");
        exit(1);
      }
      set_ndpi_flow_tuple(flow->ndpi_flow, &pp, &flow->client, &flow->server);
    }

    uint8_t dir = endpoint_equal(&src_ep, &flow->client) ? 0 : 1;
    if (dir == 0) {
      flow->c2s_packets++;
      flow->c2s_bytes += pkt->wirelen;
    } else {
      flow->s2c_packets++;
      flow->s2c_bytes += pkt->wirelen;
    }

    uint64_t ts_ms = pkt->timestamp_us / 1000ULL;
    flow->last_seen_ms = ts_ms;

    struct ndpi_flow_input_info in = {0};
    in.in_pkt_dir = dir;
    in.seen_flow_beginning = (flow->seen_packets == 0);

    (void)ndpi_detection_process_packet(w.ndpi, flow->ndpi_flow,
                                        pp.l3, pp.l3_len,
                                        ts_ms, &in);

    flow->seen_packets++;
    print_demo_flow_state(&w, flow, &pp, matched + 1, dir, ts_ms);
    matched++;
    last_flow = flow;
  }

  if (matched == 0) {
    printf("[demo] No packets matched the selected flow.\n");
  } else if (last_flow && last_flow->ndpi_flow) {
    uint16_t app = ndpi_get_flow_appprotocol(last_flow->ndpi_flow);
    printf("[demo] Final app protocol id: %u\n", app);
  }

  flow_table_destroy(w.flows, free_flow_cb, &w);
  cleanup_worker(&w);
  return 0;
}

/* ------------------------- main ------------------------- */

int main(int argc, char **argv) {
  benchmark_config_t cfg = parse_args(argc, argv);
  g_quiet_mode = cfg.quiet_mode;

  struct timeval tv_total_start, tv_total_end;
  struct timeval tv_load_start, tv_load_end;
  struct timeval tv_assign_start, tv_assign_end;
  struct timeval tv_process_start, tv_process_end;
  gettimeofday(&tv_total_start, NULL);

  printf("========================================\n");
  printf("Standalone nDPI Benchmark Tool\n");
  printf("========================================\n\n");

  printf("[1/5] Loading PCAP into memory...\n");
  gettimeofday(&tv_load_start, NULL);
  packet_pool_t *pool = load_pcap_to_memory(cfg.pcap_file);
  gettimeofday(&tv_load_end, NULL);
  if (!pool) {
    fprintf(stderr, "Error: failed to load PCAP file\n");
    return 1;
  }
  printf("      Loaded %u packets (%.2f MB)\n", pool->num_packets,
         (double)pool->total_bytes / 1024.0 / 1024.0);

  printf("[2/5] Initializing nDPI...\n");
  struct ndpi_global_context *g_ctx = ndpi_global_init();
  if (!g_ctx) {
    fprintf(stderr, "Error: ndpi_global_init() failed\n");
    free_packet_pool(pool);
    return 1;
  }

  if (cfg.demo_packets > 0) {
    int rc = run_demo_single_flow(pool, g_ctx, &cfg);
    ndpi_global_deinit(g_ctx);
    free_packet_pool(pool);
    free(cfg.core_list);
    return rc;
  }

  printf("[3/5] Creating %u worker thread(s)...\n", cfg.num_workers);
  worker_context_t *workers = (worker_context_t *)calloc(cfg.num_workers, sizeof(worker_context_t));
  if (!workers) {
    fprintf(stderr, "Error: failed to allocate workers\n");
    free_packet_pool(pool);
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    workers[i].worker_id = i;
    workers[i].cpu_core = cfg.core_list ? cfg.core_list[i] : i;
    workers[i].pool = pool;
    workers[i].num_loops = cfg.num_loops;
    workers[i].flow_randomization = cfg.flow_randomization;
    workers[i].timestamp_jitter = cfg.timestamp_jitter;
    workers[i].proto_file = cfg.proto_file;
    workers[i].g_ctx = g_ctx;
  }

  printf("[4/5] Distributing packets to workers (by flow hash)...\n");
  gettimeofday(&tv_assign_start, NULL);
  assign_packets_to_workers(pool, workers, cfg.num_workers);
  gettimeofday(&tv_assign_end, NULL);

  uint32_t min_pkts = workers[0].num_packets;
  uint32_t max_pkts = workers[0].num_packets;
  for (uint32_t i = 1; i < cfg.num_workers; i++) {
    if (workers[i].num_packets < min_pkts) min_pkts = workers[i].num_packets;
    if (workers[i].num_packets > max_pkts) max_pkts = workers[i].num_packets;
  }
  printf("      Packets per worker: min=%u, max=%u (%.1f%% variance)\n",
         min_pkts, max_pkts, min_pkts ? (double)(max_pkts - min_pkts) * 100.0 / (double)min_pkts : 0.0);

  /* Initialize per-worker nDPI modules and flow tables. IMPORTANT: nDPI docs
   * recommend not calling ndpi_init_detection_module() in parallel.
   */
  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    init_worker_ndpi(&workers[i]);
  }

  printf("[5/5] Starting benchmark...\n");
  printf("      Loops: %u\n", cfg.num_loops);
  printf("      Flow randomization: %s\n", cfg.flow_randomization ? "ON" : "OFF");
  printf("      Timestamp jitter: %s\n", cfg.timestamp_jitter ? "ON" : "OFF");
  printf("\n----------------------------------------\n");
  printf("Protocol Detection Samples (first %lu flows):\n", (unsigned long)g_sample_limit);
  printf("----------------------------------------\n\n");

  gettimeofday(&tv_process_start, NULL);
  uint64_t cycles_start = rdtsc();

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    if (pthread_create(&workers[i].thread, NULL, worker_thread, &workers[i]) != 0) {
      fprintf(stderr, "Error: pthread_create(worker=%u) failed\n", i);
      exit(1);
    }
  }

  for (uint32_t i = 0; i < cfg.num_workers; i++) {
    pthread_join(workers[i].thread, NULL);
  }

  uint64_t cycles_end = rdtsc();
  gettimeofday(&tv_process_end, NULL);
  gettimeofday(&tv_total_end, NULL);

  double elapsed = elapsed_sec(&tv_process_start, &tv_process_end);
  double total_elapsed = elapsed_sec(&tv_total_start, &tv_total_end);
  double load_elapsed = elapsed_sec(&tv_load_start, &tv_load_end);
  double assign_elapsed = elapsed_sec(&tv_assign_start, &tv_assign_end);
  double process_elapsed = elapsed;

  print_benchmark_results(workers, cfg.num_workers, cycles_end - cycles_start, elapsed);

  printf("\nTime Breakdown (wall-clock):\n");
  printf("  Load PCAP:     %.3f s (%.1f%%)\n",
         load_elapsed, total_elapsed > 0.0 ? load_elapsed * 100.0 / total_elapsed : 0.0);
  printf("  Assign packets: %.3f s (%.1f%%)\n",
         assign_elapsed, total_elapsed > 0.0 ? assign_elapsed * 100.0 / total_elapsed : 0.0);
  printf("  Processing:   %.3f s (%.1f%%)\n",
         process_elapsed, total_elapsed > 0.0 ? process_elapsed * 100.0 / total_elapsed : 0.0);
  printf("  Total:        %.3f s (100.0%%)\n", total_elapsed);

  for (uint32_t i = 0; i < cfg.num_workers; i++) cleanup_worker(&workers[i]);

  free(workers);
  free_packet_pool(pool);
  ndpi_global_deinit(g_ctx);
  free(cfg.core_list);

  return 0;
}
