#include "benchmark_internal.h"

#define CATEGORY_BUCKETS 1024

typedef struct {
  uint64_t total_packets;
  uint64_t total_bytes;
  uint64_t parse_ok_packets;
  uint64_t parse_fail_packets;
  uint64_t normalize_fail_packets;
  uint64_t flows_created;
  uint64_t flows_detected;
  uint64_t pcap_read_ns;
  uint64_t process_ns;
} benchmark_stats_t;

typedef struct {
  bool used;
  ndpi_protocol_category_t category;
  uint64_t flow_count;
  uint64_t sum_detection_ns;
  uint64_t sum_detect_pkt_in_flow;
  uint64_t sum_detect_pkt_global;
} category_stat_t;

typedef struct {
  struct ndpi_detection_module_struct *ndpi;
  category_stat_t *cat_stats;
} aggregate_ctx_t;

typedef struct {
  struct ndpi_detection_module_struct *ndpi;
  uint64_t index;
} print_ctx_t;

typedef struct {
  const char *pcap_file;
  const char *proto_file;
  uint32_t cpu_core;
  bool quiet;
} benchmark_config_t;

static void usage(const char *prog) {
  printf("%s - mark4 single-worker direct pcap reader\n\n", prog);
  printf("Usage: %s -i <pcap> [options]\n\n", prog);
  printf("Required:\n");
  printf("  -i <file>          PCAP file to process\n\n");
  printf("Options:\n");
  printf("  -c <core>          Bind current thread to CPU core\n");
  printf("  -p <file>          Protocol configuration file\n");
  printf("  -q                 Quiet mode (hide per-flow lines)\n");
  printf("  -h                 Show help\n\n");
}

static benchmark_config_t parse_args(int argc, char **argv) {
  benchmark_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.cpu_core = UINT32_MAX;

  int opt;
  while ((opt = getopt(argc, argv, "i:c:p:qh")) != -1) {
    switch (opt) {
      case 'i':
        cfg.pcap_file = optarg;
        break;
      case 'c':
        cfg.cpu_core = (uint32_t)atoi(optarg);
        break;
      case 'p':
        cfg.proto_file = optarg;
        break;
      case 'q':
        cfg.quiet = true;
        break;
      case 'h':
        usage(argv[0]);
        exit(0);
      default:
        usage(argv[0]);
        exit(1);
    }
  }

  if (!cfg.pcap_file) {
    fprintf(stderr, "Error: PCAP file required (-i)\n\n");
    usage(argv[0]);
    exit(1);
  }

  return cfg;
}

#ifdef __linux__
static void set_thread_affinity(uint32_t core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);
  int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
  if (rc != 0) {
    fprintf(stderr, "Warning: pthread_setaffinity_np(core=%u) failed: %s\n", core, strerror(rc));
  }
}
#else
static void set_thread_affinity(uint32_t core) {
  (void)core;
}
#endif

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

static void set_ndpi_flow_tuple(struct ndpi_flow_struct *flow,
                                const parsed_packet_t *p,
                                const endpoint_t *client,
                                const endpoint_t *server) {
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

static void free_flow_cb(bench_flow_t *flow, void *user) {
  (void)user;
  if (!flow) return;
  if (flow->ndpi_flow) {
    ndpi_free_flow(flow->ndpi_flow);
    flow->ndpi_flow = NULL;
  }
  free(flow);
}

static const char *category_name(struct ndpi_detection_module_struct *ndpi,
                                 ndpi_protocol_category_t category) {
  const char *name = ndpi_category_get_name(ndpi, category);
  return (name && name[0] != '\0') ? name : "(unknown-category)";
}

static void print_flow_cb(bench_flow_t *flow, void *user) {
  print_ctx_t *ctx = (print_ctx_t *)user;
  ctx->index++;

  char client[128], server[128];
  endpoint_to_string(&flow->client, client, sizeof(client));
  endpoint_to_string(&flow->server, server, sizeof(server));

  ndpi_master_app_protocol proto = {0};
  proto.master_protocol = flow->detected_master_proto;
  proto.app_protocol = flow->detected_app_proto;

  char proto_name[64] = {0};
  ndpi_protocol2name(ctx->ndpi, proto, proto_name, (u_int)sizeof(proto_name));

  if (flow->protocol_counted) {
    printf("Flow #%lu | %s <-> %s | proto=%s | category=%s | detect_latency=%.3f ms | detect_pkt(flow)=%lu | detect_pkt(global)=%lu\n",
           (unsigned long)ctx->index,
           client,
           server,
           proto_name[0] ? proto_name : "(unknown)",
           category_name(ctx->ndpi, flow->detected_category),
           (double)flow->detection_latency_ns / 1e6,
           (unsigned long)flow->detection_packet_in_flow,
           (unsigned long)flow->detection_packet_global);
  } else {
    printf("Flow #%lu | %s <-> %s | proto=(NOT_DETECTED) | category=(NOT_DETECTED) | detect_latency=N/A | detect_pkt(flow)=N/A | detect_pkt(global)=N/A\n",
           (unsigned long)ctx->index,
           client,
           server);
  }
}

static void aggregate_category_cb(bench_flow_t *flow, void *user) {
  aggregate_ctx_t *ctx = (aggregate_ctx_t *)user;
  if (!flow->protocol_counted) return;

  uint32_t idx = (uint32_t)flow->detected_category;
  if (idx >= CATEGORY_BUCKETS) return;

  category_stat_t *st = &ctx->cat_stats[idx];
  st->used = true;
  st->category = flow->detected_category;
  st->flow_count++;
  st->sum_detection_ns += flow->detection_latency_ns;
  st->sum_detect_pkt_in_flow += flow->detection_packet_in_flow;
  st->sum_detect_pkt_global += flow->detection_packet_global;
}

int main(int argc, char **argv) {
  benchmark_config_t cfg = parse_args(argc, argv);

  if (cfg.cpu_core != UINT32_MAX) {
    set_thread_affinity(cfg.cpu_core);
  }

  printf("========================================\n");
  printf("ndpiBenchmarkMark4 (Single Worker Direct Reader)\n");
  printf("========================================\n");
  printf("PCAP: %s\n\n", cfg.pcap_file);

  struct ndpi_global_context *g_ctx = ndpi_global_init();
  if (!g_ctx) {
    fprintf(stderr, "Error: ndpi_global_init() failed\n");
    return 1;
  }

  struct ndpi_detection_module_struct *ndpi = ndpi_init_detection_module(g_ctx);
  if (!ndpi) {
    fprintf(stderr, "Error: ndpi_init_detection_module() failed\n");
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  (void)ndpi_set_config(ndpi, NULL, "tcp_ack_payload_heuristic", "enable");
  if (cfg.proto_file && cfg.proto_file[0]) {
    (void)ndpi_load_protocols_file(ndpi, cfg.proto_file);
  }
  ndpi_finalize_initialization(ndpi);

  struct flow_table *flows = flow_table_create(16384);
  if (!flows) {
    fprintf(stderr, "Error: flow_table_create() failed\n");
    ndpi_exit_detection_module(ndpi);
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pc = pcap_open_offline(cfg.pcap_file, errbuf);
  if (!pc) {
    fprintf(stderr, "Error: pcap_open_offline(%s): %s\n", cfg.pcap_file, errbuf);
    flow_table_destroy(flows, free_flow_cb, NULL);
    ndpi_exit_detection_module(ndpi);
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  int linktype = pcap_datalink(pc);

  benchmark_stats_t stats;
  memset(&stats, 0, sizeof(stats));

  uint64_t wall_start_ns = get_time_ns();

  struct pcap_pkthdr *hdr = NULL;
  const u_char *pkt = NULL;
  int rc = 0;

  while (1) {
    uint64_t t_read0 = get_time_ns();
    rc = pcap_next_ex(pc, &hdr, &pkt);
    uint64_t t_read1 = get_time_ns();
    stats.pcap_read_ns += (t_read1 - t_read0);

    if (rc == 1) {
      stats.total_packets++;
      stats.total_bytes += hdr->len;

      uint64_t t_proc0 = get_time_ns();

      const uint8_t *norm_data = NULL;
      uint16_t norm_caplen = 0;
      uint16_t norm_wirelen = 0;
      uint8_t scratch[MAX_PACKET_SIZE];
      if (!normalize_to_ethernet(linktype,
                                 pkt,
                                 (uint16_t)hdr->caplen,
                                 (uint16_t)hdr->len,
                                 &norm_data,
                                 &norm_caplen,
                                 &norm_wirelen,
                                 scratch,
                                 sizeof(scratch))) {
        stats.normalize_fail_packets++;
        uint64_t t_proc1 = get_time_ns();
        stats.process_ns += (t_proc1 - t_proc0);
        continue;
      }

      parsed_packet_t pp;
      if (parse_ethernet_frame(norm_data, norm_caplen, &pp) != PARSE_OK) {
        stats.parse_fail_packets++;
        uint64_t t_proc1 = get_time_ns();
        stats.process_ns += (t_proc1 - t_proc0);
        continue;
      }
      stats.parse_ok_packets++;

      flow_key_t key;
      endpoint_t src_ep;
      endpoint_t dst_ep;
      flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);

      uint64_t h = flow_key_hash(&key);
      bool is_new = false;
      bench_flow_t *flow = flow_table_get_or_create(flows, &key, h, &is_new);
      if (!flow) {
        fprintf(stderr, "Error: flow_table_get_or_create() failed\n");
        pcap_close(pc);
        flow_table_destroy(flows, free_flow_cb, NULL);
        ndpi_exit_detection_module(ndpi);
        ndpi_global_deinit(g_ctx);
        return 1;
      }

      if (is_new) {
        stats.flows_created++;
        flow->client = src_ep;
        flow->server = dst_ep;
        flow->first_seen_ns = get_time_ns();

        flow->ndpi_flow = (struct ndpi_flow_struct *)ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
        if (!flow->ndpi_flow) {
          fprintf(stderr, "Error: ndpi_calloc(flow) failed\n");
          pcap_close(pc);
          flow_table_destroy(flows, free_flow_cb, NULL);
          ndpi_exit_detection_module(ndpi);
          ndpi_global_deinit(g_ctx);
          return 1;
        }

        set_ndpi_flow_tuple(flow->ndpi_flow, &pp, &flow->client, &flow->server);
      }

      uint8_t dir = endpoint_equal(&src_ep, &flow->client) ? 0 : 1;
      if (dir == 0) {
        flow->c2s_packets++;
        flow->c2s_bytes += norm_wirelen;
      } else {
        flow->s2c_packets++;
        flow->s2c_bytes += norm_wirelen;
      }
      flow->seen_packets++;
      flow->last_seen_ms = ((uint64_t)hdr->ts.tv_sec * 1000000ULL + (uint64_t)hdr->ts.tv_usec) / 1000ULL;

      struct ndpi_flow_input_info in = {0};
      in.in_pkt_dir = dir;
      in.seen_flow_beginning = (flow->seen_packets == 1);
      (void)ndpi_detection_process_packet(ndpi,
                                          flow->ndpi_flow,
                                          pp.l3,
                                          pp.l3_len,
                                          flow->last_seen_ms,
                                          &in);

      if (!flow->protocol_counted) {
        uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
        if (app != NDPI_PROTOCOL_UNKNOWN) {
          flow->protocol_counted = true;
          flow->detected_app_proto = app;
          flow->detected_master_proto = ndpi_get_flow_masterprotocol(flow->ndpi_flow);
          flow->detected_category = ndpi_get_flow_category(flow->ndpi_flow);
          flow->detection_packet_in_flow = flow->seen_packets;
          flow->detection_packet_global = stats.total_packets;
          flow->detection_latency_ns = get_time_ns() - flow->first_seen_ns;
          stats.flows_detected++;
        }
      }

      uint64_t t_proc1 = get_time_ns();
      stats.process_ns += (t_proc1 - t_proc0);
    } else if (rc == -2) {
      break;
    } else if (rc == 0) {
      continue;
    } else {
      fprintf(stderr, "Error: pcap_next_ex() failed: %s\n", pcap_geterr(pc));
      pcap_close(pc);
      flow_table_destroy(flows, free_flow_cb, NULL);
      ndpi_exit_detection_module(ndpi);
      ndpi_global_deinit(g_ctx);
      return 1;
    }
  }

  uint64_t wall_end_ns = get_time_ns();
  double elapsed_sec = (wall_end_ns > wall_start_ns)
                           ? (double)(wall_end_ns - wall_start_ns) / 1e9
                           : 0.0;

  printf("Total packets: %lu\n", (unsigned long)stats.total_packets);
  printf("Total bytes: %.2f MB\n", (double)stats.total_bytes / 1024.0 / 1024.0);
  printf("Parse-ok packets: %lu\n", (unsigned long)stats.parse_ok_packets);
  printf("Parse-fail packets: %lu\n", (unsigned long)stats.parse_fail_packets);
  printf("Normalize-fail packets: %lu\n", (unsigned long)stats.normalize_fail_packets);
  printf("Total flows: %lu\n", (unsigned long)stats.flows_created);
  printf("Detected flows: %lu (%.2f%%)\n",
         (unsigned long)stats.flows_detected,
         stats.flows_created ? (100.0 * (double)stats.flows_detected / (double)stats.flows_created) : 0.0);
  printf("Elapsed: %.6f sec | pcap_read: %.6f sec | process: %.6f sec\n",
         elapsed_sec,
         (double)stats.pcap_read_ns / 1e9,
         (double)stats.process_ns / 1e9);

  if (!cfg.quiet) {
    printf("\n========================================\n");
    printf("Per-flow Detection Details\n");
    printf("========================================\n");
    print_ctx_t pctx = {.ndpi = ndpi, .index = 0};
    flow_table_foreach(flows, print_flow_cb, &pctx);
  }

  category_stat_t cat_stats[CATEGORY_BUCKETS];
  memset(cat_stats, 0, sizeof(cat_stats));
  aggregate_ctx_t actx = {.ndpi = ndpi, .cat_stats = cat_stats};
  flow_table_foreach(flows, aggregate_category_cb, &actx);

  printf("\n========================================\n");
  printf("Category Summary (Detected Flows)\n");
  printf("========================================\n");
  for (uint32_t i = 0; i < CATEGORY_BUCKETS; i++) {
    if (!cat_stats[i].used || cat_stats[i].flow_count == 0) continue;
    double avg_ms = (double)cat_stats[i].sum_detection_ns / (double)cat_stats[i].flow_count / 1e6;
    double avg_pkt_flow = (double)cat_stats[i].sum_detect_pkt_in_flow / (double)cat_stats[i].flow_count;
    double avg_pkt_global = (double)cat_stats[i].sum_detect_pkt_global / (double)cat_stats[i].flow_count;

    printf("Category=%s (id=%u) | flows=%lu | avg_detect_latency=%.3f ms | avg_detect_pkt(flow)=%.2f | avg_detect_pkt(global)=%.2f\n",
           category_name(ndpi, cat_stats[i].category),
           (unsigned)cat_stats[i].category,
           (unsigned long)cat_stats[i].flow_count,
           avg_ms,
           avg_pkt_flow,
           avg_pkt_global);
  }

  pcap_close(pc);
  flow_table_destroy(flows, free_flow_cb, NULL);
  ndpi_exit_detection_module(ndpi);
  ndpi_global_deinit(g_ctx);
  return 0;
}
