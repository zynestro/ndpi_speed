#include "benchmark_internal.h"
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define PREFIX_BYTES 4

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
  uint16_t master_proto;
  uint16_t app_proto;
  ndpi_protocol_category_t category;
  uint64_t flow_count;
} label_stat_t;

typedef struct {
  uint8_t ip_version;
  uint8_t l4_proto;
  uint16_t server_port;
  uint8_t payload_prefix_len;
  uint32_t payload_prefix_u32;
} first_packet_signature_t;

typedef struct {
  first_packet_signature_t key;
  uint64_t flow_count;
  uint64_t detected_flow_count;
  uint64_t undetected_flow_count;
  uint64_t sum_flow_packets;
  uint64_t sum_flow_bytes;
  uint64_t sum_detecting_flow_ns;
  uint64_t sum_post_flow_ns;
  uint64_t sum_detecting_detection_flow_ns;
  uint64_t sum_post_detection_flow_ns;
  uint64_t sum_total_flow_ns;
  uint64_t sum_detect_pkt_in_flow;
  sample_vec_t total_flow_samples_ns;
  sample_vec_t detect_pkt_in_flow_samples;
  label_stat_t *labels;
  size_t label_count;
  size_t label_cap;
} signature_stat_t;

typedef struct {
  signature_stat_t *items;
  size_t count;
  size_t cap;
} signature_aggregate_ctx_t;

typedef struct {
  struct ndpi_detection_module_struct *ndpi;
  uint64_t index;
} print_ctx_t;

typedef struct {
  FILE *fp;
  struct ndpi_detection_module_struct *ndpi;
  uint64_t index;
} flow_profile_ctx_t;

typedef struct {
  const char *pcap_file;
  const char *proto_file;
  const char *output_root;
  uint32_t cpu_core;
  bool quiet;
} benchmark_config_t;

static bool sample_vec_grow(sample_vec_t *vec, size_t min_cap) {
  if (!vec) return false;
  if (vec->cap >= min_cap) return true;

  size_t new_cap = (vec->cap == 0) ? 16 : vec->cap;
  while (new_cap < min_cap) new_cap *= 2;

  uint64_t *new_items = (uint64_t *)realloc(vec->items, new_cap * sizeof(uint64_t));
  if (!new_items) return false;
  vec->items = new_items;
  vec->cap = new_cap;
  return true;
}

static bool sample_vec_push(sample_vec_t *vec, uint64_t value) {
  if (!vec) return false;
  if (!sample_vec_grow(vec, vec->count + 1)) return false;
  vec->items[vec->count++] = value;
  return true;
}

static void sample_vec_free(sample_vec_t *vec) {
  if (!vec) return;
  free(vec->items);
  vec->items = NULL;
  vec->count = 0;
  vec->cap = 0;
}

static int uint64_cmp_asc(const void *a, const void *b) {
  uint64_t va = *(const uint64_t *)a;
  uint64_t vb = *(const uint64_t *)b;
  if (va < vb) return -1;
  if (va > vb) return 1;
  return 0;
}

static void sample_vec_sort(sample_vec_t *vec) {
  if (!vec || vec->count < 2) return;
  qsort(vec->items, vec->count, sizeof(uint64_t), uint64_cmp_asc);
}

static uint64_t sample_vec_percentile_sorted(const sample_vec_t *vec, uint32_t pct) {
  if (!vec || vec->count == 0) return 0;
  if (pct == 0) return vec->items[0];
  if (pct >= 100) return vec->items[vec->count - 1];

  size_t rank = (size_t)(((uint64_t)pct * (uint64_t)vec->count + 99ULL) / 100ULL);
  if (rank == 0) rank = 1;
  if (rank > vec->count) rank = vec->count;
  return vec->items[rank - 1];
}

static void usage(const char *prog) {
  printf("%s - mark5 first-packet signature profiler\n\n", prog);
  printf("Usage: %s -i <pcap> [options]\n\n", prog);
  printf("Required:\n");
  printf("  -i <file>          PCAP file to process\n\n");
  printf("Options:\n");
  printf("  -c <core>          Bind current thread to CPU core\n");
  printf("  -p <file>          Protocol configuration file\n");
  printf("  -o <dir>           Output root directory (default: output)\n");
  printf("  -q                 Quiet mode (hide per-flow lines)\n");
  printf("  -h                 Show help\n\n");
}

static benchmark_config_t parse_args(int argc, char **argv) {
  benchmark_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.cpu_core = UINT32_MAX;
  cfg.output_root = NDPI_SPEED_OUTPUT_DIR;

  int opt;
  while ((opt = getopt(argc, argv, "i:c:p:o:qh")) != -1) {
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
      case 'o':
        cfg.output_root = optarg;
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
  sample_vec_free(&flow->detecting_packet_samples_ns);
  sample_vec_free(&flow->post_packet_samples_ns);
  free(flow);
}

static const char *category_name(struct ndpi_detection_module_struct *ndpi,
                                 ndpi_protocol_category_t category) {
  const char *name = ndpi_category_get_name(ndpi, category);
  return (name && name[0] != '\0') ? name : "(unknown-category)";
}

static void make_timestamp(char *buf, size_t buflen) {
  if (!buf || buflen == 0) return;
  time_t now = time(NULL);
  struct tm tm_now;
  localtime_r(&now, &tm_now);
  strftime(buf, buflen, "%Y%m%d_%H%M%S", &tm_now);
}

static bool mkdir_p(const char *dir) {
  if (!dir || dir[0] == '\0') return false;
  char tmp[PATH_MAX];
  size_t len = strnlen(dir, sizeof(tmp) - 1);
  if (len == 0 || len >= sizeof(tmp) - 1) return false;
  memcpy(tmp, dir, len);
  tmp[len] = '\0';

  for (char *p = tmp + 1; *p; p++) {
    if (*p == '/') {
      *p = '\0';
      if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
      *p = '/';
    }
  }
  if (mkdir(tmp, 0755) != 0 && errno != EEXIST) return false;
  return true;
}

static void init_signature_from_first_packet(bench_flow_t *flow,
                                             const parsed_packet_t *pp,
                                             const endpoint_t *dst_ep) {
  if (!flow || !pp || !dst_ep || flow->signature_initialized) return;

  flow->signature_initialized = true;
  flow->signature_ip_version = pp->ip_version;
  flow->signature_l4_proto = pp->l4_proto;
  flow->signature_server_port = dst_ep->port;
  flow->signature_payload_prefix_len = (pp->payload_len < PREFIX_BYTES) ? (uint8_t)pp->payload_len : PREFIX_BYTES;
  flow->signature_payload_prefix_u32 = 0;

  for (uint8_t i = 0; i < flow->signature_payload_prefix_len; i++) {
    flow->signature_payload_prefix_u32 |= (uint32_t)pp->payload[i] << (8U * (3U - i));
  }
}

static void prefix_to_hex(uint32_t prefix_u32, uint8_t prefix_len, char *buf, size_t buflen) {
  if (!buf || buflen == 0) return;
  static const char hex[] = "0123456789abcdef";
  size_t need = (size_t)prefix_len * 2 + 1;
  if (buflen < need) {
    if (buflen > 0) buf[0] = '\0';
    return;
  }

  for (uint8_t i = 0; i < prefix_len; i++) {
    uint8_t byte = (uint8_t)((prefix_u32 >> (8U * (3U - i))) & 0xFFU);
    buf[i * 2] = hex[byte >> 4];
    buf[i * 2 + 1] = hex[byte & 0x0FU];
  }
  buf[prefix_len * 2] = '\0';
}

static void prefix_n_to_hex(uint32_t prefix_u32, uint8_t available_len,
                            uint8_t n, char *buf, size_t buflen) {
  if (!buf || buflen == 0) return;
  if (available_len < n) {
    buf[0] = '\0';
    return;
  }
  prefix_to_hex(prefix_u32, n, buf, buflen);
}

static int signature_stat_cmp_desc(const void *a, const void *b) {
  const signature_stat_t *sa = (const signature_stat_t *)a;
  const signature_stat_t *sb = (const signature_stat_t *)b;
  if (sa->flow_count < sb->flow_count) return 1;
  if (sa->flow_count > sb->flow_count) return -1;
  if (sa->key.server_port < sb->key.server_port) return -1;
  if (sa->key.server_port > sb->key.server_port) return 1;
  if (sa->key.payload_prefix_u32 < sb->key.payload_prefix_u32) return -1;
  if (sa->key.payload_prefix_u32 > sb->key.payload_prefix_u32) return 1;
  return 0;
}

static bool signature_stats_grow(signature_aggregate_ctx_t *ctx) {
  if (!ctx) return false;
  if (ctx->count < ctx->cap) return true;
  size_t new_cap = (ctx->cap == 0) ? 64 : (ctx->cap * 2);
  signature_stat_t *new_items =
      (signature_stat_t *)realloc(ctx->items, new_cap * sizeof(signature_stat_t));
  if (!new_items) return false;
  ctx->items = new_items;
  ctx->cap = new_cap;
  return true;
}

static bool label_stats_grow(signature_stat_t *st) {
  if (!st) return false;
  if (st->label_count < st->label_cap) return true;
  size_t new_cap = (st->label_cap == 0) ? 4 : (st->label_cap * 2);
  label_stat_t *new_items = (label_stat_t *)realloc(st->labels, new_cap * sizeof(label_stat_t));
  if (!new_items) return false;
  st->labels = new_items;
  st->label_cap = new_cap;
  return true;
}

static void add_detected_label(signature_stat_t *st, const bench_flow_t *flow) {
  if (!st || !flow || !flow->protocol_counted) return;

  for (size_t i = 0; i < st->label_count; i++) {
    label_stat_t *label = &st->labels[i];
    if (label->master_proto == flow->detected_master_proto &&
        label->app_proto == flow->detected_app_proto &&
        label->category == flow->detected_category) {
      label->flow_count++;
      return;
    }
  }

  if (!label_stats_grow(st)) return;
  label_stat_t *dst = &st->labels[st->label_count++];
  dst->master_proto = flow->detected_master_proto;
  dst->app_proto = flow->detected_app_proto;
  dst->category = flow->detected_category;
  dst->flow_count = 1;
}

static void aggregate_signature_cb(bench_flow_t *flow, void *user) {
  signature_aggregate_ctx_t *ctx = (signature_aggregate_ctx_t *)user;
  if (!flow || !ctx || !flow->signature_initialized) return;

  uint64_t flow_total_ns = flow->detecting_time_ns_total + flow->post_time_ns_total;
  uint64_t flow_bytes = flow->c2s_bytes + flow->s2c_bytes;

  for (size_t i = 0; i < ctx->count; i++) {
    signature_stat_t *st = &ctx->items[i];
    if (st->key.ip_version == flow->signature_ip_version &&
        st->key.l4_proto == flow->signature_l4_proto &&
        st->key.server_port == flow->signature_server_port &&
        st->key.payload_prefix_len == flow->signature_payload_prefix_len &&
        st->key.payload_prefix_u32 == flow->signature_payload_prefix_u32) {
      st->flow_count++;
      st->sum_flow_packets += flow->seen_packets;
      st->sum_flow_bytes += flow_bytes;
      st->sum_detecting_flow_ns += flow->detecting_time_ns_total;
      st->sum_post_flow_ns += flow->post_time_ns_total;
      st->sum_detecting_detection_flow_ns += flow->detecting_detection_time_ns_total;
      st->sum_post_detection_flow_ns += flow->post_detection_time_ns_total;
      st->sum_total_flow_ns += flow_total_ns;
      (void)sample_vec_push(&st->total_flow_samples_ns, flow_total_ns);
      if (flow->protocol_counted) {
        st->detected_flow_count++;
        st->sum_detect_pkt_in_flow += flow->detection_packet_in_flow;
        (void)sample_vec_push(&st->detect_pkt_in_flow_samples, flow->detection_packet_in_flow);
        add_detected_label(st, flow);
      } else {
        st->undetected_flow_count++;
      }
      return;
    }
  }

  if (!signature_stats_grow(ctx)) return;
  signature_stat_t *dst = &ctx->items[ctx->count++];
  memset(dst, 0, sizeof(*dst));
  dst->key.ip_version = flow->signature_ip_version;
  dst->key.l4_proto = flow->signature_l4_proto;
  dst->key.server_port = flow->signature_server_port;
  dst->key.payload_prefix_len = flow->signature_payload_prefix_len;
  dst->key.payload_prefix_u32 = flow->signature_payload_prefix_u32;
  dst->flow_count = 1;
  dst->sum_flow_packets = flow->seen_packets;
  dst->sum_flow_bytes = flow_bytes;
  dst->sum_detecting_flow_ns = flow->detecting_time_ns_total;
  dst->sum_post_flow_ns = flow->post_time_ns_total;
  dst->sum_detecting_detection_flow_ns = flow->detecting_detection_time_ns_total;
  dst->sum_post_detection_flow_ns = flow->post_detection_time_ns_total;
  dst->sum_total_flow_ns = flow_total_ns;
  (void)sample_vec_push(&dst->total_flow_samples_ns, flow_total_ns);
  if (flow->protocol_counted) {
    dst->detected_flow_count = 1;
    dst->sum_detect_pkt_in_flow = flow->detection_packet_in_flow;
    (void)sample_vec_push(&dst->detect_pkt_in_flow_samples, flow->detection_packet_in_flow);
    add_detected_label(dst, flow);
  } else {
    dst->undetected_flow_count = 1;
  }
}

static const label_stat_t *dominant_label(const signature_stat_t *st) {
  if (!st || st->label_count == 0) return NULL;
  const label_stat_t *best = &st->labels[0];
  for (size_t i = 1; i < st->label_count; i++) {
    if (st->labels[i].flow_count > best->flow_count) best = &st->labels[i];
  }
  return best;
}

static void csv_write_escaped(FILE *fp, const char *s) {
  if (!fp) return;
  if (!s) s = "";
  fputc('"', fp);
  for (const char *p = s; *p; p++) {
    if (*p == '"') fputc('"', fp);
    fputc(*p, fp);
  }
  fputc('"', fp);
}

static bool write_signature_summary_csv(const char *csv_path,
                                        const benchmark_stats_t *summary,
                                        struct ndpi_detection_module_struct *ndpi,
                                        const signature_stat_t *stats,
                                        size_t count) {
  FILE *fp = fopen(csv_path, "w");
  if (!fp) return false;

  if (summary) {
    fprintf(fp, "# summary_key,summary_value\n");
    fprintf(fp, "# Total packets,%lu\n", (unsigned long)summary->total_packets);
    fprintf(fp, "# Total bytes,%lu\n", (unsigned long)summary->total_bytes);
    fprintf(fp, "# Parse-ok packets,%lu\n", (unsigned long)summary->parse_ok_packets);
    fprintf(fp, "# Parse-fail packets,%lu\n", (unsigned long)summary->parse_fail_packets);
    fprintf(fp, "# Normalize-fail packets,%lu\n", (unsigned long)summary->normalize_fail_packets);
    fprintf(fp, "# Total flows,%lu\n", (unsigned long)summary->flows_created);
    fprintf(fp, "# Detected flows,%lu\n", (unsigned long)summary->flows_detected);
    fprintf(fp, "\n");
  }

  fprintf(fp, "ip_version,l4_proto,server_port,payload_prefix_len,payload_prefix_hex,flows,detected_flows,undetected_flows,detected_ratio,avg_pkts_per_flow,avg_bytes_per_flow,avg_flow_detecting_ms,avg_flow_post_ms,avg_flow_total_ms,flow_total_p50_ms,flow_total_p99_ms,avg_flow_detecting_detection_only_ms,avg_flow_post_detection_only_ms,avg_detect_pkt_flow,detect_pkt_flow_p50,detect_pkt_flow_p99,dominant_proto_name,dominant_master_proto,dominant_app_proto,dominant_category_name,dominant_category_id,dominant_label_purity\n");

  for (size_t i = 0; i < count; i++) {
    const signature_stat_t *st = &stats[i];
    if (st->flow_count == 0) continue;

    char prefix_hex[2 * PREFIX_BYTES + 1] = {0};
    prefix_to_hex(st->key.payload_prefix_u32, st->key.payload_prefix_len, prefix_hex, sizeof(prefix_hex));

    double avg_pkts_per_flow = (double)st->sum_flow_packets / (double)st->flow_count;
    double avg_bytes_per_flow = (double)st->sum_flow_bytes / (double)st->flow_count;
    double avg_detecting_ms = (double)st->sum_detecting_flow_ns / (double)st->flow_count / 1e6;
    double avg_post_ms = (double)st->sum_post_flow_ns / (double)st->flow_count / 1e6;
    double avg_total_ms = (double)st->sum_total_flow_ns / (double)st->flow_count / 1e6;
    double flow_total_p50_ms = (double)sample_vec_percentile_sorted(&st->total_flow_samples_ns, 50) / 1e6;
    double flow_total_p99_ms = (double)sample_vec_percentile_sorted(&st->total_flow_samples_ns, 99) / 1e6;
    double avg_detecting_detection_only_ms =
        (double)st->sum_detecting_detection_flow_ns / (double)st->flow_count / 1e6;
    double avg_post_detection_only_ms =
        (double)st->sum_post_detection_flow_ns / (double)st->flow_count / 1e6;
    double detected_ratio = st->flow_count ? (double)st->detected_flow_count / (double)st->flow_count : 0.0;
    double avg_detect_pkt_flow = st->detected_flow_count
                                     ? (double)st->sum_detect_pkt_in_flow / (double)st->detected_flow_count
                                     : 0.0;
    double detect_pkt_flow_p50 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 50);
    double detect_pkt_flow_p99 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 99);

    const label_stat_t *best = dominant_label(st);
    char proto_name[64] = {0};
    const char *cat_name = "";
    unsigned master_proto = 0;
    unsigned app_proto = 0;
    unsigned category_id = 0;
    double purity = 0.0;
    if (best) {
      ndpi_master_app_protocol proto = {0};
      proto.master_protocol = best->master_proto;
      proto.app_protocol = best->app_proto;
      ndpi_protocol2name(ndpi, proto, proto_name, (u_int)sizeof(proto_name));
      cat_name = category_name(ndpi, best->category);
      master_proto = best->master_proto;
      app_proto = best->app_proto;
      category_id = (unsigned)best->category;
      purity = st->detected_flow_count ? (double)best->flow_count / (double)st->detected_flow_count : 0.0;
    }

    fprintf(fp, "%u,%u,%u,%u,", (unsigned)st->key.ip_version, (unsigned)st->key.l4_proto,
            (unsigned)st->key.server_port, (unsigned)st->key.payload_prefix_len);
    csv_write_escaped(fp, prefix_hex);
    fprintf(fp, ",%lu,%lu,%lu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%.3f,",
            (unsigned long)st->flow_count,
            (unsigned long)st->detected_flow_count,
            (unsigned long)st->undetected_flow_count,
            detected_ratio,
            avg_pkts_per_flow,
            avg_bytes_per_flow,
            avg_detecting_ms,
            avg_post_ms,
            avg_total_ms,
            flow_total_p50_ms,
            flow_total_p99_ms,
            avg_detecting_detection_only_ms,
            avg_post_detection_only_ms,
            avg_detect_pkt_flow,
            detect_pkt_flow_p50,
            detect_pkt_flow_p99);
    csv_write_escaped(fp, proto_name[0] ? proto_name : "");
    fprintf(fp, ",%u,%u,", master_proto, app_proto);
    csv_write_escaped(fp, cat_name);
    fprintf(fp, ",%u,%.6f\n", category_id, purity);
  }

  fclose(fp);
  return true;
}

static void write_flow_profile_cb(bench_flow_t *flow, void *user) {
  flow_profile_ctx_t *ctx = (flow_profile_ctx_t *)user;
  if (!flow || !ctx || !ctx->fp) return;

  ctx->index++;

  char prefix_1_hex[2 * 1 + 1] = {0};
  char prefix_2_hex[2 * 2 + 1] = {0};
  char prefix_4_hex[2 * 4 + 1] = {0};
  prefix_n_to_hex(flow->signature_payload_prefix_u32, flow->signature_payload_prefix_len, 1,
                  prefix_1_hex, sizeof(prefix_1_hex));
  prefix_n_to_hex(flow->signature_payload_prefix_u32, flow->signature_payload_prefix_len, 2,
                  prefix_2_hex, sizeof(prefix_2_hex));
  prefix_n_to_hex(flow->signature_payload_prefix_u32, flow->signature_payload_prefix_len, 4,
                  prefix_4_hex, sizeof(prefix_4_hex));

  const char *proto_name = "NOT_DETECTED";
  const char *cat_name = "NOT_DETECTED";
  unsigned master_proto = 0;
  unsigned app_proto = 0;
  unsigned category_id = 0;
  if (flow->protocol_counted) {
    ndpi_master_app_protocol proto = {0};
    char proto_buf[64] = {0};
    proto.master_protocol = flow->detected_master_proto;
    proto.app_protocol = flow->detected_app_proto;
    ndpi_protocol2name(ctx->ndpi, proto, proto_buf, (u_int)sizeof(proto_buf));
    proto_name = proto_buf[0] ? proto_buf : "(unknown)";
    cat_name = category_name(ctx->ndpi, flow->detected_category);
    master_proto = flow->detected_master_proto;
    app_proto = flow->detected_app_proto;
    category_id = (unsigned)flow->detected_category;

    fprintf(ctx->fp,
            "%lu,%u,%u,%u,%u,%u,",
            (unsigned long)ctx->index,
            (unsigned)flow->signature_ip_version,
            (unsigned)flow->signature_l4_proto,
            (unsigned)flow->signature_server_port,
            (unsigned)flow->signature_server_port,
            (unsigned)flow->signature_payload_prefix_len);
    csv_write_escaped(ctx->fp, prefix_1_hex);
    fputc(',', ctx->fp);
    csv_write_escaped(ctx->fp, prefix_2_hex);
    fputc(',', ctx->fp);
    csv_write_escaped(ctx->fp, prefix_4_hex);
    fprintf(ctx->fp, ",1,");
    csv_write_escaped(ctx->fp, proto_name);
    fprintf(ctx->fp, ",%u,%u,", master_proto, app_proto);
    csv_write_escaped(ctx->fp, cat_name);
    fprintf(ctx->fp, ",%u,%.6f,%.6f,%.6f,%.6f,%.6f,%lu,%lu,%lu\n",
            category_id,
            (double)flow->detecting_time_ns_total / 1e6,
            (double)flow->detecting_detection_time_ns_total / 1e6,
            (double)flow->post_time_ns_total / 1e6,
            (double)flow->post_detection_time_ns_total / 1e6,
            (double)(flow->detecting_time_ns_total + flow->post_time_ns_total) / 1e6,
            (unsigned long)flow->detection_packet_in_flow,
            (unsigned long)flow->seen_packets,
            (unsigned long)(flow->c2s_bytes + flow->s2c_bytes));
    return;
  }

  fprintf(ctx->fp,
          "%lu,%u,%u,%u,%u,%u,",
          (unsigned long)ctx->index,
          (unsigned)flow->signature_ip_version,
          (unsigned)flow->signature_l4_proto,
          (unsigned)flow->signature_server_port,
          (unsigned)flow->signature_server_port,
          (unsigned)flow->signature_payload_prefix_len);
  csv_write_escaped(ctx->fp, prefix_1_hex);
  fputc(',', ctx->fp);
  csv_write_escaped(ctx->fp, prefix_2_hex);
  fputc(',', ctx->fp);
  csv_write_escaped(ctx->fp, prefix_4_hex);
  fprintf(ctx->fp, ",0,");
  csv_write_escaped(ctx->fp, proto_name);
  fprintf(ctx->fp, ",%u,%u,", master_proto, app_proto);
  csv_write_escaped(ctx->fp, cat_name);
  fprintf(ctx->fp, ",%u,%.6f,%.6f,%.6f,%.6f,%.6f,%lu,%lu,%lu\n",
          category_id,
          (double)flow->detecting_time_ns_total / 1e6,
          (double)flow->detecting_detection_time_ns_total / 1e6,
          (double)flow->post_time_ns_total / 1e6,
          (double)flow->post_detection_time_ns_total / 1e6,
          (double)(flow->detecting_time_ns_total + flow->post_time_ns_total) / 1e6,
          (unsigned long)flow->detection_packet_in_flow,
          (unsigned long)flow->seen_packets,
          (unsigned long)(flow->c2s_bytes + flow->s2c_bytes));
}

static bool write_flow_profile_csv(const char *csv_path,
                                   struct ndpi_detection_module_struct *ndpi,
                                   struct flow_table *flows) {
  FILE *fp = fopen(csv_path, "w");
  if (!fp) return false;

  fprintf(fp, "flow_id,ip_version,l4_proto,server_port,dst_port,payload_prefix_len,prefix_1,prefix_2,prefix_4,protocol_detected,protocol,master_proto,app_proto,category_name,category_id,detecting_cost_ms,detecting_detection_only_ms,post_cost_ms,post_detection_only_ms,flow_total_ms,detect_pkt_in_flow,packets_in_flow,bytes_in_flow\n");

  flow_profile_ctx_t ctx = {
      .fp = fp,
      .ndpi = ndpi,
      .index = 0,
  };
  flow_table_foreach(flows, write_flow_profile_cb, &ctx);

  fclose(fp);
  return true;
}

static void print_flow_cb(bench_flow_t *flow, void *user) {
  print_ctx_t *ctx = (print_ctx_t *)user;
  ctx->index++;

  char client[128], server[128], prefix_hex[2 * PREFIX_BYTES + 1] = {0};
  endpoint_to_string(&flow->client, client, sizeof(client));
  endpoint_to_string(&flow->server, server, sizeof(server));
  prefix_to_hex(flow->signature_payload_prefix_u32, flow->signature_payload_prefix_len,
                prefix_hex, sizeof(prefix_hex));

  ndpi_master_app_protocol proto = {0};
  proto.master_protocol = flow->detected_master_proto;
  proto.app_protocol = flow->detected_app_proto;

  char proto_name[64] = {0};
  ndpi_protocol2name(ctx->ndpi, proto, proto_name, (u_int)sizeof(proto_name));

  double detecting_ms = (double)flow->detecting_time_ns_total / 1e6;
  double post_ms = (double)flow->post_time_ns_total / 1e6;
  double total_ms = (double)(flow->detecting_time_ns_total + flow->post_time_ns_total) / 1e6;

  if (flow->protocol_counted) {
    printf("Flow #%lu | %s <-> %s | sig=(ip=%u l4=%u port=%u prefix=%s len=%u) | proto=%s | category=%s | flow_detecting=%.3f ms | flow_post=%.3f ms | flow_total=%.3f ms | detect_pkt(flow)=%lu\n",
           (unsigned long)ctx->index,
           client,
           server,
           (unsigned)flow->signature_ip_version,
           (unsigned)flow->signature_l4_proto,
           (unsigned)flow->signature_server_port,
           prefix_hex,
           (unsigned)flow->signature_payload_prefix_len,
           proto_name[0] ? proto_name : "(unknown)",
           category_name(ctx->ndpi, flow->detected_category),
           detecting_ms,
           post_ms,
           total_ms,
           (unsigned long)flow->detection_packet_in_flow);
  } else {
    printf("Flow #%lu | %s <-> %s | sig=(ip=%u l4=%u port=%u prefix=%s len=%u) | proto=(NOT_DETECTED) | flow_detecting=%.3f ms | flow_post=%.3f ms | flow_total=%.3f ms\n",
           (unsigned long)ctx->index,
           client,
           server,
           (unsigned)flow->signature_ip_version,
           (unsigned)flow->signature_l4_proto,
           (unsigned)flow->signature_server_port,
           prefix_hex,
           (unsigned)flow->signature_payload_prefix_len,
           detecting_ms,
           post_ms,
           total_ms);
  }
}

int main(int argc, char **argv) {
  benchmark_config_t cfg = parse_args(argc, argv);
  char run_ts[32] = {0};
  char run_dir[PATH_MAX] = {0};
  char signature_csv_path[PATH_MAX] = {0};
  char flow_csv_path[PATH_MAX] = {0};

  make_timestamp(run_ts, sizeof(run_ts));
  snprintf(run_dir, sizeof(run_dir), "%s/%s", cfg.output_root, run_ts);
  snprintf(signature_csv_path, sizeof(signature_csv_path), "%s/first_packet_signature_summary.csv", run_dir);
  snprintf(flow_csv_path, sizeof(flow_csv_path), "%s/flow_profile.csv", run_dir);
  if (!mkdir_p(run_dir)) {
    fprintf(stderr, "Error: cannot create output directory: %s\n", run_dir);
    return 1;
  }

  if (cfg.cpu_core != UINT32_MAX) {
    set_thread_affinity(cfg.cpu_core);
  }

  printf("========================================\n");
  printf("ndpiBenchmarkMark5 (First-Packet Signature Profiler)\n");
  printf("========================================\n");
  printf("PCAP: %s\n\n", cfg.pcap_file);
  printf("Output: %s\n\n", run_dir);

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

  while (1) {
    uint64_t t_read0 = get_time_ns();
    int rc = pcap_next_ex(pc, &hdr, &pkt);
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
        stats.process_ns += (get_time_ns() - t_proc0);
        continue;
      }

      parsed_packet_t pp;
      if (parse_ethernet_frame(norm_data, norm_caplen, &pp) != PARSE_OK) {
        stats.parse_fail_packets++;
        stats.process_ns += (get_time_ns() - t_proc0);
        continue;
      }
      stats.parse_ok_packets++;

      flow_key_t key;
      endpoint_t src_ep, dst_ep;
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
        init_signature_from_first_packet(flow, &pp, &dst_ep);

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
      bool was_detected_before_packet = flow->protocol_counted;

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
      uint64_t t_detect0 = get_time_ns();
      (void)ndpi_detection_process_packet(ndpi,
                                          flow->ndpi_flow,
                                          pp.l3,
                                          pp.l3_len,
                                          flow->last_seen_ms,
                                          &in);
      uint64_t t_detect1 = get_time_ns();
      uint64_t detection_cost_ns = t_detect1 - t_detect0;

      if (!flow->protocol_counted) {
        uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
        if (app != NDPI_PROTOCOL_UNKNOWN) {
          flow->protocol_counted = true;
          flow->detected_app_proto = app;
          flow->detected_master_proto = ndpi_get_flow_masterprotocol(flow->ndpi_flow);
          flow->detected_category = ndpi_get_flow_category(flow->ndpi_flow);
          flow->detection_packet_in_flow = flow->seen_packets;
          flow->detection_packet_global = stats.total_packets;
          stats.flows_detected++;
        }
      }

      uint64_t packet_cost_ns = get_time_ns() - t_proc0;
      if (was_detected_before_packet) {
        flow->post_time_ns_total += packet_cost_ns;
        flow->post_detection_time_ns_total += detection_cost_ns;
        flow->post_packets++;
        if (!sample_vec_push(&flow->post_packet_samples_ns, packet_cost_ns)) {
          fprintf(stderr, "Error: sample_vec_push(post) failed\n");
          pcap_close(pc);
          flow_table_destroy(flows, free_flow_cb, NULL);
          ndpi_exit_detection_module(ndpi);
          ndpi_global_deinit(g_ctx);
          return 1;
        }
      } else {
        flow->detecting_time_ns_total += packet_cost_ns;
        flow->detecting_detection_time_ns_total += detection_cost_ns;
        flow->detecting_packets++;
        if (!sample_vec_push(&flow->detecting_packet_samples_ns, packet_cost_ns)) {
          fprintf(stderr, "Error: sample_vec_push(detecting) failed\n");
          pcap_close(pc);
          flow_table_destroy(flows, free_flow_cb, NULL);
          ndpi_exit_detection_module(ndpi);
          ndpi_global_deinit(g_ctx);
          return 1;
        }
      }

      stats.process_ns += (get_time_ns() - t_proc0);
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
  double elapsed_sec = (wall_end_ns > wall_start_ns) ? (double)(wall_end_ns - wall_start_ns) / 1e9 : 0.0;

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
    printf("Per-flow Signature Details\n");
    printf("========================================\n");
    print_ctx_t pctx = {.ndpi = ndpi, .index = 0};
    flow_table_foreach(flows, print_flow_cb, &pctx);
  }

  signature_aggregate_ctx_t sig_ctx = {0};
  flow_table_foreach(flows, aggregate_signature_cb, &sig_ctx);
  if (sig_ctx.count > 1) {
    qsort(sig_ctx.items, sig_ctx.count, sizeof(signature_stat_t), signature_stat_cmp_desc);
  }
  for (size_t i = 0; i < sig_ctx.count; i++) {
    sample_vec_sort(&sig_ctx.items[i].total_flow_samples_ns);
    sample_vec_sort(&sig_ctx.items[i].detect_pkt_in_flow_samples);
  }

  printf("\n========================================\n");
  printf("First-Packet Signature Summary\n");
  printf("========================================\n");
  for (size_t i = 0; i < sig_ctx.count; i++) {
    const signature_stat_t *st = &sig_ctx.items[i];
    char prefix_hex[2 * PREFIX_BYTES + 1] = {0};
    prefix_to_hex(st->key.payload_prefix_u32, st->key.payload_prefix_len, prefix_hex, sizeof(prefix_hex));

    double avg_pkts_per_flow = (double)st->sum_flow_packets / (double)st->flow_count;
    double avg_bytes_per_flow = (double)st->sum_flow_bytes / (double)st->flow_count;
    double avg_detecting_ms = (double)st->sum_detecting_flow_ns / (double)st->flow_count / 1e6;
    double avg_post_ms = (double)st->sum_post_flow_ns / (double)st->flow_count / 1e6;
    double avg_total_ms = (double)st->sum_total_flow_ns / (double)st->flow_count / 1e6;
    double flow_total_p50_ms = (double)sample_vec_percentile_sorted(&st->total_flow_samples_ns, 50) / 1e6;
    double flow_total_p99_ms = (double)sample_vec_percentile_sorted(&st->total_flow_samples_ns, 99) / 1e6;
    double avg_detecting_detection_only_ms =
        (double)st->sum_detecting_detection_flow_ns / (double)st->flow_count / 1e6;
    double avg_post_detection_only_ms =
        (double)st->sum_post_detection_flow_ns / (double)st->flow_count / 1e6;
    double avg_detect_pkt_flow = st->detected_flow_count
                                     ? (double)st->sum_detect_pkt_in_flow / (double)st->detected_flow_count
                                     : 0.0;
    double detect_pkt_flow_p50 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 50);
    double detect_pkt_flow_p99 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 99);

    const label_stat_t *best = dominant_label(st);
    char proto_name[64] = {0};
    const char *cat_name = "(none)";
    double purity = 0.0;
    unsigned master_proto = 0;
    unsigned app_proto = 0;
    unsigned category_id = 0;
    if (best) {
      ndpi_master_app_protocol proto = {0};
      proto.master_protocol = best->master_proto;
      proto.app_protocol = best->app_proto;
      ndpi_protocol2name(ndpi, proto, proto_name, (u_int)sizeof(proto_name));
      cat_name = category_name(ndpi, best->category);
      purity = st->detected_flow_count ? (double)best->flow_count / (double)st->detected_flow_count : 0.0;
      master_proto = best->master_proto;
      app_proto = best->app_proto;
      category_id = (unsigned)best->category;
    }

    printf("Sig=(ip=%u l4=%u port=%u prefix=%s len=%u) | flows=%lu | detected=%lu | avg_pkts=%.2f | avg_bytes=%.2f | avg_total=%.3f ms | total_p50=%.3f ms | total_p99=%.3f ms | avg_detecting=%.3f ms | avg_post=%.3f ms | avg_detecting_detection_only=%.3f ms | avg_post_detection_only=%.3f ms | avg_detect_pkt(flow)=%.2f | detect_pkt_p50=%.0f | detect_pkt_p99=%.0f | dominant_proto=%s (%u/%u) | dominant_category=%s (%u) | purity=%.2f%%\n",
           (unsigned)st->key.ip_version,
           (unsigned)st->key.l4_proto,
           (unsigned)st->key.server_port,
           prefix_hex,
           (unsigned)st->key.payload_prefix_len,
           (unsigned long)st->flow_count,
           (unsigned long)st->detected_flow_count,
           avg_pkts_per_flow,
           avg_bytes_per_flow,
           avg_total_ms,
           flow_total_p50_ms,
           flow_total_p99_ms,
           avg_detecting_ms,
           avg_post_ms,
           avg_detecting_detection_only_ms,
           avg_post_detection_only_ms,
           avg_detect_pkt_flow,
           detect_pkt_flow_p50,
           detect_pkt_flow_p99,
           proto_name[0] ? proto_name : "(none)",
           master_proto,
           app_proto,
           cat_name,
           category_id,
           purity * 100.0);
  }

  if (write_flow_profile_csv(flow_csv_path, ndpi, flows)) {
    printf("\nFlow CSV saved: %s\n", flow_csv_path);
  } else {
    fprintf(stderr, "\nWarning: failed to write flow CSV: %s\n", flow_csv_path);
  }

  if (write_signature_summary_csv(signature_csv_path, &stats, ndpi, sig_ctx.items, sig_ctx.count)) {
    printf("Signature CSV saved: %s\n", signature_csv_path);
  } else {
    fprintf(stderr, "Warning: failed to write signature CSV: %s\n", signature_csv_path);
  }

  for (size_t i = 0; i < sig_ctx.count; i++) {
    sample_vec_free(&sig_ctx.items[i].total_flow_samples_ns);
    sample_vec_free(&sig_ctx.items[i].detect_pkt_in_flow_samples);
    free(sig_ctx.items[i].labels);
  }
  free(sig_ctx.items);

  pcap_close(pc);
  flow_table_destroy(flows, free_flow_cb, NULL);
  ndpi_exit_detection_module(ndpi);
  ndpi_global_deinit(g_ctx);
  return 0;
}
