#include "benchmark_internal.h"
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/*
 * mark4/src/main.c
 *
 * 核心定位：单线程直读版本。
 * - 不使用 reader/worker 队列，也不做 dispatcher 分发
 * - 直接在一个循环里完成读包、解析、flow 状态推进、nDPI 识别
 * - 结束后遍历 flow 表做汇总输出与 CSV 落盘
 */

/*
 * ==============================
 * mark4 main 详细时序说明
 * ==============================
 *
 * mark4 的执行可以拆成 6 个阶段：
 *
 * 阶段 1：参数与输出目录准备
 * - 解析输入 pcap、可选 core 绑定、输出目录
 * - 生成时间戳目录 output/<timestamp>，避免覆盖旧结果
 *
 * 阶段 2：nDPI 初始化
 * - ndpi_global_init 创建全局上下文
 * - ndpi_init_detection_module 创建本次运行唯一 detection module
 * - 可选加载 proto 文件，最后 finalize
 *
 * 阶段 3：flow 状态容器初始化
 * - flow_table_create 建立 flow_key -> bench_flow_t 映射
 * - 所有包共享这张表，结束后统一遍历汇总
 *
 * 阶段 4：单线程读包主循环（核心）
 * 对每个包执行：
 * 1) pcap_next_ex
 * 2) normalize_to_ethernet
 * 3) parse_ethernet_frame
 * 4) flow_key_from_packet + flow_table_get_or_create
 * 5) ndpi_detection_process_packet
 * 6) 首次识别成功时记录检测时延/包位置
 *
 * 阶段 5：结束后聚合统计
 * - 基础吞吐/流识别统计
 * - 可选 per-flow 明细打印
 * - category 汇总
 * - proto+category 汇总并排序
 * - 写 CSV
 *
 * 阶段 6：资源释放
 * - pcap_close
 * - flow_table_destroy（连带释放 ndpi_flow）
 * - ndpi module/global deinit
 *
 * 你在讲解时可以强调：
 * - mark4 代码路径短、行为确定，适合作为准确性/延迟基线
 * - mark3 复杂并行结构的对照组就是 mark4
 */

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
  uint64_t sum_flow_packets;
  uint64_t sum_flow_bytes;
  uint64_t sum_detecting_flow_ns;
  uint64_t sum_post_flow_ns;
  uint64_t sum_detecting_detection_flow_ns;
  uint64_t sum_post_detection_flow_ns;
  uint64_t sum_total_flow_ns;
  long double sumsq_detecting_flow_ns;
  long double sumsq_total_flow_ns;
  uint64_t sum_detecting_packet_ns;
  uint64_t sum_post_packet_ns;
  uint64_t sum_detecting_packets;
  uint64_t sum_post_packets;
  uint64_t sum_detect_pkt_in_flow;
  uint64_t sum_detect_pkt_global;
  sample_vec_t detect_pkt_in_flow_samples;
} category_stat_t;

typedef struct {
  uint16_t master_proto;
  uint16_t app_proto;
  ndpi_protocol_category_t category;
  uint64_t flow_count;
  uint64_t sum_flow_packets;
  uint64_t sum_flow_bytes;
  uint64_t sum_detecting_flow_ns;
  uint64_t sum_post_flow_ns;
  uint64_t sum_detecting_detection_flow_ns;
  uint64_t sum_post_detection_flow_ns;
  uint64_t sum_total_flow_ns;
  long double sumsq_detecting_flow_ns;
  long double sumsq_total_flow_ns;
  uint64_t sum_detecting_packet_ns;
  uint64_t sum_post_packet_ns;
  uint64_t sum_detecting_packets;
  uint64_t sum_post_packets;
  uint64_t sum_detect_pkt_in_flow;
  uint64_t sum_detect_pkt_global;
  sample_vec_t detecting_packet_samples_ns;
  sample_vec_t post_packet_samples_ns;
  sample_vec_t detect_pkt_in_flow_samples;
} proto_stat_t;

typedef struct {
  struct ndpi_detection_module_struct *ndpi;
  category_stat_t *cat_stats;
} aggregate_ctx_t;

typedef struct {
  proto_stat_t *items;
  size_t count;
  size_t cap;
} proto_aggregate_ctx_t;

typedef struct {
  struct ndpi_detection_module_struct *ndpi;
  uint64_t index;
} print_ctx_t;

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

static bool sample_vec_append(sample_vec_t *dst, const sample_vec_t *src) {
  if (!dst || !src || src->count == 0) return true;
  size_t old_count = dst->count;
  if (!sample_vec_grow(dst, dst->count + src->count)) return false;
  memcpy(dst->items + old_count, src->items, src->count * sizeof(uint64_t));
  dst->count += src->count;
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
  printf("%s - mark4 single-worker direct pcap reader\n\n", prog);
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
  /* 解析运行参数，形成单线程版本的配置对象。 */
  benchmark_config_t cfg;
  memset(&cfg, 0, sizeof(cfg));
  cfg.cpu_core = UINT32_MAX;
  cfg.output_root = "output";

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

static int proto_stat_cmp_desc(const void *a, const void *b) {
  const proto_stat_t *pa = (const proto_stat_t *)a;
  const proto_stat_t *pb = (const proto_stat_t *)b;
  if (pa->flow_count < pb->flow_count) return 1;
  if (pa->flow_count > pb->flow_count) return -1;
  if (pa->app_proto < pb->app_proto) return -1;
  if (pa->app_proto > pb->app_proto) return 1;
  if (pa->master_proto < pb->master_proto) return -1;
  if (pa->master_proto > pb->master_proto) return 1;
  return 0;
}

static bool proto_stats_grow(proto_aggregate_ctx_t *ctx) {
  if (!ctx) return false;
  if (ctx->count < ctx->cap) return true;
  size_t new_cap = (ctx->cap == 0) ? 16 : (ctx->cap * 2);
  proto_stat_t *new_items = (proto_stat_t *)realloc(ctx->items, new_cap * sizeof(proto_stat_t));
  if (!new_items) return false;
  ctx->items = new_items;
  ctx->cap = new_cap;
  return true;
}

static double variance_from_sums(uint64_t count, uint64_t sum_ns, long double sumsq_ns) {
  if (count == 0) return 0.0;
  long double mean_ns = (long double)sum_ns / (long double)count;
  long double mean_sq_ns = sumsq_ns / (long double)count;
  long double var_ns2 = mean_sq_ns - mean_ns * mean_ns;
  if (var_ns2 < 0) var_ns2 = 0;
  return (double)(var_ns2 / 1e12L);
}

static void aggregate_proto_cb(bench_flow_t *flow, void *user) {
  proto_aggregate_ctx_t *ctx = (proto_aggregate_ctx_t *)user;
  if (!flow || !ctx || !flow->protocol_counted) return;

  uint64_t flow_total_ns = flow->detecting_time_ns_total + flow->post_time_ns_total;
  uint64_t flow_bytes = flow->c2s_bytes + flow->s2c_bytes;

  for (size_t i = 0; i < ctx->count; i++) {
    proto_stat_t *st = &ctx->items[i];
    if (st->master_proto == flow->detected_master_proto &&
        st->app_proto == flow->detected_app_proto &&
        st->category == flow->detected_category) {
      st->flow_count++;
      st->sum_flow_packets += flow->seen_packets;
      st->sum_flow_bytes += flow_bytes;
      st->sum_detecting_flow_ns += flow->detecting_time_ns_total;
      st->sum_post_flow_ns += flow->post_time_ns_total;
      st->sum_detecting_detection_flow_ns += flow->detecting_detection_time_ns_total;
      st->sum_post_detection_flow_ns += flow->post_detection_time_ns_total;
      st->sum_total_flow_ns += flow_total_ns;
      st->sumsq_detecting_flow_ns += (long double)flow->detecting_time_ns_total * (long double)flow->detecting_time_ns_total;
      st->sumsq_total_flow_ns += (long double)flow_total_ns * (long double)flow_total_ns;
      st->sum_detecting_packet_ns += flow->detecting_time_ns_total;
      st->sum_post_packet_ns += flow->post_time_ns_total;
      st->sum_detecting_packets += flow->detecting_packets;
      st->sum_post_packets += flow->post_packets;
      st->sum_detect_pkt_in_flow += flow->detection_packet_in_flow;
      st->sum_detect_pkt_global += flow->detection_packet_global;
      (void)sample_vec_append(&st->detecting_packet_samples_ns, &flow->detecting_packet_samples_ns);
      (void)sample_vec_append(&st->post_packet_samples_ns, &flow->post_packet_samples_ns);
      if (flow->detection_packet_in_flow > 0) {
        (void)sample_vec_push(&st->detect_pkt_in_flow_samples, flow->detection_packet_in_flow);
      }
      return;
    }
  }

  if (!proto_stats_grow(ctx)) return;
  proto_stat_t *dst = &ctx->items[ctx->count++];
  memset(dst, 0, sizeof(*dst));
  dst->master_proto = flow->detected_master_proto;
  dst->app_proto = flow->detected_app_proto;
  dst->category = flow->detected_category;
  dst->flow_count = 1;
  dst->sum_flow_packets = flow->seen_packets;
  dst->sum_flow_bytes = flow_bytes;
  dst->sum_detecting_flow_ns = flow->detecting_time_ns_total;
  dst->sum_post_flow_ns = flow->post_time_ns_total;
  dst->sum_detecting_detection_flow_ns = flow->detecting_detection_time_ns_total;
  dst->sum_post_detection_flow_ns = flow->post_detection_time_ns_total;
  dst->sum_total_flow_ns = flow_total_ns;
  dst->sumsq_detecting_flow_ns = (long double)flow->detecting_time_ns_total * (long double)flow->detecting_time_ns_total;
  dst->sumsq_total_flow_ns = (long double)flow_total_ns * (long double)flow_total_ns;
  dst->sum_detecting_packet_ns = flow->detecting_time_ns_total;
  dst->sum_post_packet_ns = flow->post_time_ns_total;
  dst->sum_detecting_packets = flow->detecting_packets;
  dst->sum_post_packets = flow->post_packets;
  dst->sum_detect_pkt_in_flow = flow->detection_packet_in_flow;
  dst->sum_detect_pkt_global = flow->detection_packet_global;
  (void)sample_vec_append(&dst->detecting_packet_samples_ns, &flow->detecting_packet_samples_ns);
  (void)sample_vec_append(&dst->post_packet_samples_ns, &flow->post_packet_samples_ns);
  if (flow->detection_packet_in_flow > 0) {
    (void)sample_vec_push(&dst->detect_pkt_in_flow_samples, flow->detection_packet_in_flow);
  }
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

static bool write_proto_summary_csv(const char *csv_path,
                                    const benchmark_stats_t *summary,
                                    struct ndpi_detection_module_struct *ndpi,
                                    const proto_stat_t *stats,
                                    size_t count) {
  /* CSV 列是“可分析字段”而不是原始内部字段：
   * - 协议名 + master/app id
   * - category 名称/id
   * - 流数与平均检测延迟/检测包位次
   */
  FILE *fp = fopen(csv_path, "w");
  if (!fp) return false;

  if (summary) {
    fprintf(fp, "# summary_key,summary_value\n");
    fprintf(fp, "# Total packets,%lu\n", (unsigned long)summary->total_packets);
    fprintf(fp, "# Total bytes,%lu\n", (unsigned long)summary->total_bytes);
    fprintf(fp, "# Parse-ok packets,%lu\n", (unsigned long)summary->parse_ok_packets);
    fprintf(fp, "# Parse-fail packets,%lu\n", (unsigned long)summary->parse_fail_packets);
    fprintf(fp, "# Normalize-fail packets,%lu\n", (unsigned long)summary->normalize_fail_packets);
    fprintf(fp, "\n");
  }

  fprintf(fp, "proto_name,master_proto,app_proto,category_name,category_id,flows,avg_pkts_per_flow,avg_bytes_per_flow,avg_flow_detecting_ms,var_flow_detecting_ms2,avg_flow_post_ms,avg_flow_total_ms,var_flow_total_ms2,avg_flow_detecting_detection_only_ms,avg_flow_post_detection_only_ms,detecting_pkt_mean_us,detecting_pkt_p50_us,detecting_pkt_p99_us,post_pkt_mean_us,post_pkt_p50_us,post_pkt_p99_us,avg_detect_pkt_flow,detect_pkt_flow_p50,detect_pkt_flow_p99,avg_detect_pkt_global\n");
  for (size_t i = 0; i < count; i++) {
    const proto_stat_t *st = &stats[i];
    if (st->flow_count == 0) continue;

    ndpi_master_app_protocol proto = {0};
    proto.master_protocol = st->master_proto;
    proto.app_protocol = st->app_proto;

    char proto_name[64] = {0};
    ndpi_protocol2name(ndpi, proto, proto_name, (u_int)sizeof(proto_name));

    const char *cat_name = category_name(ndpi, st->category);
    double avg_pkts_per_flow = (double)st->sum_flow_packets / (double)st->flow_count;
    double avg_bytes_per_flow = (double)st->sum_flow_bytes / (double)st->flow_count;
    double avg_detecting_ms = (double)st->sum_detecting_flow_ns / (double)st->flow_count / 1e6;
    double var_detecting_ms2 = variance_from_sums(st->flow_count, st->sum_detecting_flow_ns, st->sumsq_detecting_flow_ns);
    double avg_post_ms = (double)st->sum_post_flow_ns / (double)st->flow_count / 1e6;
    double avg_total_ms = (double)st->sum_total_flow_ns / (double)st->flow_count / 1e6;
    double var_total_ms2 = variance_from_sums(st->flow_count, st->sum_total_flow_ns, st->sumsq_total_flow_ns);
    double avg_detecting_detection_only_ms = (double)st->sum_detecting_detection_flow_ns / (double)st->flow_count / 1e6;
    double avg_post_detection_only_ms = (double)st->sum_post_detection_flow_ns / (double)st->flow_count / 1e6;
    double detecting_mean_us = st->sum_detecting_packets
                                   ? ((double)st->sum_detecting_packet_ns / (double)st->sum_detecting_packets / 1e3)
                                   : 0.0;
    double post_mean_us = st->sum_post_packets
                              ? ((double)st->sum_post_packet_ns / (double)st->sum_post_packets / 1e3)
                              : 0.0;
    double avg_pkt_flow = (double)st->sum_detect_pkt_in_flow / (double)st->flow_count;
    double avg_pkt_global = (double)st->sum_detect_pkt_global / (double)st->flow_count;
    double detect_pkt_flow_p50 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 50);
    double detect_pkt_flow_p99 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 99);
    double detecting_p50_us = (double)sample_vec_percentile_sorted(&st->detecting_packet_samples_ns, 50) / 1e3;
    double detecting_p99_us = (double)sample_vec_percentile_sorted(&st->detecting_packet_samples_ns, 99) / 1e3;
    double post_p50_us = (double)sample_vec_percentile_sorted(&st->post_packet_samples_ns, 50) / 1e3;
    double post_p99_us = (double)sample_vec_percentile_sorted(&st->post_packet_samples_ns, 99) / 1e3;

    csv_write_escaped(fp, proto_name[0] ? proto_name : "(unknown)");
    fprintf(fp, ",%u,%u,", (unsigned)st->master_proto, (unsigned)st->app_proto);
    csv_write_escaped(fp, cat_name);
    fprintf(fp, ",%u,%lu,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.3f,%.3f,%.3f,%.3f,%.3f,%.3f,%.6f,%.3f,%.3f,%.6f\n",
            (unsigned)st->category,
            (unsigned long)st->flow_count,
            avg_pkts_per_flow,
            avg_bytes_per_flow,
            avg_detecting_ms,
            var_detecting_ms2,
            avg_post_ms,
            avg_total_ms,
            var_total_ms2,
            avg_detecting_detection_only_ms,
            avg_post_detection_only_ms,
            detecting_mean_us,
            detecting_p50_us,
            detecting_p99_us,
            post_mean_us,
            post_p50_us,
            post_p99_us,
            avg_pkt_flow,
            detect_pkt_flow_p50,
            detect_pkt_flow_p99,
            avg_pkt_global);
  }

  fclose(fp);
  return true;
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

  double detecting_ms = (double)flow->detecting_time_ns_total / 1e6;
  double post_ms = (double)flow->post_time_ns_total / 1e6;
  double total_ms = (double)(flow->detecting_time_ns_total + flow->post_time_ns_total) / 1e6;
  double detecting_detection_ms = (double)flow->detecting_detection_time_ns_total / 1e6;
  double post_detection_ms = (double)flow->post_detection_time_ns_total / 1e6;

  if (flow->protocol_counted) {
    printf("Flow #%lu | %s <-> %s | proto=%s | category=%s | flow_detecting=%.3f ms | flow_post=%.3f ms | flow_total=%.3f ms | detection_only_detecting=%.3f ms | detection_only_post=%.3f ms | detect_pkt(flow)=%lu | detect_pkt(global)=%lu\n",
           (unsigned long)ctx->index,
           client,
           server,
           proto_name[0] ? proto_name : "(unknown)",
           category_name(ctx->ndpi, flow->detected_category),
           detecting_ms,
           post_ms,
           total_ms,
           detecting_detection_ms,
           post_detection_ms,
           (unsigned long)flow->detection_packet_in_flow,
           (unsigned long)flow->detection_packet_global);
  } else {
    printf("Flow #%lu | %s <-> %s | proto=(NOT_DETECTED) | category=(NOT_DETECTED) | flow_detecting=%.3f ms | flow_post=%.3f ms | flow_total=%.3f ms | detection_only_detecting=%.3f ms | detection_only_post=%.3f ms | detect_pkt(flow)=N/A | detect_pkt(global)=N/A\n",
           (unsigned long)ctx->index,
           client,
           server,
           detecting_ms,
           post_ms,
           total_ms,
           detecting_detection_ms,
           post_detection_ms);
  }
}

static void aggregate_category_cb(bench_flow_t *flow, void *user) {
  aggregate_ctx_t *ctx = (aggregate_ctx_t *)user;
  if (!flow->protocol_counted) return;

  uint32_t idx = (uint32_t)flow->detected_category;
  if (idx >= CATEGORY_BUCKETS) return;

  category_stat_t *st = &ctx->cat_stats[idx];
  uint64_t flow_total_ns = flow->detecting_time_ns_total + flow->post_time_ns_total;
  uint64_t flow_bytes = flow->c2s_bytes + flow->s2c_bytes;
  st->used = true;
  st->category = flow->detected_category;
  st->flow_count++;
  st->sum_flow_packets += flow->seen_packets;
  st->sum_flow_bytes += flow_bytes;
  st->sum_detecting_flow_ns += flow->detecting_time_ns_total;
  st->sum_post_flow_ns += flow->post_time_ns_total;
  st->sum_detecting_detection_flow_ns += flow->detecting_detection_time_ns_total;
  st->sum_post_detection_flow_ns += flow->post_detection_time_ns_total;
  st->sum_total_flow_ns += flow_total_ns;
  st->sumsq_detecting_flow_ns += (long double)flow->detecting_time_ns_total * (long double)flow->detecting_time_ns_total;
  st->sumsq_total_flow_ns += (long double)flow_total_ns * (long double)flow_total_ns;
  st->sum_detecting_packet_ns += flow->detecting_time_ns_total;
  st->sum_post_packet_ns += flow->post_time_ns_total;
  st->sum_detecting_packets += flow->detecting_packets;
  st->sum_post_packets += flow->post_packets;
  st->sum_detect_pkt_in_flow += flow->detection_packet_in_flow;
  st->sum_detect_pkt_global += flow->detection_packet_global;
  if (flow->detection_packet_in_flow > 0) {
    (void)sample_vec_push(&st->detect_pkt_in_flow_samples, flow->detection_packet_in_flow);
  }
}

int main(int argc, char **argv) {
  /* 0) 初始化运行目录与可选绑核。 */
  benchmark_config_t cfg = parse_args(argc, argv);
  char run_ts[32] = {0};
  char run_dir[PATH_MAX] = {0};
  char csv_path[PATH_MAX] = {0};

  make_timestamp(run_ts, sizeof(run_ts));
  snprintf(run_dir, sizeof(run_dir), "%s/%s", cfg.output_root, run_ts);
  snprintf(csv_path, sizeof(csv_path), "%s/proto_category_summary.csv", run_dir);
  /* 每次运行固定写入 output/<timestamp>/，避免覆盖历史结果。 */
  if (!mkdir_p(run_dir)) {
    fprintf(stderr, "Error: cannot create output directory: %s\n", run_dir);
    return 1;
  }

  if (cfg.cpu_core != UINT32_MAX) {
    /* 单线程版本也支持绑核，便于减少调度抖动。 */
    set_thread_affinity(cfg.cpu_core);
  }

  printf("========================================\n");
  printf("ndpiBenchmarkMark4 (Single Worker Direct Reader)\n");
  printf("========================================\n");
  printf("PCAP: %s\n\n", cfg.pcap_file);
  printf("Output: %s\n\n", run_dir);

  /* 1) 初始化 nDPI。 */
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

  /* 2) 创建 flow 状态表（所有包共享同一张表）。 */
  struct flow_table *flows = flow_table_create(16384);
  if (!flows) {
    fprintf(stderr, "Error: flow_table_create() failed\n");
    ndpi_exit_detection_module(ndpi);
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  /* 3) 打开 pcap，开始单线程主循环。 */
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

  /* 主处理路径（单线程）：
   * 1) 从 pcap 逐包读取
   * 2) 标准化链路层并解析五元组
   * 3) 在 flow table 中查找/创建流状态
   * 4) 调用 nDPI 推进协议识别
   * 5) 在“首次识别成功”时记录检测时延和包位置
   */
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
      /* 收到一个有效包，进入完整处理路径。 */
      stats.total_packets++;
      stats.total_bytes += hdr->len;

      uint64_t t_proc0 = get_time_ns();

      /* 把多种链路层输入统一成 Ethernet 视图，后续解析分支更少。 */
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
        /* 标准化失败：记录统计并跳过该包。 */
        stats.normalize_fail_packets++;
        uint64_t t_proc1 = get_time_ns();
        stats.process_ns += (t_proc1 - t_proc0);
        continue;
      }

      parsed_packet_t pp;
      /* 解析 L3/L4 关键字段（IP/端口/协议号）供 flow key 和 nDPI 使用。 */
      if (parse_ethernet_frame(norm_data, norm_caplen, &pp) != PARSE_OK) {
        /* L3/L4 解析失败：记录统计并跳过该包。 */
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
      /* flow_key 是双向 canonical key，保证双向包聚合到同一 flow。 */

      uint64_t h = flow_key_hash(&key);
      bool is_new = false;
      /* flow table 保存每条流的累计统计和 nDPI flow 状态。 */
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
        /* 首次出现该 flow：初始化方向端点与 nDPI 流状态。 */
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
      bool was_detected_before_packet = flow->protocol_counted;
      /* 与 mark3 一样，方向由“首包定义 client”规则确定。 */
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
      /* 把当前包喂给 nDPI，识别结果写回 flow->ndpi_flow 内部状态。 */
      uint64_t t_detect0 = get_time_ns();
      (void)ndpi_detection_process_packet(ndpi,
                                          flow->ndpi_flow,
                                          pp.l3,
                                          pp.l3_len,
                                          flow->last_seen_ms,
                                          &in);
      uint64_t t_detect1 = get_time_ns();
      uint64_t detection_cost_ns = t_detect1 - t_detect0;
      /* nDPI 识别不是一次完成，通常需要同流多个包逐步收敛。 */

      if (!flow->protocol_counted) {
        uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
        if (app != NDPI_PROTOCOL_UNKNOWN) {
          /* 只在第一次识别成功时计数，避免同一 flow 重复累加统计。 */
          flow->protocol_counted = true;
          flow->detected_app_proto = app;
          flow->detected_master_proto = ndpi_get_flow_masterprotocol(flow->ndpi_flow);
          flow->detected_category = ndpi_get_flow_category(flow->ndpi_flow);
          flow->detection_packet_in_flow = flow->seen_packets;  /* 第几个同流包识别成功 */
          flow->detection_packet_global = stats.total_packets;
          stats.flows_detected++;
        }
      }

      uint64_t t_proc1 = get_time_ns();
      uint64_t packet_cost_ns = t_proc1 - t_proc0;
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
      stats.process_ns += (t_proc1 - t_proc0);
    } else if (rc == -2) {
      /* EOF：正常结束。 */
      break;
    } else if (rc == 0) {
      /* 超时/暂时无数据（离线 pcap 通常较少见），继续轮询。 */
      continue;
    } else {
      /* 读取错误：打印错误并失败退出。 */
      fprintf(stderr, "Error: pcap_next_ex() failed: %s\n", pcap_geterr(pc));
      pcap_close(pc);
      flow_table_destroy(flows, free_flow_cb, NULL);
      ndpi_exit_detection_module(ndpi);
      ndpi_global_deinit(g_ctx);
      return 1;
    }
  }

  /* 4) 处理结束后做多维汇总输出。 */
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
  /* 第一轮聚合：按 category 汇总。 */
  flow_table_foreach(flows, aggregate_category_cb, &actx);
  /* 第一轮聚合按 category，观察业务类型分布。 */

  printf("\n========================================\n");
  printf("Category Summary (Detected Flows)\n");
  printf("========================================\n");
  for (uint32_t i = 0; i < CATEGORY_BUCKETS; i++) {
    if (!cat_stats[i].used || cat_stats[i].flow_count == 0) continue;
    double avg_pkts_per_flow = (double)cat_stats[i].sum_flow_packets / (double)cat_stats[i].flow_count;
    double avg_bytes_per_flow = (double)cat_stats[i].sum_flow_bytes / (double)cat_stats[i].flow_count;
    double avg_detecting_ms = (double)cat_stats[i].sum_detecting_flow_ns / (double)cat_stats[i].flow_count / 1e6;
    double var_detecting_ms2 = variance_from_sums(cat_stats[i].flow_count, cat_stats[i].sum_detecting_flow_ns, cat_stats[i].sumsq_detecting_flow_ns);
    double avg_post_ms = (double)cat_stats[i].sum_post_flow_ns / (double)cat_stats[i].flow_count / 1e6;
    double avg_total_ms = (double)cat_stats[i].sum_total_flow_ns / (double)cat_stats[i].flow_count / 1e6;
    double var_total_ms2 = variance_from_sums(cat_stats[i].flow_count, cat_stats[i].sum_total_flow_ns, cat_stats[i].sumsq_total_flow_ns);
    double avg_detecting_detection_only_ms = (double)cat_stats[i].sum_detecting_detection_flow_ns / (double)cat_stats[i].flow_count / 1e6;
    double avg_post_detection_only_ms = (double)cat_stats[i].sum_post_detection_flow_ns / (double)cat_stats[i].flow_count / 1e6;
    double detecting_mean_us = cat_stats[i].sum_detecting_packets
                                   ? ((double)cat_stats[i].sum_detecting_packet_ns / (double)cat_stats[i].sum_detecting_packets / 1e3)
                                   : 0.0;
    double post_mean_us = cat_stats[i].sum_post_packets
                              ? ((double)cat_stats[i].sum_post_packet_ns / (double)cat_stats[i].sum_post_packets / 1e3)
                              : 0.0;
    double avg_pkt_flow = (double)cat_stats[i].sum_detect_pkt_in_flow / (double)cat_stats[i].flow_count;
    double detect_pkt_flow_p50 = (double)sample_vec_percentile_sorted(&cat_stats[i].detect_pkt_in_flow_samples, 50);
    double detect_pkt_flow_p99 = (double)sample_vec_percentile_sorted(&cat_stats[i].detect_pkt_in_flow_samples, 99);
    double avg_pkt_global = (double)cat_stats[i].sum_detect_pkt_global / (double)cat_stats[i].flow_count;

    printf("Category=%s (id=%u) | flows=%lu | avg_pkts_per_flow=%.2f | avg_bytes_per_flow=%.2f | avg_flow_detecting=%.3f ms | var_flow_detecting=%.6f ms^2 | avg_flow_post=%.3f ms | avg_flow_total=%.3f ms | var_flow_total=%.6f ms^2 | avg_flow_detecting_detection_only=%.3f ms | avg_flow_post_detection_only=%.3f ms | detecting_pkt_mean=%.3f us | post_pkt_mean=%.3f us | avg_detect_pkt(flow)=%.2f | detect_pkt_flow_p50=%.0f | detect_pkt_flow_p99=%.0f | avg_detect_pkt(global)=%.2f\n",
           category_name(ndpi, cat_stats[i].category),
           (unsigned)cat_stats[i].category,
           (unsigned long)cat_stats[i].flow_count,
           avg_pkts_per_flow,
           avg_bytes_per_flow,
           avg_detecting_ms,
           var_detecting_ms2,
           avg_post_ms,
           avg_total_ms,
           var_total_ms2,
           avg_detecting_detection_only_ms,
           avg_post_detection_only_ms,
           detecting_mean_us,
           post_mean_us,
           avg_pkt_flow,
           detect_pkt_flow_p50,
           detect_pkt_flow_p99,
           avg_pkt_global);
  }

  proto_aggregate_ctx_t proto_ctx = {0};
  /* 第二轮聚合：按 proto+category 汇总，并写入 CSV。 */
  flow_table_foreach(flows, aggregate_proto_cb, &proto_ctx);
  if (proto_ctx.count > 1) {
    qsort(proto_ctx.items, proto_ctx.count, sizeof(proto_stat_t), proto_stat_cmp_desc);
  }
  for (size_t i = 0; i < proto_ctx.count; i++) {
    sample_vec_sort(&proto_ctx.items[i].detecting_packet_samples_ns);
    sample_vec_sort(&proto_ctx.items[i].post_packet_samples_ns);
    sample_vec_sort(&proto_ctx.items[i].detect_pkt_in_flow_samples);
  }

  printf("\n========================================\n");
  printf("Proto+Category Summary (Detected Flows)\n");
  printf("========================================\n");
  for (size_t i = 0; i < proto_ctx.count; i++) {
    const proto_stat_t *st = &proto_ctx.items[i];
    if (st->flow_count == 0) continue;

    ndpi_master_app_protocol proto = {0};
    proto.master_protocol = st->master_proto;
    proto.app_protocol = st->app_proto;
    char proto_name[64] = {0};
    ndpi_protocol2name(ndpi, proto, proto_name, (u_int)sizeof(proto_name));

    double avg_pkts_per_flow = (double)st->sum_flow_packets / (double)st->flow_count;
    double avg_bytes_per_flow = (double)st->sum_flow_bytes / (double)st->flow_count;
    double avg_detecting_ms = (double)st->sum_detecting_flow_ns / (double)st->flow_count / 1e6;
    double var_detecting_ms2 = variance_from_sums(st->flow_count, st->sum_detecting_flow_ns, st->sumsq_detecting_flow_ns);
    double avg_post_ms = (double)st->sum_post_flow_ns / (double)st->flow_count / 1e6;
    double avg_total_ms = (double)st->sum_total_flow_ns / (double)st->flow_count / 1e6;
    double var_total_ms2 = variance_from_sums(st->flow_count, st->sum_total_flow_ns, st->sumsq_total_flow_ns);
    double avg_detecting_detection_only_ms = (double)st->sum_detecting_detection_flow_ns / (double)st->flow_count / 1e6;
    double avg_post_detection_only_ms = (double)st->sum_post_detection_flow_ns / (double)st->flow_count / 1e6;
    double detecting_mean_us = st->sum_detecting_packets
                                   ? ((double)st->sum_detecting_packet_ns / (double)st->sum_detecting_packets / 1e3)
                                   : 0.0;
    double post_mean_us = st->sum_post_packets
                              ? ((double)st->sum_post_packet_ns / (double)st->sum_post_packets / 1e3)
                              : 0.0;
    double detecting_p50_us = (double)sample_vec_percentile_sorted(&st->detecting_packet_samples_ns, 50) / 1e3;
    double detecting_p99_us = (double)sample_vec_percentile_sorted(&st->detecting_packet_samples_ns, 99) / 1e3;
    double post_p50_us = (double)sample_vec_percentile_sorted(&st->post_packet_samples_ns, 50) / 1e3;
    double post_p99_us = (double)sample_vec_percentile_sorted(&st->post_packet_samples_ns, 99) / 1e3;
    double avg_pkt_flow = (double)st->sum_detect_pkt_in_flow / (double)st->flow_count;
    double detect_pkt_flow_p50 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 50);
    double detect_pkt_flow_p99 = (double)sample_vec_percentile_sorted(&st->detect_pkt_in_flow_samples, 99);
    double avg_pkt_global = (double)st->sum_detect_pkt_global / (double)st->flow_count;
    printf("Proto=%s (master=%u app=%u) | Category=%s (id=%u) | flows=%lu | avg_pkts_per_flow=%.2f | avg_bytes_per_flow=%.2f | avg_flow_detecting=%.3f ms | var_flow_detecting=%.6f ms^2 | avg_flow_post=%.3f ms | avg_flow_total=%.3f ms | var_flow_total=%.6f ms^2 | avg_flow_detecting_detection_only=%.3f ms | avg_flow_post_detection_only=%.3f ms | detecting_pkt_mean=%.3f us | detecting_pkt_p50=%.3f us | detecting_pkt_p99=%.3f us | post_pkt_mean=%.3f us | post_pkt_p50=%.3f us | post_pkt_p99=%.3f us | avg_detect_pkt(flow)=%.2f | detect_pkt_flow_p50=%.0f | detect_pkt_flow_p99=%.0f | avg_detect_pkt(global)=%.2f\n",
           proto_name[0] ? proto_name : "(unknown)",
           (unsigned)st->master_proto,
           (unsigned)st->app_proto,
           category_name(ndpi, st->category),
           (unsigned)st->category,
           (unsigned long)st->flow_count,
           avg_pkts_per_flow,
           avg_bytes_per_flow,
           avg_detecting_ms,
           var_detecting_ms2,
           avg_post_ms,
           avg_total_ms,
           var_total_ms2,
           avg_detecting_detection_only_ms,
           avg_post_detection_only_ms,
           detecting_mean_us,
           detecting_p50_us,
           detecting_p99_us,
           post_mean_us,
           post_p50_us,
           post_p99_us,
           avg_pkt_flow,
           detect_pkt_flow_p50,
           detect_pkt_flow_p99,
           avg_pkt_global);
  }

  if (write_proto_summary_csv(csv_path, &stats, ndpi, proto_ctx.items, proto_ctx.count)) {
    printf("\nCSV saved: %s\n", csv_path);
  } else {
    fprintf(stderr, "\nWarning: failed to write CSV: %s\n", csv_path);
  }

  for (size_t i = 0; i < proto_ctx.count; i++) {
    sample_vec_free(&proto_ctx.items[i].detecting_packet_samples_ns);
    sample_vec_free(&proto_ctx.items[i].post_packet_samples_ns);
    sample_vec_free(&proto_ctx.items[i].detect_pkt_in_flow_samples);
  }
  free(proto_ctx.items);
  for (uint32_t i = 0; i < CATEGORY_BUCKETS; i++) {
    sample_vec_free(&cat_stats[i].detect_pkt_in_flow_samples);
  }

  /* 5) 释放资源。 */
  pcap_close(pc);
  flow_table_destroy(flows, free_flow_cb, NULL);
  ndpi_exit_detection_module(ndpi);
  ndpi_global_deinit(g_ctx);
  return 0;
}
