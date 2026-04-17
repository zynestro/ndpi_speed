#include "benchmark_internal.h"
#include <limits.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

#define PREFIX_BYTES 4

#if defined(MARK5_PROFILE_TIME)
#define MODE_TAG "time"
#define MODE_TITLE "Time Cost Profiler"
#define FLOW_CSV_BASENAME "time_flow_profile.csv"
#define PROTO_CSV_BASENAME "time_protocol_summary.csv"
#elif defined(MARK5_PROFILE_HW)
#define MODE_TAG "hardware"
#define MODE_TITLE "Hardware Counter Profiler"
#define FLOW_CSV_BASENAME "hardware_flow_profile.csv"
#define PROTO_CSV_BASENAME "hardware_protocol_summary.csv"
#else
#error "One of MARK5_PROFILE_TIME or MARK5_PROFILE_HW must be defined"
#endif

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
  bool detected;
  uint16_t master_proto;
  uint16_t app_proto;
  ndpi_protocol_category_t category;
  uint64_t flow_count;
  uint64_t sum_detect_pkt_in_flow;
  uint64_t sum_detecting_bytes;
  uint64_t sum_packets_in_flow;
  uint64_t sum_bytes_in_flow;
  double sumsq_detect_pkt_in_flow;
  double sumsq_detecting_bytes;
  double sumsq_packets_in_flow;
  double sumsq_bytes_in_flow;
#if defined(MARK5_PROFILE_TIME)
  uint64_t sum_detecting_total_ns;
  uint64_t sum_detecting_detection_only_ns;
  uint64_t sum_detecting_flow_table_ns;
  uint64_t sum_detecting_other_ns;
  uint64_t sum_post_total_ns;
  uint64_t sum_post_detection_only_ns;
  uint64_t sum_post_flow_table_ns;
  uint64_t sum_post_other_ns;
  uint64_t sum_detecting_packets;
  uint64_t sum_post_packets;
  double sumsq_detecting_total_ns;
  double sumsq_detecting_detection_only_ns;
  double sumsq_detecting_flow_table_ns;
  double sumsq_detecting_other_ns;
  double sumsq_post_total_ns;
  double sumsq_post_detection_only_ns;
  double sumsq_post_flow_table_ns;
  double sumsq_post_other_ns;
  double sumsq_detecting_detection_ratio;
  double sumsq_detecting_flow_table_ratio;
  double sumsq_detecting_other_ratio;
  double sumsq_post_detection_ratio;
  double sumsq_post_flow_table_ratio;
  double sumsq_post_other_ratio;
#endif
#if defined(MARK5_PROFILE_HW)
  uint64_t sum_detecting_instructions;
  uint64_t sum_detecting_cycles;
  uint64_t sum_detecting_llc_misses;
  uint64_t sum_detecting_llc_refs;
  uint64_t sum_detecting_branch_misses;
  uint64_t sum_post_instructions;
  uint64_t sum_post_cycles;
  uint64_t sum_post_llc_misses;
  uint64_t sum_post_llc_refs;
  uint64_t sum_post_branch_misses;
  uint64_t sum_detecting_packets;
  uint64_t sum_post_packets;
  double sumsq_detecting_instructions;
  double sumsq_detecting_cycles;
  double sumsq_detecting_ipc;
  double sumsq_detecting_llc_misses;
  double sumsq_detecting_llc_refs;
  double sumsq_detecting_llc_miss_ratio;
  double sumsq_detecting_branch_misses;
  double sumsq_detecting_branch_miss_per_kinst;
  double sumsq_post_instructions;
  double sumsq_post_cycles;
  double sumsq_post_ipc;
  double sumsq_post_llc_misses;
  double sumsq_post_llc_refs;
  double sumsq_post_llc_miss_ratio;
  double sumsq_post_branch_misses;
  double sumsq_post_branch_miss_per_kinst;
#endif
} proto_stat_t;

typedef struct {
  proto_stat_t *items;
  size_t count;
  size_t cap;
} proto_aggregate_ctx_t;

typedef struct {
  struct ndpi_detection_module_struct *ndpi;
  FILE *fp;
  uint64_t index;
} flow_csv_ctx_t;

typedef struct {
  const char *pcap_file;
  const char *proto_file;
  const char *output_root;
  uint32_t cpu_core;
  bool quiet;
} benchmark_config_t;

#if defined(MARK5_PROFILE_HW)
typedef struct {
  uint64_t instructions;
  uint64_t cycles;
  uint64_t llc_misses;
  uint64_t llc_refs;
  uint64_t branch_misses;
} hw_snapshot_t;

typedef struct {
  int leader_fd;
  int fds[3];
  size_t count;
} perf_group_t;

typedef struct {
  perf_group_t work;
  perf_group_t bottleneck;
  uint32_t pmu_type;
  const char *pmu_name;
} perf_monitor_t;
#endif

static void sample_vec_free(sample_vec_t *vec) {
  if (!vec) return;
  free(vec->items);
  vec->items = NULL;
  vec->count = 0;
  vec->cap = 0;
}

static void usage(const char *prog) {
  printf("%s - mark5 %s\n\n", prog, MODE_TITLE);
  printf("Usage: %s -i <pcap> [options]\n\n", prog);
  printf("Required:\n");
  printf("  -i <file>          PCAP file to process\n\n");
  printf("Options:\n");
  printf("  -c <core>          Bind current thread to CPU core\n");
  printf("  -p <file>          Protocol configuration file\n");
  printf("  -o <dir>           Output root directory (default: %s)\n", NDPI_SPEED_OUTPUT_DIR);
  printf("  -q                 Quiet mode\n");
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

static double safe_ratio_u64(uint64_t num, uint64_t den) {
  return den ? (double)num / (double)den : 0.0;
}

static double variance_from_sums(double sum, double sumsq, uint64_t count) {
  if (count == 0) return 0.0;
  double mean = sum / (double)count;
  double var = (sumsq / (double)count) - (mean * mean);
  return (var > 0.0) ? var : 0.0;
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
  flow->signature_payload_prefix_len =
      (pp->payload_len < PREFIX_BYTES) ? (uint8_t)pp->payload_len : PREFIX_BYTES;
  flow->signature_payload_prefix_u32 = 0;

  for (uint8_t i = 0; i < flow->signature_payload_prefix_len; i++) {
    flow->signature_payload_prefix_u32 |= (uint32_t)pp->payload[i] << (8U * (3U - i));
  }
}

static void prefix_to_hex(uint32_t prefix_u32, uint8_t prefix_len, char *buf, size_t buflen) {
  static const char hex[] = "0123456789abcdef";
  if (!buf || buflen == 0) return;
  size_t need = (size_t)prefix_len * 2 + 1;
  if (buflen < need) {
    buf[0] = '\0';
    return;
  }
  for (uint8_t i = 0; i < prefix_len; i++) {
    uint8_t byte = (uint8_t)((prefix_u32 >> (8U * (3U - i))) & 0xFFU);
    buf[i * 2] = hex[byte >> 4];
    buf[i * 2 + 1] = hex[byte & 0x0FU];
  }
  buf[prefix_len * 2] = '\0';
}

static const char *proto_name_from_flow(struct ndpi_detection_module_struct *ndpi,
                                        const bench_flow_t *flow,
                                        char *buf,
                                        size_t buflen) {
  if (!flow || !flow->protocol_counted) return "NOT_DETECTED";
  ndpi_master_app_protocol proto = {0};
  proto.master_protocol = flow->detected_master_proto;
  proto.app_protocol = flow->detected_app_proto;
  ndpi_protocol2name(ndpi, proto, buf, (u_int)buflen);
  return buf[0] ? buf : "(unknown)";
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

#if defined(MARK5_PROFILE_HW)
static bool read_uint_from_file(const char *path, uint32_t *value_out) {
  FILE *fp = fopen(path, "r");
  if (!fp) return false;
  unsigned int value = 0;
  int ok = fscanf(fp, "%u", &value);
  fclose(fp);
  if (ok != 1) return false;
  *value_out = (uint32_t)value;
  return true;
}

static bool perf_alias_to_config(const char *pmu_name, const char *event_name, uint64_t *config_out) {
  char path[PATH_MAX];
  snprintf(path, sizeof(path), "/sys/bus/event_source/devices/%s/events/%s", pmu_name, event_name);

  FILE *fp = fopen(path, "r");
  if (!fp) return false;

  char spec[256];
  if (!fgets(spec, sizeof(spec), fp)) {
    fclose(fp);
    return false;
  }
  fclose(fp);

  uint64_t config = 0;
  char *saveptr = NULL;
  for (char *token = strtok_r(spec, ",\n", &saveptr); token; token = strtok_r(NULL, ",\n", &saveptr)) {
    unsigned int value = 0;
    if (sscanf(token, "event=%x", &value) == 1) {
      config |= (uint64_t)value;
    } else if (sscanf(token, "umask=%x", &value) == 1) {
      config |= ((uint64_t)value << 8U);
    } else if (sscanf(token, "cmask=%x", &value) == 1) {
      config |= ((uint64_t)value << 24U);
    } else if (strcmp(token, "edge=1") == 0) {
      config |= (1ULL << 18U);
    } else if (strcmp(token, "inv=1") == 0) {
      config |= (1ULL << 23U);
    } else if (strcmp(token, "pc=1") == 0) {
      config |= (1ULL << 19U);
    }
  }

  *config_out = config;
  return true;
}

static bool perf_pmu_for_core(uint32_t cpu_core, uint32_t *pmu_type_out, const char **pmu_name_out) {
  const char *pmu_name = NULL;
  const char *type_path = NULL;

  if (cpu_core <= 15U) {
    pmu_name = "cpu_core";
    type_path = "/sys/bus/event_source/devices/cpu_core/type";
  } else if (cpu_core <= 31U) {
    pmu_name = "cpu_atom";
    type_path = "/sys/bus/event_source/devices/cpu_atom/type";
  } else {
    return false;
  }

  uint32_t pmu_type = 0;
  if (!read_uint_from_file(type_path, &pmu_type)) return false;
  *pmu_type_out = pmu_type;
  *pmu_name_out = pmu_name;
  return true;
}

static long perf_event_open(struct perf_event_attr *attr, pid_t pid, int cpu, int group_fd, unsigned long flags) {
  return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

static void perf_group_close(perf_group_t *group) {
  if (!group) return;
  for (size_t i = 0; i < group->count; i++) {
    if (group->fds[i] >= 0) close(group->fds[i]);
    group->fds[i] = -1;
  }
  group->leader_fd = -1;
  group->count = 0;
}

static bool perf_group_open(perf_group_t *group,
                            uint32_t pmu_type,
                            const char *pmu_name,
                            const char *const *event_names,
                            const uint64_t *configs,
                            size_t count,
                            const char *label) {
  memset(group, 0, sizeof(*group));
  group->leader_fd = -1;
  for (size_t i = 0; i < 3; i++) group->fds[i] = -1;

  for (size_t i = 0; i < count; i++) {
    struct perf_event_attr attr;
    memset(&attr, 0, sizeof(attr));
    attr.size = sizeof(attr);
    attr.type = pmu_type;
    attr.config = configs[i];
    if (pmu_name && event_names && event_names[i]) {
      uint64_t resolved_config = 0;
      if (!perf_alias_to_config(pmu_name, event_names[i], &resolved_config)) {
        fprintf(stderr, "Error: failed to resolve PMU event alias %s/%s\n", pmu_name, event_names[i]);
        perf_group_close(group);
        return false;
      }
      attr.config = resolved_config;
    }
    attr.disabled = (i == 0) ? 1 : 0;
    attr.exclude_kernel = 1;
    attr.exclude_hv = 1;
    attr.read_format = PERF_FORMAT_GROUP | PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;

    int fd = (int)perf_event_open(&attr, 0, -1, (i == 0) ? -1 : group->leader_fd, 0);
    if (fd < 0) {
      fprintf(stderr, "Error: perf_event_open(%s,%zu) failed: %s\n", label, i, strerror(errno));
      perf_group_close(group);
      return false;
    }
    if (i == 0) group->leader_fd = fd;
    group->fds[i] = fd;
    group->count++;
  }

  if (ioctl(group->leader_fd, PERF_EVENT_IOC_RESET, PERF_IOC_FLAG_GROUP) != 0) {
    fprintf(stderr, "Error: perf reset failed: %s\n", strerror(errno));
    perf_group_close(group);
    return false;
  }
  if (ioctl(group->leader_fd, PERF_EVENT_IOC_ENABLE, PERF_IOC_FLAG_GROUP) != 0) {
    fprintf(stderr, "Error: perf enable failed: %s\n", strerror(errno));
    perf_group_close(group);
    return false;
  }
  return true;
}

static bool perf_group_read_values(const perf_group_t *group, uint64_t *values_out, size_t expected_count) {
  struct {
    uint64_t nr;
    uint64_t time_enabled;
    uint64_t time_running;
    uint64_t values[3];
  } data;

  ssize_t n = read(group->leader_fd, &data, sizeof(data));
  if (n < 0) return false;
  if (data.nr < expected_count) return false;

  double scale = 1.0;
  if (data.time_running != 0 && data.time_enabled > data.time_running) {
    scale = (double)data.time_enabled / (double)data.time_running;
  }
  for (size_t i = 0; i < expected_count; i++) {
    values_out[i] = (uint64_t)((double)data.values[i] * scale);
  }
  return true;
}

static bool perf_monitor_open(perf_monitor_t *monitor, uint32_t cpu_core) {
  static const uint64_t work_configs[2] = {
      PERF_COUNT_HW_INSTRUCTIONS,
      PERF_COUNT_HW_CPU_CYCLES,
  };
  static const char *const work_event_names[2] = {
      "instructions",
      "cpu-cycles",
  };
  static const uint64_t bottleneck_configs[3] = {
      PERF_COUNT_HW_CACHE_MISSES,
      PERF_COUNT_HW_CACHE_REFERENCES,
      PERF_COUNT_HW_BRANCH_MISSES,
  };
  static const char *const bottleneck_event_names[3] = {
      "cache-misses",
      "cache-references",
      "branch-misses",
  };

  memset(monitor, 0, sizeof(*monitor));
  monitor->pmu_type = PERF_TYPE_HARDWARE;
  monitor->pmu_name = "cpu";
  if (cpu_core != UINT32_MAX) {
    if (!perf_pmu_for_core(cpu_core, &monitor->pmu_type, &monitor->pmu_name)) {
      fprintf(stderr, "Error: unable to resolve PMU type for cpu core %u\n", cpu_core);
      return false;
    }
  }

  const char *const *work_names = (monitor->pmu_type == PERF_TYPE_HARDWARE) ? NULL : work_event_names;
  const char *const *bottleneck_names = (monitor->pmu_type == PERF_TYPE_HARDWARE) ? NULL : bottleneck_event_names;

  if (!perf_group_open(&monitor->work, monitor->pmu_type, monitor->pmu_name, work_names, work_configs, 2, "work")) {
    return false;
  }
  if (!perf_group_open(&monitor->bottleneck,
                       monitor->pmu_type,
                       monitor->pmu_name,
                       bottleneck_names,
                       bottleneck_configs,
                       3,
                       "bottleneck")) {
    perf_group_close(&monitor->work);
    return false;
  }
  return true;
}

static void perf_monitor_close(perf_monitor_t *monitor) {
  if (!monitor) return;
  perf_group_close(&monitor->work);
  perf_group_close(&monitor->bottleneck);
}

static bool perf_monitor_read(perf_monitor_t *monitor, hw_snapshot_t *snap) {
  uint64_t work_vals[2] = {0};
  uint64_t bottleneck_vals[3] = {0};
  if (!perf_group_read_values(&monitor->work, work_vals, 2)) return false;
  if (!perf_group_read_values(&monitor->bottleneck, bottleneck_vals, 3)) return false;
  snap->instructions = work_vals[0];
  snap->cycles = work_vals[1];
  snap->llc_misses = bottleneck_vals[0];
  snap->llc_refs = bottleneck_vals[1];
  snap->branch_misses = bottleneck_vals[2];
  return true;
}

static hw_snapshot_t hw_snapshot_delta(const hw_snapshot_t *end, const hw_snapshot_t *begin) {
  hw_snapshot_t delta;
  delta.instructions = end->instructions - begin->instructions;
  delta.cycles = end->cycles - begin->cycles;
  delta.llc_misses = end->llc_misses - begin->llc_misses;
  delta.llc_refs = end->llc_refs - begin->llc_refs;
  delta.branch_misses = end->branch_misses - begin->branch_misses;
  return delta;
}
#endif

static bool proto_stats_grow(proto_aggregate_ctx_t *ctx) {
  if (!ctx) return false;
  if (ctx->count < ctx->cap) return true;
  size_t new_cap = (ctx->cap == 0) ? 32 : ctx->cap * 2;
  proto_stat_t *new_items = (proto_stat_t *)realloc(ctx->items, new_cap * sizeof(proto_stat_t));
  if (!new_items) return false;
  ctx->items = new_items;
  ctx->cap = new_cap;
  return true;
}

static bool proto_key_equal(const proto_stat_t *st, const bench_flow_t *flow) {
  if (st->detected != flow->protocol_counted) return false;
  if (!st->detected) return true;
  return st->master_proto == flow->detected_master_proto &&
         st->app_proto == flow->detected_app_proto &&
         st->category == flow->detected_category;
}

static void aggregate_proto_cb(bench_flow_t *flow, void *user) {
  proto_aggregate_ctx_t *ctx = (proto_aggregate_ctx_t *)user;
  if (!flow || !ctx) return;

  proto_stat_t *st = NULL;
  for (size_t i = 0; i < ctx->count; i++) {
    if (proto_key_equal(&ctx->items[i], flow)) {
      st = &ctx->items[i];
      break;
    }
  }
  if (!st) {
    if (!proto_stats_grow(ctx)) return;
    st = &ctx->items[ctx->count++];
    memset(st, 0, sizeof(*st));
    st->detected = flow->protocol_counted;
    st->master_proto = flow->detected_master_proto;
    st->app_proto = flow->detected_app_proto;
    st->category = flow->detected_category;
  }

  st->flow_count++;
  st->sum_detect_pkt_in_flow += flow->detection_packet_in_flow;
  st->sum_detecting_bytes += flow->detecting_bytes_total;
  st->sum_packets_in_flow += flow->seen_packets;
  st->sum_bytes_in_flow += flow->c2s_bytes + flow->s2c_bytes;
  st->sumsq_detect_pkt_in_flow += (double)flow->detection_packet_in_flow * (double)flow->detection_packet_in_flow;
  st->sumsq_detecting_bytes += (double)flow->detecting_bytes_total * (double)flow->detecting_bytes_total;
  st->sumsq_packets_in_flow += (double)flow->seen_packets * (double)flow->seen_packets;
  {
    uint64_t flow_bytes = flow->c2s_bytes + flow->s2c_bytes;
    st->sumsq_bytes_in_flow += (double)flow_bytes * (double)flow_bytes;
  }
#if defined(MARK5_PROFILE_TIME)
  {
    uint64_t detecting_other_ns = flow->detecting_time_ns_total -
                                  flow->detecting_detection_time_ns_total -
                                  flow->detecting_flow_table_time_ns_total;
    uint64_t post_other_ns = flow->post_time_ns_total -
                             flow->post_detection_time_ns_total -
                             flow->post_flow_table_time_ns_total;
    double detection_ratio = safe_ratio_u64(flow->detecting_detection_time_ns_total, flow->detecting_time_ns_total);
    double flow_table_ratio = safe_ratio_u64(flow->detecting_flow_table_time_ns_total, flow->detecting_time_ns_total);
    double other_ratio = safe_ratio_u64(detecting_other_ns, flow->detecting_time_ns_total);
    double post_detection_ratio = safe_ratio_u64(flow->post_detection_time_ns_total, flow->post_time_ns_total);
    double post_flow_table_ratio = safe_ratio_u64(flow->post_flow_table_time_ns_total, flow->post_time_ns_total);
    double post_other_ratio = safe_ratio_u64(post_other_ns, flow->post_time_ns_total);

    st->sum_detecting_total_ns += flow->detecting_time_ns_total;
    st->sum_detecting_detection_only_ns += flow->detecting_detection_time_ns_total;
    st->sum_detecting_flow_table_ns += flow->detecting_flow_table_time_ns_total;
    st->sum_detecting_other_ns += detecting_other_ns;
    st->sum_post_total_ns += flow->post_time_ns_total;
    st->sum_post_detection_only_ns += flow->post_detection_time_ns_total;
    st->sum_post_flow_table_ns += flow->post_flow_table_time_ns_total;
    st->sum_post_other_ns += post_other_ns;
    st->sum_detecting_packets += flow->detecting_packets;
    st->sum_post_packets += flow->post_packets;
    st->sumsq_detecting_total_ns += (double)flow->detecting_time_ns_total * (double)flow->detecting_time_ns_total;
    st->sumsq_detecting_detection_only_ns += (double)flow->detecting_detection_time_ns_total *
                                             (double)flow->detecting_detection_time_ns_total;
    st->sumsq_detecting_flow_table_ns += (double)flow->detecting_flow_table_time_ns_total *
                                         (double)flow->detecting_flow_table_time_ns_total;
    st->sumsq_detecting_other_ns += (double)detecting_other_ns * (double)detecting_other_ns;
    st->sumsq_post_total_ns += (double)flow->post_time_ns_total * (double)flow->post_time_ns_total;
    st->sumsq_post_detection_only_ns += (double)flow->post_detection_time_ns_total *
                                        (double)flow->post_detection_time_ns_total;
    st->sumsq_post_flow_table_ns += (double)flow->post_flow_table_time_ns_total *
                                    (double)flow->post_flow_table_time_ns_total;
    st->sumsq_post_other_ns += (double)post_other_ns * (double)post_other_ns;
    st->sumsq_detecting_detection_ratio += detection_ratio * detection_ratio;
    st->sumsq_detecting_flow_table_ratio += flow_table_ratio * flow_table_ratio;
    st->sumsq_detecting_other_ratio += other_ratio * other_ratio;
    st->sumsq_post_detection_ratio += post_detection_ratio * post_detection_ratio;
    st->sumsq_post_flow_table_ratio += post_flow_table_ratio * post_flow_table_ratio;
    st->sumsq_post_other_ratio += post_other_ratio * post_other_ratio;
  }
#endif
#if defined(MARK5_PROFILE_HW)
  {
    double detecting_ipc = safe_ratio_u64(flow->detecting_instructions_total, flow->detecting_cycles_total);
    double detecting_llc_miss_ratio = safe_ratio_u64(flow->detecting_llc_misses_total, flow->detecting_llc_refs_total);
    double branch_miss_per_kinst =
        safe_ratio_u64(flow->detecting_branch_misses_total * 1000ULL, flow->detecting_instructions_total);
    double post_ipc = safe_ratio_u64(flow->post_instructions_total, flow->post_cycles_total);
    double post_llc_miss_ratio = safe_ratio_u64(flow->post_llc_misses_total, flow->post_llc_refs_total);
    double post_branch_miss_per_kinst =
        safe_ratio_u64(flow->post_branch_misses_total * 1000ULL, flow->post_instructions_total);
    st->sum_detecting_instructions += flow->detecting_instructions_total;
    st->sum_detecting_cycles += flow->detecting_cycles_total;
    st->sum_detecting_llc_misses += flow->detecting_llc_misses_total;
    st->sum_detecting_llc_refs += flow->detecting_llc_refs_total;
    st->sum_detecting_branch_misses += flow->detecting_branch_misses_total;
    st->sum_post_instructions += flow->post_instructions_total;
    st->sum_post_cycles += flow->post_cycles_total;
    st->sum_post_llc_misses += flow->post_llc_misses_total;
    st->sum_post_llc_refs += flow->post_llc_refs_total;
    st->sum_post_branch_misses += flow->post_branch_misses_total;
    st->sum_detecting_packets += flow->detecting_packets;
    st->sum_post_packets += flow->post_packets;
    st->sumsq_detecting_instructions += (double)flow->detecting_instructions_total *
                                        (double)flow->detecting_instructions_total;
    st->sumsq_detecting_cycles += (double)flow->detecting_cycles_total * (double)flow->detecting_cycles_total;
    st->sumsq_detecting_ipc += detecting_ipc * detecting_ipc;
    st->sumsq_detecting_llc_misses += (double)flow->detecting_llc_misses_total *
                                      (double)flow->detecting_llc_misses_total;
    st->sumsq_detecting_llc_refs += (double)flow->detecting_llc_refs_total * (double)flow->detecting_llc_refs_total;
    st->sumsq_detecting_llc_miss_ratio += detecting_llc_miss_ratio * detecting_llc_miss_ratio;
    st->sumsq_detecting_branch_misses += (double)flow->detecting_branch_misses_total *
                                         (double)flow->detecting_branch_misses_total;
    st->sumsq_detecting_branch_miss_per_kinst += branch_miss_per_kinst * branch_miss_per_kinst;
    st->sumsq_post_instructions += (double)flow->post_instructions_total *
                                   (double)flow->post_instructions_total;
    st->sumsq_post_cycles += (double)flow->post_cycles_total * (double)flow->post_cycles_total;
    st->sumsq_post_ipc += post_ipc * post_ipc;
    st->sumsq_post_llc_misses += (double)flow->post_llc_misses_total *
                                 (double)flow->post_llc_misses_total;
    st->sumsq_post_llc_refs += (double)flow->post_llc_refs_total * (double)flow->post_llc_refs_total;
    st->sumsq_post_llc_miss_ratio += post_llc_miss_ratio * post_llc_miss_ratio;
    st->sumsq_post_branch_misses += (double)flow->post_branch_misses_total *
                                    (double)flow->post_branch_misses_total;
    st->sumsq_post_branch_miss_per_kinst += post_branch_miss_per_kinst * post_branch_miss_per_kinst;
  }
#endif
}

static int proto_stat_cmp_desc(const void *a, const void *b) {
  const proto_stat_t *pa = (const proto_stat_t *)a;
  const proto_stat_t *pb = (const proto_stat_t *)b;
  if (pa->flow_count < pb->flow_count) return 1;
  if (pa->flow_count > pb->flow_count) return -1;
  if (pa->detected != pb->detected) return pa->detected ? -1 : 1;
  if (pa->app_proto < pb->app_proto) return -1;
  if (pa->app_proto > pb->app_proto) return 1;
  return 0;
}

static void write_packet_columns_header(FILE *fp) {
  for (int i = 1; i <= MARK5_FIRST_PACKET_SAMPLES; i++) {
#if defined(MARK5_PROFILE_TIME)
    fprintf(fp, ",pkt%02d_total_ns,pkt%02d_detection_ns,pkt%02d_flow_table_ns,pkt%02d_other_ns",
            i, i, i, i);
#endif
#if defined(MARK5_PROFILE_HW)
    fprintf(fp, ",pkt%02d_instr,pkt%02d_cycles,pkt%02d_llc_misses,pkt%02d_llc_refs,pkt%02d_branch_misses",
            i, i, i, i, i);
#endif
  }
  fputc('\n', fp);
}

static void write_packet_columns_row(FILE *fp, const bench_flow_t *flow) {
  for (int i = 0; i < MARK5_FIRST_PACKET_SAMPLES; i++) {
#if defined(MARK5_PROFILE_TIME)
    fprintf(fp, ",%lu,%lu,%lu,%lu",
            (unsigned long)flow->first_packet_total_ns[i],
            (unsigned long)flow->first_packet_detection_ns[i],
            (unsigned long)flow->first_packet_flow_table_ns[i],
            (unsigned long)flow->first_packet_other_ns[i]);
#endif
#if defined(MARK5_PROFILE_HW)
    fprintf(fp, ",%lu,%lu,%lu,%lu,%lu",
            (unsigned long)flow->first_packet_instructions[i],
            (unsigned long)flow->first_packet_cycles[i],
            (unsigned long)flow->first_packet_llc_misses[i],
            (unsigned long)flow->first_packet_llc_refs[i],
            (unsigned long)flow->first_packet_branch_misses[i]);
#endif
  }
  fputc('\n', fp);
}

static void write_flow_csv_cb(bench_flow_t *flow, void *user) {
  flow_csv_ctx_t *ctx = (flow_csv_ctx_t *)user;
  if (!flow || !ctx || !ctx->fp) return;

  ctx->index++;
  char prefix_hex[2 * PREFIX_BYTES + 1] = {0};
  char proto_buf[64] = {0};
  prefix_to_hex(flow->signature_payload_prefix_u32, flow->signature_payload_prefix_len,
                prefix_hex, sizeof(prefix_hex));
  const char *proto_name = proto_name_from_flow(ctx->ndpi, flow, proto_buf, sizeof(proto_buf));
  const char *cat_name = flow->protocol_counted ? category_name(ctx->ndpi, flow->detected_category) : "NOT_DETECTED";
  uint64_t flow_bytes = flow->c2s_bytes + flow->s2c_bytes;

#if defined(MARK5_PROFILE_TIME)
  uint64_t detecting_other_ns = flow->detecting_time_ns_total -
                                flow->detecting_detection_time_ns_total -
                                flow->detecting_flow_table_time_ns_total;
  uint64_t post_other_ns = flow->post_time_ns_total -
                           flow->post_detection_time_ns_total -
                           flow->post_flow_table_time_ns_total;
  fprintf(ctx->fp,
          "%lu,%u,%u,%u,%u,%s,%u,%u,%s,%u,%u,%s,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%lu,%lu,%lu",
          (unsigned long)ctx->index,
          (unsigned)flow->protocol_counted,
          (unsigned)flow->signature_ip_version,
          (unsigned)flow->signature_l4_proto,
          (unsigned)flow->signature_server_port,
          prefix_hex,
          (unsigned)flow->detected_master_proto,
          (unsigned)flow->detected_app_proto,
          cat_name,
          (unsigned)flow->detected_category,
          (unsigned)flow->detection_packet_in_flow,
          proto_name,
          (double)flow->detecting_time_ns_total / 1e6,
          (double)flow->detecting_detection_time_ns_total / 1e6,
          (double)flow->detecting_flow_table_time_ns_total / 1e6,
          (double)detecting_other_ns / 1e6,
          safe_ratio_u64(flow->detecting_detection_time_ns_total, flow->detecting_time_ns_total),
          safe_ratio_u64(flow->detecting_flow_table_time_ns_total, flow->detecting_time_ns_total),
          safe_ratio_u64(detecting_other_ns, flow->detecting_time_ns_total),
          (double)flow->post_time_ns_total / 1e6,
          (double)flow->post_detection_time_ns_total / 1e6,
          (double)flow->post_flow_table_time_ns_total / 1e6,
          (double)post_other_ns / 1e6,
          safe_ratio_u64(flow->post_detection_time_ns_total, flow->post_time_ns_total),
          safe_ratio_u64(flow->post_flow_table_time_ns_total, flow->post_time_ns_total),
          safe_ratio_u64(post_other_ns, flow->post_time_ns_total),
          (unsigned long)flow->detecting_bytes_total,
          (unsigned long)flow->seen_packets,
          (unsigned long)flow_bytes);
#endif

#if defined(MARK5_PROFILE_HW)
  uint64_t total_instr = flow->detecting_instructions_total + flow->post_instructions_total;
  uint64_t total_cycles = flow->detecting_cycles_total + flow->post_cycles_total;
  uint64_t total_llc_misses = flow->detecting_llc_misses_total + flow->post_llc_misses_total;
  uint64_t total_llc_refs = flow->detecting_llc_refs_total + flow->post_llc_refs_total;
  uint64_t total_branch_misses = flow->detecting_branch_misses_total + flow->post_branch_misses_total;
  fprintf(ctx->fp,
          "%lu,%u,%u,%u,%u,%s,%u,%u,%s,%u,%u,%s",
          (unsigned long)ctx->index,
          (unsigned)flow->protocol_counted,
          (unsigned)flow->signature_ip_version,
          (unsigned)flow->signature_l4_proto,
          (unsigned)flow->signature_server_port,
          prefix_hex,
          (unsigned)flow->detected_master_proto,
          (unsigned)flow->detected_app_proto,
          cat_name,
          (unsigned)flow->detected_category,
          (unsigned)flow->detection_packet_in_flow,
          proto_name);
  fprintf(ctx->fp,
          ",%lu,%lu,%.6f,%lu,%lu,%.6f,%lu,%.6f,%lu,%lu,%.6f,%lu,%lu,%.6f,%lu,%.6f,%lu,%lu,%lu,%lu,%lu,%lu,%.6f",
          (unsigned long)flow->detecting_instructions_total,
          (unsigned long)flow->detecting_cycles_total,
          safe_ratio_u64(flow->detecting_instructions_total, flow->detecting_cycles_total),
          (unsigned long)flow->detecting_llc_misses_total,
          (unsigned long)flow->detecting_llc_refs_total,
          safe_ratio_u64(flow->detecting_llc_misses_total, flow->detecting_llc_refs_total),
          (unsigned long)flow->detecting_branch_misses_total,
          safe_ratio_u64(flow->detecting_branch_misses_total * 1000ULL, flow->detecting_instructions_total),
          (unsigned long)flow->post_instructions_total,
          (unsigned long)flow->post_cycles_total,
          safe_ratio_u64(flow->post_instructions_total, flow->post_cycles_total),
          (unsigned long)flow->post_llc_misses_total,
          (unsigned long)flow->post_llc_refs_total,
          safe_ratio_u64(flow->post_llc_misses_total, flow->post_llc_refs_total),
          (unsigned long)flow->post_branch_misses_total,
          safe_ratio_u64(flow->post_branch_misses_total * 1000ULL, flow->post_instructions_total),
          (unsigned long)flow->detecting_bytes_total,
          (unsigned long)flow->seen_packets,
          (unsigned long)flow_bytes,
          (unsigned long)total_llc_misses,
          (unsigned long)total_llc_refs,
          (unsigned long)total_branch_misses,
          safe_ratio_u64(total_instr, total_cycles));
#endif
  write_packet_columns_row(ctx->fp, flow);
}

static bool write_flow_csv(const char *csv_path,
                           struct ndpi_detection_module_struct *ndpi,
                           struct flow_table *flows) {
  FILE *fp = fopen(csv_path, "w");
  if (!fp) return false;

#if defined(MARK5_PROFILE_TIME)
  fprintf(fp, "flow_id,protocol_detected,ip_version,l4_proto,server_port,prefix_4,master_proto,app_proto,category_name,category_id,detect_pkt_in_flow,protocol,detecting_total_ms,detecting_detection_only_ms,detecting_flow_table_ms,detecting_other_ms,detecting_detection_ratio,detecting_flow_table_ratio,detecting_other_ratio,post_total_ms,post_detection_only_ms,post_flow_table_ms,post_other_ms,post_detection_ratio,post_flow_table_ratio,post_other_ratio,detecting_bytes,packets_in_flow,bytes_in_flow");
#endif
#if defined(MARK5_PROFILE_HW)
  fprintf(fp, "flow_id,protocol_detected,ip_version,l4_proto,server_port,prefix_4,master_proto,app_proto,category_name,category_id,detect_pkt_in_flow,protocol,detecting_instructions,detecting_cycles,detecting_ipc,detecting_llc_misses,detecting_llc_refs,detecting_llc_miss_ratio,detecting_branch_misses,detecting_branch_miss_per_kinst,post_instructions,post_cycles,post_ipc,post_llc_misses,post_llc_refs,post_llc_miss_ratio,post_branch_misses,post_branch_miss_per_kinst,detecting_bytes,packets_in_flow,bytes_in_flow,total_llc_misses,total_llc_refs,total_branch_misses,total_ipc");
#endif
  write_packet_columns_header(fp);

  flow_csv_ctx_t ctx = {.ndpi = ndpi, .fp = fp, .index = 0};
  flow_table_foreach(flows, write_flow_csv_cb, &ctx);
  fclose(fp);
  return true;
}

static bool write_protocol_csv(const char *csv_path,
                               struct ndpi_detection_module_struct *ndpi,
                               proto_stat_t *stats,
                               size_t count) {
  FILE *fp = fopen(csv_path, "w");
  if (!fp) return false;

#if defined(MARK5_PROFILE_TIME)
  fprintf(fp, "protocol,protocol_detected,master_proto,app_proto,category_name,category_id,flows,avg_detect_pkt_in_flow,var_detect_pkt_in_flow,avg_detecting_bytes,var_detecting_bytes,avg_packets_in_flow,var_packets_in_flow,avg_bytes_in_flow,var_bytes_in_flow,avg_detecting_total_ms,var_detecting_total_ms,avg_detecting_detection_only_ms,var_detecting_detection_only_ms,avg_detecting_flow_table_ms,var_detecting_flow_table_ms,avg_detecting_other_ms,var_detecting_other_ms,avg_detecting_detection_ratio,var_detecting_detection_ratio,avg_detecting_flow_table_ratio,var_detecting_flow_table_ratio,avg_detecting_other_ratio,var_detecting_other_ratio,avg_post_total_ms,var_post_total_ms,avg_post_detection_only_ms,var_post_detection_only_ms,avg_post_flow_table_ms,var_post_flow_table_ms,avg_post_other_ms,var_post_other_ms,avg_post_detection_ratio,var_post_detection_ratio,avg_post_flow_table_ratio,var_post_flow_table_ratio,avg_post_other_ratio,var_post_other_ratio\n");
#endif
#if defined(MARK5_PROFILE_HW)
  fprintf(fp, "protocol,protocol_detected,master_proto,app_proto,category_name,category_id,flows,avg_detect_pkt_in_flow,var_detect_pkt_in_flow,avg_detecting_bytes,var_detecting_bytes,avg_packets_in_flow,var_packets_in_flow,avg_bytes_in_flow,var_bytes_in_flow,avg_detecting_instructions,var_detecting_instructions,avg_detecting_cycles,var_detecting_cycles,avg_detecting_ipc,var_detecting_ipc,avg_detecting_llc_misses,var_detecting_llc_misses,avg_detecting_llc_refs,var_detecting_llc_refs,avg_detecting_llc_miss_ratio,var_detecting_llc_miss_ratio,avg_detecting_branch_misses,var_detecting_branch_misses,avg_detecting_branch_miss_per_kinst,var_detecting_branch_miss_per_kinst,avg_post_instructions,var_post_instructions,avg_post_cycles,var_post_cycles,avg_post_ipc,var_post_ipc,avg_post_llc_misses,var_post_llc_misses,avg_post_llc_refs,var_post_llc_refs,avg_post_llc_miss_ratio,var_post_llc_miss_ratio,avg_post_branch_misses,var_post_branch_misses,avg_post_branch_miss_per_kinst,var_post_branch_miss_per_kinst\n");
#endif

  for (size_t i = 0; i < count; i++) {
    proto_stat_t *st = &stats[i];
    char proto_buf[64] = {0};
    const char *proto_name = "NOT_DETECTED";
    const char *cat_name = "NOT_DETECTED";
    if (st->detected) {
      ndpi_master_app_protocol proto = {0};
      proto.master_protocol = st->master_proto;
      proto.app_protocol = st->app_proto;
      ndpi_protocol2name(ndpi, proto, proto_buf, (u_int)sizeof(proto_buf));
      proto_name = proto_buf[0] ? proto_buf : "(unknown)";
      cat_name = category_name(ndpi, st->category);
    }

#if defined(MARK5_PROFILE_TIME)
    double avg_detect_pkt_in_flow = (double)st->sum_detect_pkt_in_flow / (double)st->flow_count;
    double avg_detecting_bytes = (double)st->sum_detecting_bytes / (double)st->flow_count;
    double avg_packets_in_flow = (double)st->sum_packets_in_flow / (double)st->flow_count;
    double avg_bytes_in_flow = (double)st->sum_bytes_in_flow / (double)st->flow_count;
    double avg_detecting_total_ms = (double)st->sum_detecting_total_ns / (double)st->flow_count / 1e6;
    double avg_detecting_detection_only_ms =
        (double)st->sum_detecting_detection_only_ns / (double)st->flow_count / 1e6;
    double avg_detecting_flow_table_ms =
        (double)st->sum_detecting_flow_table_ns / (double)st->flow_count / 1e6;
    double avg_detecting_other_ms = (double)st->sum_detecting_other_ns / (double)st->flow_count / 1e6;
    double avg_detecting_detection_ratio =
        safe_ratio_u64(st->sum_detecting_detection_only_ns, st->sum_detecting_total_ns);
    double avg_detecting_flow_table_ratio =
        safe_ratio_u64(st->sum_detecting_flow_table_ns, st->sum_detecting_total_ns);
    double avg_detecting_other_ratio =
        safe_ratio_u64(st->sum_detecting_other_ns, st->sum_detecting_total_ns);
    double avg_post_total_ms = (double)st->sum_post_total_ns / (double)st->flow_count / 1e6;
    double avg_post_detection_only_ms =
        (double)st->sum_post_detection_only_ns / (double)st->flow_count / 1e6;
    double avg_post_flow_table_ms =
        (double)st->sum_post_flow_table_ns / (double)st->flow_count / 1e6;
    double avg_post_other_ms = (double)st->sum_post_other_ns / (double)st->flow_count / 1e6;
    double avg_post_detection_ratio =
        safe_ratio_u64(st->sum_post_detection_only_ns, st->sum_post_total_ns);
    double avg_post_flow_table_ratio =
        safe_ratio_u64(st->sum_post_flow_table_ns, st->sum_post_total_ns);
    double avg_post_other_ratio =
        safe_ratio_u64(st->sum_post_other_ns, st->sum_post_total_ns);
    double var_detect_pkt_in_flow =
        variance_from_sums((double)st->sum_detect_pkt_in_flow, st->sumsq_detect_pkt_in_flow, st->flow_count);
    double var_detecting_bytes =
        variance_from_sums((double)st->sum_detecting_bytes, st->sumsq_detecting_bytes, st->flow_count);
    double var_packets_in_flow =
        variance_from_sums((double)st->sum_packets_in_flow, st->sumsq_packets_in_flow, st->flow_count);
    double var_bytes_in_flow =
        variance_from_sums((double)st->sum_bytes_in_flow, st->sumsq_bytes_in_flow, st->flow_count);
    double var_detecting_total_ms =
        variance_from_sums((double)st->sum_detecting_total_ns / 1e6, st->sumsq_detecting_total_ns / 1e12, st->flow_count);
    double var_detecting_detection_only_ms =
        variance_from_sums((double)st->sum_detecting_detection_only_ns / 1e6,
                           st->sumsq_detecting_detection_only_ns / 1e12, st->flow_count);
    double var_detecting_flow_table_ms =
        variance_from_sums((double)st->sum_detecting_flow_table_ns / 1e6,
                           st->sumsq_detecting_flow_table_ns / 1e12, st->flow_count);
    double var_detecting_other_ms =
        variance_from_sums((double)st->sum_detecting_other_ns / 1e6, st->sumsq_detecting_other_ns / 1e12, st->flow_count);
    double var_detecting_detection_ratio =
        variance_from_sums(avg_detecting_detection_ratio * (double)st->flow_count,
                           st->sumsq_detecting_detection_ratio, st->flow_count);
    double var_detecting_flow_table_ratio =
        variance_from_sums(avg_detecting_flow_table_ratio * (double)st->flow_count,
                           st->sumsq_detecting_flow_table_ratio, st->flow_count);
    double var_detecting_other_ratio =
        variance_from_sums(avg_detecting_other_ratio * (double)st->flow_count,
                           st->sumsq_detecting_other_ratio, st->flow_count);
    double var_post_total_ms =
        variance_from_sums((double)st->sum_post_total_ns / 1e6, st->sumsq_post_total_ns / 1e12, st->flow_count);
    double var_post_detection_only_ms =
        variance_from_sums((double)st->sum_post_detection_only_ns / 1e6,
                           st->sumsq_post_detection_only_ns / 1e12, st->flow_count);
    double var_post_flow_table_ms =
        variance_from_sums((double)st->sum_post_flow_table_ns / 1e6,
                           st->sumsq_post_flow_table_ns / 1e12, st->flow_count);
    double var_post_other_ms =
        variance_from_sums((double)st->sum_post_other_ns / 1e6, st->sumsq_post_other_ns / 1e12, st->flow_count);
    double var_post_detection_ratio =
        variance_from_sums(avg_post_detection_ratio * (double)st->flow_count,
                           st->sumsq_post_detection_ratio, st->flow_count);
    double var_post_flow_table_ratio =
        variance_from_sums(avg_post_flow_table_ratio * (double)st->flow_count,
                           st->sumsq_post_flow_table_ratio, st->flow_count);
    double var_post_other_ratio =
        variance_from_sums(avg_post_other_ratio * (double)st->flow_count,
                           st->sumsq_post_other_ratio, st->flow_count);
    fprintf(fp, "%s,%u,%u,%u,%s,%u,%lu",
            proto_name,
            (unsigned)st->detected,
            (unsigned)st->master_proto,
            (unsigned)st->app_proto,
            cat_name,
            (unsigned)st->category,
            (unsigned long)st->flow_count);
    fprintf(fp, ",%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f",
            avg_detect_pkt_in_flow,
            var_detect_pkt_in_flow,
            avg_detecting_bytes,
            var_detecting_bytes,
            avg_packets_in_flow,
            var_packets_in_flow,
            avg_bytes_in_flow,
            var_bytes_in_flow);
    fprintf(fp, ",%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f",
            avg_detecting_total_ms,
            var_detecting_total_ms,
            avg_detecting_detection_only_ms,
            var_detecting_detection_only_ms,
            avg_detecting_flow_table_ms,
            var_detecting_flow_table_ms,
            avg_detecting_other_ms,
            var_detecting_other_ms,
            avg_detecting_detection_ratio,
            var_detecting_detection_ratio,
            avg_detecting_flow_table_ratio,
            var_detecting_flow_table_ratio,
            avg_detecting_other_ratio,
            var_detecting_other_ratio);
    fprintf(fp, ",%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
            avg_post_total_ms,
            var_post_total_ms,
            avg_post_detection_only_ms,
            var_post_detection_only_ms,
            avg_post_flow_table_ms,
            var_post_flow_table_ms,
            avg_post_other_ms,
            var_post_other_ms,
            avg_post_detection_ratio,
            var_post_detection_ratio,
            avg_post_flow_table_ratio,
            var_post_flow_table_ratio,
            avg_post_other_ratio,
            var_post_other_ratio);
#endif
#if defined(MARK5_PROFILE_HW)
    double avg_detect_pkt_in_flow = (double)st->sum_detect_pkt_in_flow / (double)st->flow_count;
    double avg_detecting_bytes = (double)st->sum_detecting_bytes / (double)st->flow_count;
    double avg_packets_in_flow = (double)st->sum_packets_in_flow / (double)st->flow_count;
    double avg_bytes_in_flow = (double)st->sum_bytes_in_flow / (double)st->flow_count;
    double avg_detecting_instructions = (double)st->sum_detecting_instructions / (double)st->flow_count;
    double avg_detecting_cycles = (double)st->sum_detecting_cycles / (double)st->flow_count;
    double avg_detecting_ipc = safe_ratio_u64(st->sum_detecting_instructions, st->sum_detecting_cycles);
    double avg_detecting_llc_misses = (double)st->sum_detecting_llc_misses / (double)st->flow_count;
    double avg_detecting_llc_refs = (double)st->sum_detecting_llc_refs / (double)st->flow_count;
    double avg_detecting_llc_miss_ratio = safe_ratio_u64(st->sum_detecting_llc_misses, st->sum_detecting_llc_refs);
    double avg_detecting_branch_misses = (double)st->sum_detecting_branch_misses / (double)st->flow_count;
    double avg_detecting_branch_miss_per_kinst =
        safe_ratio_u64(st->sum_detecting_branch_misses * 1000ULL, st->sum_detecting_instructions);
    double avg_post_instructions = (double)st->sum_post_instructions / (double)st->flow_count;
    double avg_post_cycles = (double)st->sum_post_cycles / (double)st->flow_count;
    double avg_post_ipc = safe_ratio_u64(st->sum_post_instructions, st->sum_post_cycles);
    double avg_post_llc_misses = (double)st->sum_post_llc_misses / (double)st->flow_count;
    double avg_post_llc_refs = (double)st->sum_post_llc_refs / (double)st->flow_count;
    double avg_post_llc_miss_ratio = safe_ratio_u64(st->sum_post_llc_misses, st->sum_post_llc_refs);
    double avg_post_branch_misses = (double)st->sum_post_branch_misses / (double)st->flow_count;
    double avg_post_branch_miss_per_kinst =
        safe_ratio_u64(st->sum_post_branch_misses * 1000ULL, st->sum_post_instructions);
    double var_detect_pkt_in_flow =
        variance_from_sums((double)st->sum_detect_pkt_in_flow, st->sumsq_detect_pkt_in_flow, st->flow_count);
    double var_detecting_bytes =
        variance_from_sums((double)st->sum_detecting_bytes, st->sumsq_detecting_bytes, st->flow_count);
    double var_packets_in_flow =
        variance_from_sums((double)st->sum_packets_in_flow, st->sumsq_packets_in_flow, st->flow_count);
    double var_bytes_in_flow =
        variance_from_sums((double)st->sum_bytes_in_flow, st->sumsq_bytes_in_flow, st->flow_count);
    double var_detecting_instructions =
        variance_from_sums((double)st->sum_detecting_instructions, st->sumsq_detecting_instructions, st->flow_count);
    double var_detecting_cycles =
        variance_from_sums((double)st->sum_detecting_cycles, st->sumsq_detecting_cycles, st->flow_count);
    double var_detecting_ipc =
        variance_from_sums(avg_detecting_ipc * (double)st->flow_count, st->sumsq_detecting_ipc, st->flow_count);
    double var_detecting_llc_misses =
        variance_from_sums((double)st->sum_detecting_llc_misses, st->sumsq_detecting_llc_misses, st->flow_count);
    double var_detecting_llc_refs =
        variance_from_sums((double)st->sum_detecting_llc_refs, st->sumsq_detecting_llc_refs, st->flow_count);
    double var_detecting_llc_miss_ratio =
        variance_from_sums(avg_detecting_llc_miss_ratio * (double)st->flow_count,
                           st->sumsq_detecting_llc_miss_ratio, st->flow_count);
    double var_detecting_branch_misses =
        variance_from_sums((double)st->sum_detecting_branch_misses, st->sumsq_detecting_branch_misses, st->flow_count);
    double var_detecting_branch_miss_per_kinst =
        variance_from_sums(avg_detecting_branch_miss_per_kinst * (double)st->flow_count,
                           st->sumsq_detecting_branch_miss_per_kinst, st->flow_count);
    double var_post_instructions =
        variance_from_sums((double)st->sum_post_instructions, st->sumsq_post_instructions, st->flow_count);
    double var_post_cycles =
        variance_from_sums((double)st->sum_post_cycles, st->sumsq_post_cycles, st->flow_count);
    double var_post_ipc =
        variance_from_sums(avg_post_ipc * (double)st->flow_count, st->sumsq_post_ipc, st->flow_count);
    double var_post_llc_misses =
        variance_from_sums((double)st->sum_post_llc_misses, st->sumsq_post_llc_misses, st->flow_count);
    double var_post_llc_refs =
        variance_from_sums((double)st->sum_post_llc_refs, st->sumsq_post_llc_refs, st->flow_count);
    double var_post_llc_miss_ratio =
        variance_from_sums(avg_post_llc_miss_ratio * (double)st->flow_count,
                           st->sumsq_post_llc_miss_ratio, st->flow_count);
    double var_post_branch_misses =
        variance_from_sums((double)st->sum_post_branch_misses, st->sumsq_post_branch_misses, st->flow_count);
    double var_post_branch_miss_per_kinst =
        variance_from_sums(avg_post_branch_miss_per_kinst * (double)st->flow_count,
                           st->sumsq_post_branch_miss_per_kinst, st->flow_count);
    fprintf(fp, "%s,%u,%u,%u,%s,%u,%lu",
            proto_name,
            (unsigned)st->detected,
            (unsigned)st->master_proto,
            (unsigned)st->app_proto,
            cat_name,
            (unsigned)st->category,
            (unsigned long)st->flow_count);
    fprintf(fp, ",%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f",
            avg_detect_pkt_in_flow,
            var_detect_pkt_in_flow,
            avg_detecting_bytes,
            var_detecting_bytes,
            avg_packets_in_flow,
            var_packets_in_flow,
            avg_bytes_in_flow,
            var_bytes_in_flow);
    fprintf(fp, ",%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f",
            avg_detecting_instructions,
            var_detecting_instructions,
            avg_detecting_cycles,
            var_detecting_cycles,
            avg_detecting_ipc,
            var_detecting_ipc,
            avg_detecting_llc_misses,
            var_detecting_llc_misses,
            avg_detecting_llc_refs,
            var_detecting_llc_refs,
            avg_detecting_llc_miss_ratio,
            var_detecting_llc_miss_ratio,
            avg_detecting_branch_misses,
            var_detecting_branch_misses,
            avg_detecting_branch_miss_per_kinst,
            var_detecting_branch_miss_per_kinst);
    fprintf(fp, ",%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f\n",
            avg_post_instructions,
            var_post_instructions,
            avg_post_cycles,
            var_post_cycles,
            avg_post_ipc,
            var_post_ipc,
            avg_post_llc_misses,
            var_post_llc_misses,
            avg_post_llc_refs,
            var_post_llc_refs,
            avg_post_llc_miss_ratio,
            var_post_llc_miss_ratio,
            avg_post_branch_misses,
            var_post_branch_misses,
            avg_post_branch_miss_per_kinst,
            var_post_branch_miss_per_kinst);
#endif
  }

  fclose(fp);
  return true;
}

int main(int argc, char **argv) {
  benchmark_config_t cfg = parse_args(argc, argv);
  char run_ts[32] = {0};
  char run_dir[PATH_MAX] = {0};
  char flow_csv_path[PATH_MAX] = {0};
  char proto_csv_path[PATH_MAX] = {0};

  make_timestamp(run_ts, sizeof(run_ts));
  snprintf(run_dir, sizeof(run_dir), "%s/%s", cfg.output_root, run_ts);
  snprintf(flow_csv_path, sizeof(flow_csv_path), "%s/%s", run_dir, FLOW_CSV_BASENAME);
  snprintf(proto_csv_path, sizeof(proto_csv_path), "%s/%s", run_dir, PROTO_CSV_BASENAME);
  if (!mkdir_p(run_dir)) {
    fprintf(stderr, "Error: cannot create output directory: %s\n", run_dir);
    return 1;
  }

  if (cfg.cpu_core != UINT32_MAX) set_thread_affinity(cfg.cpu_core);

  printf("========================================\n");
  printf("ndpiBenchmarkMark5 (%s)\n", MODE_TITLE);
  printf("========================================\n");
  printf("PCAP: %s\n", cfg.pcap_file);
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
  if (cfg.proto_file && cfg.proto_file[0]) (void)ndpi_load_protocols_file(ndpi, cfg.proto_file);
  ndpi_finalize_initialization(ndpi);

  struct flow_table *flows = flow_table_create(16384);
  if (!flows) {
    fprintf(stderr, "Error: flow_table_create() failed\n");
    ndpi_exit_detection_module(ndpi);
    ndpi_global_deinit(g_ctx);
    return 1;
  }

  pcap_t *pc;
  char errbuf[PCAP_ERRBUF_SIZE];
  pc = pcap_open_offline(cfg.pcap_file, errbuf);
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

#if defined(MARK5_PROFILE_HW)
  perf_monitor_t perf_monitor;
  if (!perf_monitor_open(&perf_monitor, cfg.cpu_core)) {
    pcap_close(pc);
    flow_table_destroy(flows, free_flow_cb, NULL);
    ndpi_exit_detection_module(ndpi);
    ndpi_global_deinit(g_ctx);
    return 1;
  }
  if (!cfg.quiet) {
    printf("Hardware PMU: %s (type=%u)\n", perf_monitor.pmu_name, perf_monitor.pmu_type);
  }
#endif

  uint64_t wall_start_ns = get_time_ns();
  struct pcap_pkthdr *hdr = NULL;
  const u_char *pkt = NULL;

  while (1) {
    uint64_t t_read0 = get_time_ns();
    int rc = pcap_next_ex(pc, &hdr, &pkt);
    uint64_t t_read1 = get_time_ns();
    stats.pcap_read_ns += (t_read1 - t_read0);

    if (rc == -2) break;
    if (rc == 0) continue;
    if (rc != 1) {
      fprintf(stderr, "Error: pcap_next_ex() failed: %s\n", pcap_geterr(pc));
#if defined(MARK5_PROFILE_HW)
      perf_monitor_close(&perf_monitor);
#endif
      pcap_close(pc);
      flow_table_destroy(flows, free_flow_cb, NULL);
      ndpi_exit_detection_module(ndpi);
      ndpi_global_deinit(g_ctx);
      return 1;
    }

    stats.total_packets++;
    stats.total_bytes += hdr->len;

#if defined(MARK5_PROFILE_TIME)
    uint64_t t_proc0 = get_time_ns();
#endif
#if defined(MARK5_PROFILE_HW)
    hw_snapshot_t hw_begin, hw_end, hw_delta;
    if (!perf_monitor_read(&perf_monitor, &hw_begin)) {
      fprintf(stderr, "Error: perf read(begin) failed\n");
      perf_monitor_close(&perf_monitor);
      pcap_close(pc);
      flow_table_destroy(flows, free_flow_cb, NULL);
      ndpi_exit_detection_module(ndpi);
      ndpi_global_deinit(g_ctx);
      return 1;
    }
#endif

    const uint8_t *norm_data = NULL;
    uint16_t norm_caplen = 0;
    uint16_t norm_wirelen = 0;
    uint8_t scratch[MAX_PACKET_SIZE];
    if (!normalize_to_ethernet(linktype, pkt, (uint16_t)hdr->caplen, (uint16_t)hdr->len,
                               &norm_data, &norm_caplen, &norm_wirelen, scratch, sizeof(scratch))) {
      stats.normalize_fail_packets++;
#if defined(MARK5_PROFILE_TIME)
      stats.process_ns += (get_time_ns() - t_proc0);
#endif
      continue;
    }

    parsed_packet_t pp;
    if (parse_ethernet_frame(norm_data, norm_caplen, &pp) != PARSE_OK) {
      stats.parse_fail_packets++;
#if defined(MARK5_PROFILE_TIME)
      stats.process_ns += (get_time_ns() - t_proc0);
#endif
      continue;
    }
    stats.parse_ok_packets++;

    flow_key_t key;
    endpoint_t src_ep, dst_ep;
    flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);
    uint64_t h = flow_key_hash(&key);
    bool is_new = false;

#if defined(MARK5_PROFILE_TIME)
    uint64_t t_ft0 = get_time_ns();
#endif
    bench_flow_t *flow = flow_table_get_or_create(flows, &key, h, &is_new);
#if defined(MARK5_PROFILE_TIME)
    uint64_t t_ft1 = get_time_ns();
    uint64_t flow_table_cost_ns = t_ft1 - t_ft0;
#endif
    if (!flow) {
      fprintf(stderr, "Error: flow_table_get_or_create() failed\n");
#if defined(MARK5_PROFILE_HW)
      perf_monitor_close(&perf_monitor);
#endif
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
#if defined(MARK5_PROFILE_HW)
        perf_monitor_close(&perf_monitor);
#endif
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
    if (!was_detected_before_packet) flow->detecting_bytes_total += norm_wirelen;
    flow->last_seen_ms = ((uint64_t)hdr->ts.tv_sec * 1000000ULL + (uint64_t)hdr->ts.tv_usec) / 1000ULL;

    struct ndpi_flow_input_info in = {0};
    in.in_pkt_dir = dir;
    in.seen_flow_beginning = (flow->seen_packets == 1);

#if defined(MARK5_PROFILE_TIME)
    uint64_t t_detect0 = get_time_ns();
#endif
    (void)ndpi_detection_process_packet(ndpi, flow->ndpi_flow, pp.l3, pp.l3_len, flow->last_seen_ms, &in);
#if defined(MARK5_PROFILE_TIME)
    uint64_t t_detect1 = get_time_ns();
    uint64_t detection_cost_ns = t_detect1 - t_detect0;
#endif

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

#if defined(MARK5_PROFILE_TIME)
    uint64_t t_proc1 = get_time_ns();
    uint64_t packet_total_ns = t_proc1 - t_proc0;
    uint64_t packet_other_ns = packet_total_ns - detection_cost_ns - flow_table_cost_ns;
    if (was_detected_before_packet) {
      flow->post_time_ns_total += packet_total_ns;
      flow->post_detection_time_ns_total += detection_cost_ns;
      flow->post_flow_table_time_ns_total += flow_table_cost_ns;
      flow->post_packets++;
    } else {
      flow->detecting_time_ns_total += packet_total_ns;
      flow->detecting_detection_time_ns_total += detection_cost_ns;
      flow->detecting_flow_table_time_ns_total += flow_table_cost_ns;
      flow->detecting_packets++;
      if (flow->seen_packets <= MARK5_FIRST_PACKET_SAMPLES) {
        size_t idx = (size_t)flow->seen_packets - 1;
        flow->first_packet_total_ns[idx] = packet_total_ns;
        flow->first_packet_detection_ns[idx] = detection_cost_ns;
        flow->first_packet_flow_table_ns[idx] = flow_table_cost_ns;
        flow->first_packet_other_ns[idx] = packet_other_ns;
        flow->first_packet_time_sample_count = (uint8_t)flow->seen_packets;
      }
    }
    stats.process_ns += packet_total_ns;
#endif

#if defined(MARK5_PROFILE_HW)
    if (!perf_monitor_read(&perf_monitor, &hw_end)) {
      fprintf(stderr, "Error: perf read(end) failed\n");
      perf_monitor_close(&perf_monitor);
      pcap_close(pc);
      flow_table_destroy(flows, free_flow_cb, NULL);
      ndpi_exit_detection_module(ndpi);
      ndpi_global_deinit(g_ctx);
      return 1;
    }
    hw_delta = hw_snapshot_delta(&hw_end, &hw_begin);
    if (was_detected_before_packet) {
      flow->post_instructions_total += hw_delta.instructions;
      flow->post_cycles_total += hw_delta.cycles;
      flow->post_llc_misses_total += hw_delta.llc_misses;
      flow->post_llc_refs_total += hw_delta.llc_refs;
      flow->post_branch_misses_total += hw_delta.branch_misses;
      flow->post_packets++;
    } else {
      flow->detecting_instructions_total += hw_delta.instructions;
      flow->detecting_cycles_total += hw_delta.cycles;
      flow->detecting_llc_misses_total += hw_delta.llc_misses;
      flow->detecting_llc_refs_total += hw_delta.llc_refs;
      flow->detecting_branch_misses_total += hw_delta.branch_misses;
      flow->detecting_packets++;
      if (flow->seen_packets <= MARK5_FIRST_PACKET_SAMPLES) {
        size_t idx = (size_t)flow->seen_packets - 1;
        flow->first_packet_instructions[idx] = hw_delta.instructions;
        flow->first_packet_cycles[idx] = hw_delta.cycles;
        flow->first_packet_llc_misses[idx] = hw_delta.llc_misses;
        flow->first_packet_llc_refs[idx] = hw_delta.llc_refs;
        flow->first_packet_branch_misses[idx] = hw_delta.branch_misses;
        flow->first_packet_hw_sample_count = (uint8_t)flow->seen_packets;
      }
    }
#endif
  }

  uint64_t wall_end_ns = get_time_ns();
  double elapsed_sec = (double)(wall_end_ns - wall_start_ns) / 1e9;

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
         elapsed_sec, (double)stats.pcap_read_ns / 1e9, (double)stats.process_ns / 1e9);

  proto_aggregate_ctx_t proto_ctx = {0};
  flow_table_foreach(flows, aggregate_proto_cb, &proto_ctx);
  if (proto_ctx.count > 1) qsort(proto_ctx.items, proto_ctx.count, sizeof(proto_stat_t), proto_stat_cmp_desc);

  if (!write_flow_csv(flow_csv_path, ndpi, flows)) {
    fprintf(stderr, "Error: failed to write flow CSV: %s\n", flow_csv_path);
  } else {
    printf("Flow CSV saved: %s\n", flow_csv_path);
  }
  if (!write_protocol_csv(proto_csv_path, ndpi, proto_ctx.items, proto_ctx.count)) {
    fprintf(stderr, "Error: failed to write protocol CSV: %s\n", proto_csv_path);
  } else {
    printf("Protocol CSV saved: %s\n", proto_csv_path);
  }

  free(proto_ctx.items);
#if defined(MARK5_PROFILE_HW)
  perf_monitor_close(&perf_monitor);
#endif
  pcap_close(pc);
  flow_table_destroy(flows, free_flow_cb, NULL);
  ndpi_exit_detection_module(ndpi);
  ndpi_global_deinit(g_ctx);
  return 0;
}
