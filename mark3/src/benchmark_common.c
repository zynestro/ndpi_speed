#include "benchmark_internal.h"

/* 进程级共享状态：
 * - 控制“打印前 N 条识别样本”的并发互斥和计数
 * - 控制是否静默输出
 */
pthread_mutex_t g_print_mutex = PTHREAD_MUTEX_INITIALIZER;
uint64_t g_samples_printed = 0;
const uint64_t g_sample_limit = 10;
bool g_quiet_mode = false;

/* 把 endpoint_t 转成可读字符串，供样本日志打印。 */
static void endpoint_to_string(const endpoint_t *ep, char *buf, size_t buflen) {
  if (!ep || !buf || buflen == 0) return;

  char ip[INET6_ADDRSTRLEN] = {0};
  /* IPv4/IPv6 分支分别调用 inet_ntop，输出统一为 "ip:port"。 */
  if (ep->ip_version == 4) {
    inet_ntop(AF_INET, ep->addr, ip, sizeof(ip));
  } else {
    inet_ntop(AF_INET6, ep->addr, ip, sizeof(ip));
  }

  snprintf(buf, buflen, "%s:%u", ip, (unsigned)ep->port);
}

/* 在协议首次识别成功时打印流样本。
 * 这里只做展示与调试，不参与识别逻辑本身。
 *
 * 触发时机：
 * - worker 在某条 flow 第一次拿到非 UNKNOWN app 协议时调用
 * - 或 flow 回收阶段做兜底统计时调用
 */
void maybe_print_flow_sample(worker_context_t *w, const bench_flow_t *f) {
  if (g_quiet_mode) return;

  /* 多 worker 并发打印，必须串行化，避免输出交错。 */
  pthread_mutex_lock(&g_print_mutex);
  if (g_samples_printed >= g_sample_limit) {
    pthread_mutex_unlock(&g_print_mutex);
    return;
  }

  /* 从 nDPI flow 状态中取主协议/应用协议并转成可读名称。
   * nDPI 内部编码通过 ndpi_protocol2name 映射成字符串。
   */
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

  /* 只打印前 g_sample_limit 条。 */
  g_samples_printed++;
  pthread_mutex_unlock(&g_print_mutex);
}

#ifdef __linux__
/* 尝试绑定当前线程到指定 CPU core，用于降低调度抖动。
 * 绑核失败时只告警不退出，避免在受限环境下无法运行。
 */
void set_thread_affinity(uint32_t core) {
  cpu_set_t cpuset;
  CPU_ZERO(&cpuset);
  CPU_SET(core, &cpuset);
  int rc = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
  if (rc != 0 && !g_quiet_mode) {
    fprintf(stderr, "Warning: pthread_setaffinity_np(core=%u) failed: %s\n", core, strerror(rc));
  }
}
#else
/* 非 Linux 平台上保持空实现，保证跨平台可编译。 */
void set_thread_affinity(uint32_t core) {
  (void)core;
}
#endif
