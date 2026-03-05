#include "benchmark_internal.h"

static void free_flow_cb(bench_flow_t *flow, void *user);

/* 初始化单个 worker 的识别环境：
 * - 创建 ndpi detection module
 * - 应用可选配置
 * - 创建该 worker 私有 flow table
 *
 * 关键点：
 * - 每个 worker 有独立 ndpi module，避免跨线程共享内部状态
 * - g_ctx 是共享的，但 flow 状态不共享
 */
void init_worker_ndpi(worker_context_t *worker) {
  if (!worker) return;

  worker->ndpi = ndpi_init_detection_module(worker->g_ctx);
  if (!worker->ndpi) {
    fprintf(stderr, "Error: ndpi_init_detection_module() failed for worker %u\n", worker->worker_id);
    exit(1);
  }

  /* 启用 ACK payload heuristic，提升部分流量场景的识别能力。 */
  (void)ndpi_set_config(worker->ndpi, NULL, "tcp_ack_payload_heuristic", "enable");

  if (worker->proto_file && worker->proto_file[0]) {
    (void)ndpi_load_protocols_file(worker->ndpi, worker->proto_file);
  }

  ndpi_finalize_initialization(worker->ndpi);

  worker->flows = flow_table_create(16384);
  if (!worker->flows) {
    fprintf(stderr, "Error: flow_table_create() failed\n");
    exit(1);
  }
}

/* 释放 worker 资源，顺序与初始化相反。
 * flow_table_destroy 会触发 free_flow_cb，保证 nDPI flow 也释放。
 */
void cleanup_worker(worker_context_t *worker) {
  if (!worker) return;

  if (worker->flows) {
    flow_table_destroy(worker->flows, free_flow_cb, worker);
    worker->flows = NULL;
  }

#ifdef NDPI_BENCHMARK_CLASSIFIED
  if (worker->classified) {
    classified_table_destroy(worker->classified);
    worker->classified = NULL;
  }
#endif

  if (worker->ndpi) {
    ndpi_exit_detection_module(worker->ndpi);
    worker->ndpi = NULL;
  }

  if (worker->queue) {
    packet_queue_destroy(worker->queue);
    worker->queue = NULL;
  }
}

/* 新建 flow 时，把 bench 解析结果映射到 ndpi_flow_struct 的 5 元组字段。 */
static inline void set_ndpi_flow_tuple(struct ndpi_flow_struct *flow,
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

/* flow 释放回调：
 * - 在释放前补做一次“是否已识别协议”的统计结算
 * - 释放 nDPI flow 状态与 bench_flow 内存
 *
 * 兜底意义：
 * - 有些流可能在主路径中还没触发 protocol_counted
 * - 释放时再查一次，避免漏统计
 */
static void free_flow_cb(bench_flow_t *flow, void *user) {
  worker_context_t *w = (worker_context_t *)user;
  if (!flow) return;

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

/* worker 的单包处理主路径：
 * parse -> flow lookup/create -> ndpi process -> protocol accounted
 *
 * 计时切分：
 * - parse_time_us: 协议头解析
 * - flow_time_us: flow 表操作 + 新流初始化
 * - ndpi_time_us: ndpi_detection_process_packet
 * - other_time_us: 剩余 bookkeeping
 */
static inline void worker_process_packet(worker_context_t *w, const queue_packet_t *pkt) {
  uint64_t t0 = get_time_us();

  /* 1) 解析 L2/L3/L4，失败直接计时并返回。 */
  parsed_packet_t pp;
  if (parse_ethernet_frame(pkt->data, pkt->caplen, &pp) != PARSE_OK) {
    /* 对不支持/截断包，策略是“丢弃但计时”，不影响后续流。 */
    uint64_t t1 = get_time_us();
    w->parse_time_us += (t1 - t0);
    w->processing_time_us += (t1 - t0);
    return;
  }
  uint64_t t1 = get_time_us();
  w->parse_time_us += (t1 - t0);

  flow_key_t key;
  endpoint_t src_ep, dst_ep;
  flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);

  uint64_t h = flow_key_hash(&key);
#ifdef NDPI_BENCHMARK_CLASSIFIED
  /* classified 版本：已分类流直接命中缓存，不再走 nDPI。 */
  uint16_t cached_app = 0;
  if (classified_table_lookup(w->classified, &key, h, &cached_app)) {
    /* 命中后仍记包/字节计数，但不再维护 active flow 状态。 */
    w->packets_processed++;
    w->bytes_processed += pkt->wirelen;
    uint64_t t4 = get_time_us();
    w->other_time_us += (t4 - t1);
    w->processing_time_us += (t4 - t0);
    return;
  }
#endif

  /* 2) 在 worker 私有 flow 表中查找或创建状态。 */
  bool is_new = false;
  bench_flow_t *flow = flow_table_get_or_create(w->flows, &key, h, &is_new);
  if (!flow) {
    uint64_t t2 = get_time_us();
    w->flow_time_us += (t2 - t1);
    w->processing_time_us += (t2 - t0);
    return;
  }

  if (is_new) {
    /* 新流：初始化双向端点、nDPI flow state。 */
    w->flows_created_total++;
    atomic_fetch_add_explicit(&w->active_flows, 1, memory_order_relaxed);

    flow->client = src_ep;
    flow->server = dst_ep;

    flow->ndpi_flow = (struct ndpi_flow_struct *)ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
    if (!flow->ndpi_flow) {
      /* 这里是致命错误：无法维护 nDPI flow 状态，直接退出。 */
      fprintf(stderr, "Error: ndpi_calloc(flow) failed\n");
      exit(1);
    }

    set_ndpi_flow_tuple(flow->ndpi_flow, &pp, &flow->client, &flow->server);
  }
  uint64_t t2 = get_time_us();
  w->flow_time_us += (t2 - t1);

  /* 方向判断基于“首次包定义 client 端点”的约定。 */
  uint8_t dir = endpoint_equal(&src_ep, &flow->client) ? 0 : 1;

  /* 3) 更新双向报文/字节统计，维护 last_seen。 */
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

  /* 4) 交给 nDPI 做增量识别。 */
  (void)ndpi_detection_process_packet(w->ndpi, flow->ndpi_flow,
                                      pp.l3, pp.l3_len,
                                      ts_ms, &in);
  uint64_t t3 = get_time_us();
  w->ndpi_time_us += (t3 - t2);

  flow->seen_packets++;

#ifdef NDPI_BENCHMARK_CLASSIFIED
  bool newly_classified = false;
  uint16_t app_proto = NDPI_PROTOCOL_UNKNOWN;
#endif
  /* 5) 首次识别到应用协议时，只计一次 flow 命中。 */
  if (!flow->protocol_counted) {
    /* 只在 UNKNOWN->已识别 的边沿做一次计数。 */
    uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
    if (app != NDPI_PROTOCOL_UNKNOWN) {
      flow->protocol_counted = true;
      w->flows_with_protocol_total++;
      maybe_print_flow_sample(w, flow);
#ifdef NDPI_BENCHMARK_CLASSIFIED
      app_proto = app;
      newly_classified = true;
#endif
    }
  }

  w->packets_processed++;
  w->bytes_processed += pkt->wirelen;

  uint64_t t4 = get_time_us();
  w->other_time_us += (t4 - t3);
  w->processing_time_us += (t4 - t0);

  /* 周期性更新“单包处理耗时 EWMA”，供后续负载感知策略扩展。 */
  if ((w->packets_processed & 0x3FF) == 0) {
    uint64_t avg = w->processing_time_us / w->packets_processed;
    uint64_t prev = atomic_load_explicit(&w->proc_ewma_us, memory_order_relaxed);
    uint64_t ewma = prev ? ((prev * 7 + avg) / 8) : avg;
    atomic_store_explicit(&w->proc_ewma_us, ewma, memory_order_relaxed);
  }

#ifdef NDPI_BENCHMARK_CLASSIFIED
  /* classified 版本：一旦分类成功，将流转移到 classified 表并从 active 表删除。 */
  if (newly_classified) {
    /* 先写分类表，再删 active 表，确保后续包不会短暂“无状态”。 */
    classified_table_insert(w->classified, &flow->key, h, app_proto);
    flow_table_delete(w->flows, &flow->key, h, free_flow_cb, w);
    atomic_fetch_sub_explicit(&w->active_flows, 1, memory_order_relaxed);
  }
#endif
}

/* worker 线程入口：
 * 持续从队列 peek/consume，直到 reader 标记 finished 且队列耗尽。
 */
void *worker_thread_entry(void *arg) {
  worker_context_t *w = (worker_context_t *)arg;

  set_thread_affinity(w->cpu_core);

  queue_packet_t *pkt = NULL;
  while (packet_queue_peek(w->queue, &pkt)) {
    worker_process_packet(w, pkt);
    packet_queue_consume(w->queue);
  }

  return NULL;
}
