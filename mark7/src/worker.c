#include "benchmark_internal.h"

/*
 * mark3/src/worker.c
 *
 * worker 是“真正做协议识别”的执行单元：
 * - 从队列取包
 * - parse -> flow 状态 -> nDPI 增量识别
 * - 更新统计并在首次识别成功时计数
 */

static void free_flow_cb(bench_flow_t *flow, void *user);

/*
 * ==============================
 * mark3 worker 模块详细说明
 * ==============================
 *
 * 一、worker 在线程模型里的位置
 * --------------------------------
 * - worker 是“最终执行识别”的消费者线程
 * - 上游由 reader/dispatcher 把包写进每个 worker 的 queue
 * - worker 只消费自己的队列，不共享 flow 表
 *
 * 二、为什么每个 worker 拥有独立 ndpi module？
 * --------------------------------
 * nDPI 的每流状态和内部缓存是可变的；并发共享同一 module 会引入锁或竞态。
 * mark3 采取“每 worker 一份 ndpi detection module”：
 * - 避免识别路径上的锁竞争
 * - 使 worker 处理路径保持纯本地状态
 * - 代价是内存占用上升（可接受，换吞吐）
 *
 * 三、worker_process_packet 的 6 步主线
 * --------------------------------
 * 1) parse：把以太网帧解析到 L3/L4 视图
 * 2) keybuild：构造 canonical flow key + src/dst endpoint
 * 3) flow lookup/create：在 worker 私有 hash 表取状态
 * 4) flow update：更新方向计数、时间戳、seen_packets
 * 5) ndpi call：增量推进协议识别状态机
 * 6) proto edge check：只在 UNKNOWN->KNOWN 的边沿累计“识别成功流数”
 *
 * 四、计时体系
 * --------------------------------
 * worker 把每包处理拆成多个子阶段计时：
 * - parse/keybuild/flow_lookup/flow_init/ndpi_call/proto_check/other
 * 这样主程序能输出更细粒度瓶颈定位信息。
 *
 * 五、方向判断约定
 * --------------------------------
 * - 首包的 src endpoint 定义为 client
 * - 后续包通过 endpoint_equal 与 client 比较得到 dir(0/1)
 * - 该 dir 传给 nDPI 的 in_pkt_dir，影响内部识别逻辑
 *
 * 六、可选 classified 快路径（编译宏）
 * --------------------------------
 * NDPI_BENCHMARK_CLASSIFIED 开启时：
 * - 已识别过的 flow 可直接命中 classified_table
 * - 命中后跳过 ndpi_detection_process_packet，降低重复开销
 */

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

  free(worker->flow_detect_latency_ns);
  worker->flow_detect_latency_ns = NULL;
  worker->flow_detect_latency_count = 0;
  worker->flow_detect_latency_cap = 0;
}

static void worker_record_flow_detect_latency(worker_context_t *w,
                                              uint64_t latency_ns) {
  if (w->flow_detect_latency_count == w->flow_detect_latency_cap) {
    size_t next_cap = w->flow_detect_latency_cap ? w->flow_detect_latency_cap * 2 : 1024;
    uint64_t *next =
        (uint64_t *)realloc(w->flow_detect_latency_ns, next_cap * sizeof(uint64_t));
    if (!next) return;
    w->flow_detect_latency_ns = next;
    w->flow_detect_latency_cap = next_cap;
  }
  w->flow_detect_latency_ns[w->flow_detect_latency_count++] = latency_ns;
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
 * 计时切分（纳秒）：
 * - parse_time_ns: 协议头解析
 * - keybuild_time_ns: flow_key 构造
 * - flow_lookup_time_ns: flow 表查找/创建
 * - flow_init_time_ns: 新流初始化
 * - ndpi_call_time_ns: ndpi_detection_process_packet 调用
 * - proto_check_time_ns: 协议命中检查与计数
 * - classified_fastpath_ns: classified 命中快路径
 * - other_time_ns: 剩余 bookkeeping
 */
static inline void worker_process_packet(worker_context_t *w, const queue_packet_t *pkt) {
  /* 单包函数是 worker 的热路径，尽量保持：
   * - 早失败快速返回
   * - 分项计时可解释
   * - 状态更新顺序稳定（先状态后统计）
   */
  uint64_t t0 = get_time_ns();
  uint64_t known_ns = 0;

  /* 1) 解析 L2/L3/L4，失败直接计时并返回。 */
  parsed_packet_t pp;
  if (parse_ethernet_frame(pkt->data, pkt->caplen, &pp) != PARSE_OK) {
    /* 对不支持/截断包，策略是“丢弃但计时”，不影响后续流。 */
    uint64_t t1 = get_time_ns();
    uint64_t dt = t1 - t0;
    w->parse_time_ns += dt;
    w->processing_time_ns += dt;
    return;
  }
  uint64_t t1 = get_time_ns();
  uint64_t parse_ns = t1 - t0;
  w->parse_time_ns += parse_ns;
  known_ns += parse_ns;

  uint64_t t_key0 = get_time_ns();
  flow_key_t key;
  endpoint_t src_ep, dst_ep;
  flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);
  /* flow_key_from_packet 会做双向规范化：
   * A->B 与 B->A 归并到同一 flow_key。
   */
  uint64_t t_key1 = get_time_ns();
  uint64_t keybuild_ns = t_key1 - t_key0;
  w->keybuild_time_ns += keybuild_ns;
  known_ns += keybuild_ns;

  uint64_t h = flow_key_hash(&key);
#ifdef NDPI_BENCHMARK_CLASSIFIED
  /* classified 版本：已分类流直接命中缓存，不再走 nDPI。 */
  uint16_t cached_app = 0;
  uint64_t t_cls0 = get_time_ns();
  if (classified_table_lookup(w->classified, &key, h, &cached_app)) {
    /* 命中后仍记包/字节计数，但不再维护 active flow 状态。 */
    w->packets_processed++;
    w->bytes_processed += pkt->wirelen;
    uint64_t t_cls1 = get_time_ns();
    uint64_t cls_ns = t_cls1 - t_cls0;
    w->classified_fastpath_ns += cls_ns;
    known_ns += cls_ns;
    uint64_t total_ns = t_cls1 - t0;
    if (total_ns > known_ns) w->other_time_ns += (total_ns - known_ns);
    w->processing_time_ns += total_ns;
    return;
  }
  uint64_t t_cls1 = get_time_ns();
  uint64_t cls_ns = t_cls1 - t_cls0;
  w->classified_fastpath_ns += cls_ns;
  known_ns += cls_ns;
#endif

  /* 2) 在 worker 私有 flow 表中查找或创建状态。 */
  bool is_new = false;
  uint64_t t_lookup0 = get_time_ns();
  bench_flow_t *flow = flow_table_get_or_create(w->flows, &key, h, &is_new);
  uint64_t t_lookup1 = get_time_ns();
  uint64_t lookup_ns = t_lookup1 - t_lookup0;
  w->flow_lookup_time_ns += lookup_ns;
  known_ns += lookup_ns;
  if (!flow) {
    w->flow_time_ns += lookup_ns;
    uint64_t total_ns = t_lookup1 - t0;
    if (total_ns > known_ns) w->other_time_ns += (total_ns - known_ns);
    w->processing_time_ns += total_ns;
    return;
  }

  uint64_t init_ns = 0;
  if (is_new) {
    /* 新流：初始化双向端点、nDPI flow state。 */
    uint64_t t_init0 = get_time_ns();
    w->flows_created_total++;
    atomic_fetch_add_explicit(&w->active_flows, 1, memory_order_relaxed);

    flow->client = src_ep;
    flow->server = dst_ep;
    flow->first_enqueue_time_ns = pkt->enqueue_time_ns ? pkt->enqueue_time_ns : t0;
    /* 这里把“首次方向”固化到 flow，用于后续 dir 判定。 */

    flow->ndpi_flow = (struct ndpi_flow_struct *)ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
    if (!flow->ndpi_flow) {
      /* 这里是致命错误：无法维护 nDPI flow 状态，直接退出。 */
      fprintf(stderr, "Error: ndpi_calloc(flow) failed\n");
      exit(1);
    }

    set_ndpi_flow_tuple(flow->ndpi_flow, &pp, &flow->client, &flow->server);
    uint64_t t_init1 = get_time_ns();
    init_ns = t_init1 - t_init0;
    w->flow_init_time_ns += init_ns;
    known_ns += init_ns;
  }
  w->flow_time_ns += (lookup_ns + init_ns);

  /* 方向判断基于“首次包定义 client 端点”的约定。 */
  uint8_t dir = endpoint_equal(&src_ep, &flow->client) ? 0 : 1;
  /* dir 的语义：
   * - 0：当前包方向与首包 client->server 一致
   * - 1：反向 server->client
   */

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
  /* seen_flow_beginning 给 nDPI 一个提示：
   * 当前包是否是该流第一包，可影响某些协议状态初始化路径。
   */

  /* 4) 交给 nDPI 做增量识别。 */
  uint64_t t_ndpi0 = get_time_ns();
  (void)ndpi_detection_process_packet(w->ndpi, flow->ndpi_flow,
                                      pp.l3, pp.l3_len,
                                      ts_ms, &in);
  /* 注意：
   * nDPI 识别是增量推进，不保证每包都有最终协议结论。
   * 所以这里不能“每次都+1 detected”，只能检测边沿。
   */
  uint64_t t_ndpi1 = get_time_ns();
  uint64_t ndpi_call_ns = t_ndpi1 - t_ndpi0;
  w->ndpi_call_time_ns += ndpi_call_ns;
  known_ns += ndpi_call_ns;

  flow->seen_packets++;

#ifdef NDPI_BENCHMARK_CLASSIFIED
  bool newly_classified = false;
  uint16_t app_proto = NDPI_PROTOCOL_UNKNOWN;
#endif
  /* 5) 首次识别到应用协议时，只计一次 flow 命中。 */
  uint64_t t_chk0 = get_time_ns();
  if (!flow->protocol_counted) {
    /* 只在 UNKNOWN->已识别 的边沿做一次计数。 */
    uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
    if (app != NDPI_PROTOCOL_UNKNOWN) {
      flow->protocol_counted = true;
      w->flows_with_protocol_total++;
      uint64_t detect_now_ns = get_time_ns();
      uint64_t first_ns = flow->first_enqueue_time_ns ? flow->first_enqueue_time_ns : t0;
      if (detect_now_ns >= first_ns) {
        worker_record_flow_detect_latency(w, detect_now_ns - first_ns);
      }
      /* 样本打印只做展示，不影响识别结果。 */
      maybe_print_flow_sample(w, flow);
#ifdef NDPI_BENCHMARK_CLASSIFIED
      app_proto = app;
      newly_classified = true;
#endif
    }
  }
  uint64_t t_chk1 = get_time_ns();
  uint64_t proto_check_ns = t_chk1 - t_chk0;
  w->proto_check_time_ns += proto_check_ns;
  known_ns += proto_check_ns;
  w->ndpi_time_ns += (ndpi_call_ns + proto_check_ns);

  w->packets_processed++;
  w->bytes_processed += pkt->wirelen;
  uint64_t t4 = get_time_ns();
  uint64_t total_ns = t4 - t0;
  if (total_ns > known_ns) w->other_time_ns += (total_ns - known_ns);
  w->processing_time_ns += total_ns;

  /* 周期性更新“单包处理耗时 EWMA”，供后续负载感知策略扩展。 */
  if ((w->packets_processed & 0x3FF) == 0) {
    /* 每 1024 包更新一次 EWMA，避免每包原子写的成本。 */
    uint64_t avg = (w->processing_time_ns / w->packets_processed) / 1000ULL;
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

  /* worker 线程入口语义：
   * - 先绑核（若配置）
   * - 再不断从 queue 消费，直到 queue finished 且耗尽
   */
  set_thread_affinity(w->cpu_core);

  queue_packet_t *pkt = NULL;
  while (packet_queue_peek(w->queue, &pkt)) {
    /* peek 成功表示有可读包；consume 后 tail 前进。 */
    worker_process_packet(w, pkt);
    if (w->runtime && pkt->retire_cost_x1000) {
      atomic_fetch_add_explicit(&w->runtime->retired_cost_x1000,
                                pkt->retire_cost_x1000,
                                memory_order_relaxed);
    }
    if (w->runtime) {
      atomic_fetch_sub_explicit(&w->runtime->queue_depth, 1, memory_order_relaxed);
    }
    packet_queue_consume(w->queue);
  }

  return NULL;
}
