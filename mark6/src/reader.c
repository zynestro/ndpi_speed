#include "benchmark_internal.h"

/*
 * mark3/src/reader.c
 *
 * reader 负责两件大事：
 * 1) 预处理阶段：读取 pcap -> 标准化 -> 快速 hash -> flow->dispatcher 绑定 -> 缓存包
 * 2) 分发阶段：启动多个 dispatcher，把缓存包按 flow 粘性投递到 worker 队列
 *
 * 设计动机：
 * - 把“读盘/标准化”和“投递队列”解耦，便于分析并行分发收益
 */

#define PREPROCESS_PACKET_SIZE 1400

typedef struct {
  uint64_t timestamp_us;
  flow_key_t flow_key;
  uint64_t fallback_hash;
  uint32_t dispatcher_id;
  uint16_t caplen;
  uint16_t wirelen;
  uint16_t dst_port;
  uint8_t payload_prefix[4];
  uint8_t payload_prefix_len;
  bool has_flow_key;
  uint8_t data[PREPROCESS_PACKET_SIZE];
} dispatch_packet_t;

typedef struct {
  reader_context_t *ctx;
  uint32_t dispatcher_id;
  uint32_t cpu_core;
} dispatcher_arg_t;

/*
 * ==============================
 * mark3 reader 模块详细说明
 * ==============================
 *
 * 一、为什么 reader 要分两段？
 * --------------------------------
 * mark3 不是“读一包 -> 立刻 enqueue -> worker 处理”的直通模型，而是：
 *
 *  预处理段（load_pcap_packets）：
 *    pcap 读取 + 链路层标准化 + 快速 hash + flow->dispatcher 绑定 + 缓存包
 *
 *  分发段（dispatcher_thread_entry）：
 *    多 dispatcher 线程并发扫描各自片段，再做 flow->worker 绑定并入队
 *
 * 这么做的目的：
 * - 把 I/O/标准化 与 并发投递 解耦，便于独立测量与优化
 * - 让 dispatcher 在线程级并行，模拟“多队列读包+分发”的软件流水线
 * - 更清晰地观察 preprocess 和 dispatch 两层开销占比
 *
 * 二、关键状态对象
 * --------------------------------
 * reader_context_t 里有三组最关键的数据：
 * 1) packets/packet_count：
 *    预加载后的 dispatch_packet_t 数组（连续内存）
 * 2) dispatcher_offsets / dispatcher_indices：
 *    把 packet 索引按 dispatcher 切分后的调度计划
 * 3) 计时字段（preprocess_* / read_*）：
 *    统计每个阶段的细项耗时，最终在 main 汇总打印
 *
 * 三、flow 粘性是如何保证的？
 * --------------------------------
 * - 预处理阶段用 dispatcher_map（局部 rss_table）做 flow->dispatcher
 * - 分发阶段用 ctx->rss（全局 rss_table）做 flow->worker
 * - 结果：同一 flow 在一个活跃窗口内尽量固定到同一个 worker
 *
 * 四、为什么预加载包只保留 1400 字节？
 * --------------------------------
 * PREPROCESS_PACKET_SIZE=1400 是一个显式 tradeoff：
 * - 减少预处理缓存占用，降低内存压力和复制成本
 * - 仍能覆盖大多数协议识别所需的前部载荷
 * - 对特别依赖深层 payload 的协议，识别精度可能下降
 *
 * 五、线程结束语义
 * --------------------------------
 * - dispatcher 全部 join 后，reader 调用 packet_queue_finish
 * - worker 在 packet_queue_peek 中看到“空队列且 finished=true”后退出
 * - 这保证了“包处理完再退出”，避免提前终止
 */

static inline void reset_reader_timers(reader_context_t *ctx) {
  ctx->pcap_read_ns = 0;
  ctx->normalize_ns = 0;
  ctx->hash_ns = 0;
  ctx->rss_lookup_ns = 0;
  ctx->enqueue_ns = 0;
  ctx->read_other_ns = 0;
  ctx->read_time_ns = 0;
  ctx->preprocess_ns = 0;
  ctx->preprocess_dispatch_rss_ns = 0;
  ctx->preprocess_store_ns = 0;
  ctx->preprocess_schedule_ns = 0;
  ctx->preprocess_other_ns = 0;
}

static inline void finalize_reader_timers(reader_context_t *ctx) {
  ctx->read_time_ns = ctx->rss_lookup_ns + ctx->enqueue_ns + ctx->read_other_ns;
}

static void cleanup_preloaded_packets(reader_context_t *ctx) {
  free(ctx->packets);
  ctx->packets = NULL;
  ctx->packet_count = 0;

  free(ctx->dispatcher_offsets);
  ctx->dispatcher_offsets = NULL;

  free(ctx->dispatcher_indices);
  ctx->dispatcher_indices = NULL;
}

static bool append_packet(dispatch_packet_t **pkts, size_t *count, size_t *cap,
                          const uint8_t *data, uint16_t caplen,
                          uint16_t wirelen, uint64_t ts_us,
                          const flow_key_t *flow_key, uint64_t fallback_hash,
                          uint32_t dispatcher_id, uint16_t dst_port,
                          const uint8_t *payload_prefix, uint8_t payload_prefix_len,
                          bool has_flow_key) {
  if (*count == *cap) {
    size_t new_cap = (*cap == 0) ? 8192 : (*cap * 2);
    dispatch_packet_t *next =
        (dispatch_packet_t *)realloc(*pkts, new_cap * sizeof(dispatch_packet_t));
    if (!next) return false;
    *pkts = next;
    *cap = new_cap;
  }

  dispatch_packet_t *p = &(*pkts)[*count];
  uint16_t stored_caplen = (caplen > PREPROCESS_PACKET_SIZE)
                               ? (uint16_t)PREPROCESS_PACKET_SIZE
                               : caplen;
  p->timestamp_us = ts_us;
  memset(&p->flow_key, 0, sizeof(p->flow_key));
  if (flow_key) p->flow_key = *flow_key;
  p->fallback_hash = fallback_hash;
  p->dispatcher_id = dispatcher_id;
  p->caplen = stored_caplen;
  p->wirelen = wirelen;
  p->dst_port = dst_port;
  p->payload_prefix_len = payload_prefix_len > 4 ? 4 : payload_prefix_len;
  p->has_flow_key = has_flow_key;
  if (payload_prefix && p->payload_prefix_len > 0) {
    memcpy(p->payload_prefix, payload_prefix, p->payload_prefix_len);
  } else {
    memset(p->payload_prefix, 0, sizeof(p->payload_prefix));
  }
  memcpy(p->data, data, stored_caplen);
  (*count)++;
  return true;
}

static bool build_dispatch_schedule(reader_context_t *ctx,
                                    const dispatch_packet_t *packets,
                                    size_t packet_count) {
  size_t *counts = (size_t *)calloc(ctx->num_dispatchers, sizeof(size_t));
  if (!counts) return false;

  for (size_t i = 0; i < packet_count; i++) {
    uint32_t d = packets[i].dispatcher_id;
    if (d >= ctx->num_dispatchers) {
      free(counts);
      return false;
    }
    counts[d]++;
  }

  size_t *offsets = (size_t *)calloc(ctx->num_dispatchers + 1, sizeof(size_t));
  if (!offsets) {
    free(counts);
    return false;
  }

  for (uint32_t d = 0; d < ctx->num_dispatchers; d++) {
    offsets[d + 1] = offsets[d] + counts[d];
  }

  size_t *indices = NULL;
  if (packet_count > 0) {
    indices = (size_t *)calloc(packet_count, sizeof(size_t));
    if (!indices) {
      free(counts);
      free(offsets);
      return false;
    }
  }

  size_t *cursor = (size_t *)calloc(ctx->num_dispatchers, sizeof(size_t));
  if (!cursor) {
    free(counts);
    free(offsets);
    free(indices);
    return false;
  }

  for (uint32_t d = 0; d < ctx->num_dispatchers; d++) {
    cursor[d] = offsets[d];
  }

  for (size_t i = 0; i < packet_count; i++) {
    uint32_t d = packets[i].dispatcher_id;
    indices[cursor[d]++] = i;
  }

  free(counts);
  free(cursor);

  ctx->dispatcher_offsets = offsets;
  ctx->dispatcher_indices = indices;
  return true;
}

static bool load_pcap_packets(reader_context_t *ctx,
                              dispatch_packet_t **out_packets,
                              size_t *out_count) {
  /* 预处理入口：
   * - 打开离线 pcap
   * - 顺序扫描每个包并生成 dispatch_packet_t
   * - 同时记录 preprocess 细项耗时
   */
  char errbuf[PCAP_ERRBUF_SIZE] = {0};
  pcap_t *handle = pcap_open_offline(ctx->pcap_file, errbuf);
  if (!handle) {
    fprintf(stderr, "Error opening PCAP: %s\n", errbuf);
    return false;
  }

  dispatch_packet_t *packets = NULL;
  size_t count = 0;
  size_t cap = 0;

  struct pcap_pkthdr *header = NULL;
  const u_char *data = NULL;
  int linktype = pcap_datalink(handle);
  uint8_t scratch[MAX_PACKET_SIZE];

  while (1) {
    /* loop_start_ns / known_ns 组合用于“分项计时”：
     * - known_ns 累加已明确归因的阶段耗时
     * - loop_ns - known_ns 归到 preprocess_other_ns
     * 这样可以减少漏记但又不把未知开销混到主项里。
     */
    uint64_t loop_start_ns = get_time_ns();

    uint64_t t_pcap0 = get_time_ns();
    int rc = pcap_next_ex(handle, &header, &data);
    uint64_t t_pcap1 = get_time_ns();
    uint64_t pcap_ns = t_pcap1 - t_pcap0;
    ctx->pcap_read_ns += pcap_ns;

    if (rc <= 0) {
      /* rc<=0 表示 EOF/错误/无数据，离线文件通常以 EOF 结束。 */
      if (rc == -1 && !g_quiet_mode) {
        fprintf(stderr, "Warning: pcap_next_ex() failed: %s\n", pcap_geterr(handle));
      }
      break;
    }

    const uint8_t *pkt_data = data;
    uint64_t known_ns = pcap_ns;
    if (header->caplen > MAX_PACKET_SIZE) {
      uint64_t loop_end_ns = get_time_ns();
      uint64_t loop_ns = loop_end_ns - loop_start_ns;
      if (loop_ns > known_ns) ctx->preprocess_other_ns += (loop_ns - known_ns);
      continue;
    }

    uint16_t pkt_caplen = (uint16_t)header->caplen;
    uint16_t pkt_wirelen = (uint16_t)header->len;

    uint64_t t_norm0 = get_time_ns();
    bool ok = normalize_to_ethernet(linktype, data, pkt_caplen, pkt_wirelen,
                                    &pkt_data, &pkt_caplen, &pkt_wirelen,
                                    scratch, sizeof(scratch));
    uint64_t t_norm1 = get_time_ns();
    uint64_t norm_ns = t_norm1 - t_norm0;
    ctx->normalize_ns += norm_ns;
    known_ns += norm_ns;
    if (!ok) {
      /* 无法标准化到 Ethernet 的包直接跳过，不进入后续 hash/分发。 */
      uint64_t loop_end_ns = get_time_ns();
      uint64_t loop_ns = loop_end_ns - loop_start_ns;
      if (loop_ns > known_ns) ctx->preprocess_other_ns += (loop_ns - known_ns);
      continue;
    }

    uint64_t ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;

    uint64_t t_hash0 = get_time_ns();
    parsed_packet_t pp;
    flow_key_t flow_key;
    endpoint_t src_ep, dst_ep;
    uint64_t flow_hash = 0;
    uint64_t fallback_hash = 0;
    uint16_t dst_port = 0;
    uint8_t payload_prefix[4] = {0};
    uint8_t payload_prefix_len = 0;
    bool has_flow_key = false;

    parse_result_t parsed = parse_ethernet_frame(pkt_data, pkt_caplen, &pp);
    if (parsed == PARSE_OK) {
      flow_key_from_packet(&pp, &flow_key, &src_ep, &dst_ep);
      flow_hash = flow_key_hash(&flow_key);
      fallback_hash = flow_hash;
      dst_port = pp.dst_port;
      payload_prefix_len = (pp.payload_len >= 4) ? 4 : (uint8_t)pp.payload_len;
      if (payload_prefix_len > 0 && pp.payload) {
        memcpy(payload_prefix, pp.payload, payload_prefix_len);
      }
      has_flow_key = true;
    } else {
      uint32_t h1 = compute_flow_hash(pkt_data, pkt_caplen, 0);
      uint32_t h2 = rss_mix32(h1 ^ 0x9e3779b9U);
      fallback_hash = ((uint64_t)h1 << 32) | h2;
    }
    uint64_t t_hash1 = get_time_ns();
    uint64_t hash_ns = t_hash1 - t_hash0;
    ctx->hash_ns += hash_ns;
    known_ns += hash_ns;

    uint64_t t_drss0 = get_time_ns();
    uint32_t dispatcher_id = 0;
    if (ctx->num_dispatchers > 0) {
      uint64_t rss_hash = has_flow_key ? flow_hash : fallback_hash;
      dispatcher_id = (uint32_t)(rss_hash % ctx->num_dispatchers);
    }
    uint64_t t_drss1 = get_time_ns();
    uint64_t drss_ns = t_drss1 - t_drss0;
    ctx->preprocess_dispatch_rss_ns += drss_ns;
    known_ns += drss_ns;

    uint64_t t_copy0 = get_time_ns();
    bool pushed = append_packet(&packets, &count, &cap,
                                pkt_data, pkt_caplen, pkt_wirelen,
                                ts_us,
                                has_flow_key ? &flow_key : NULL,
                                fallback_hash,
                                dispatcher_id,
                                dst_port,
                                payload_prefix,
                                payload_prefix_len,
                                has_flow_key);
    uint64_t t_copy1 = get_time_ns();
    uint64_t store_ns = t_copy1 - t_copy0;
    ctx->preprocess_store_ns += store_ns;
    known_ns += store_ns;
    if (!pushed) {
      fprintf(stderr, "Error: out of memory while loading packets\n");
      free(packets);
      pcap_close(handle);
      return false;
    }

    uint64_t loop_end_ns = get_time_ns();
    uint64_t loop_ns = loop_end_ns - loop_start_ns;
    if (loop_ns > known_ns) ctx->preprocess_other_ns += (loop_ns - known_ns);
  }

  pcap_close(handle);
  *out_packets = packets;
  *out_count = count;
  return true;
}

static void merge_dispatcher_stats(reader_context_t *ctx,
                                   uint64_t rss_lookup_ns,
                                   uint64_t enqueue_ns,
                                   uint64_t read_other_ns) {
  pthread_mutex_lock(&ctx->stats_lock);
  ctx->rss_lookup_ns += rss_lookup_ns;
  ctx->enqueue_ns += enqueue_ns;
  ctx->read_other_ns += read_other_ns;
  pthread_mutex_unlock(&ctx->stats_lock);
}

static void *dispatcher_thread_entry(void *arg) {
  dispatcher_arg_t *darg = (dispatcher_arg_t *)arg;
  reader_context_t *ctx = darg->ctx;

  /* dispatcher 线程职责：
   * - 只处理自己分配到的 [start, end) 区间
   * - 对每个预处理包做 flow->worker 查询并 enqueue
   * - 本地累计计时，最后一次性 merge 到 reader_context
   */
  if (darg->cpu_core != UINT32_MAX) {
    set_thread_affinity(darg->cpu_core);
  }

#ifdef NDPI_BENCHMARK_BATCH
  packet_queue_prod_t prod[MAX_WORKERS];
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_init(ctx->workers[i].queue, &prod[i]);
  }
#endif

  uint64_t rss_lookup_ns = 0;
  uint64_t enqueue_ns = 0;
  uint64_t read_other_ns = 0;

  const dispatch_packet_t *packets = (const dispatch_packet_t *)ctx->packets;
  size_t start = ctx->dispatcher_offsets[darg->dispatcher_id];
  size_t end = ctx->dispatcher_offsets[darg->dispatcher_id + 1];
  /* 注意：
   * start/end 是基于“索引数组”划分，不是直接切 packets 连续块；
   * 真正包下标在 ctx->dispatcher_indices[pos] 中。
   */

  for (size_t pos = start; pos < end; pos++) {
    uint64_t loop_start_ns = get_time_ns();

    size_t idx = ctx->dispatcher_indices[pos];
    const dispatch_packet_t *pkt = &packets[idx];
    uint64_t known_ns = 0;

    uint64_t t_rss0 = get_time_ns();
    uint32_t worker_id = 0;
    uint32_t retire_cost_x1000 = 0;
    if (pkt->has_flow_key) {
      dispatch_result_t dr = dispatch_lookup_or_assign(ctx->dispatch,
                                                       &pkt->flow_key,
                                                       pkt->dst_port,
                                                       pkt->payload_prefix,
                                                       pkt->payload_prefix_len);
      worker_id = dr.worker_id;
      retire_cost_x1000 = dr.retire_cost_x1000;
    } else {
      worker_id = (uint32_t)(pkt->fallback_hash % ctx->num_workers);
    }
    uint64_t t_rss1 = get_time_ns();
    uint64_t d_rss_ns = t_rss1 - t_rss0;
    rss_lookup_ns += d_rss_ns;
    known_ns += d_rss_ns;

    uint64_t t_enq0 = get_time_ns();
#ifdef NDPI_BENCHMARK_BATCH
    (void)packet_queue_push_cached(ctx->workers[worker_id].queue,
                                   &prod[worker_id],
                                   pkt->data,
                                   pkt->caplen,
                                   pkt->wirelen,
                                   pkt->timestamp_us,
                                   retire_cost_x1000);
#else
    (void)packet_queue_push(ctx->workers[worker_id].queue,
                            pkt->data,
                            pkt->caplen,
                            pkt->wirelen,
                            pkt->timestamp_us,
                            retire_cost_x1000);
#endif
    atomic_fetch_add_explicit(&ctx->workers[worker_id].runtime->queue_depth,
                              1,
                              memory_order_relaxed);
    uint64_t t_enq1 = get_time_ns();
    uint64_t d_enq_ns = t_enq1 - t_enq0;
    enqueue_ns += d_enq_ns;
    known_ns += d_enq_ns;

    uint64_t loop_end_ns = get_time_ns();
    uint64_t loop_ns = loop_end_ns - loop_start_ns;
    if (loop_ns > known_ns) read_other_ns += (loop_ns - known_ns);
  }

#ifdef NDPI_BENCHMARK_BATCH
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_flush(ctx->workers[i].queue, &prod[i]);
  }
#endif

  merge_dispatcher_stats(ctx, rss_lookup_ns, enqueue_ns, read_other_ns);
  return NULL;
}

void *reader_thread_entry(void *arg) {
  reader_context_t *ctx = (reader_context_t *)arg;
  /* reader 主控线程时序：
   * 1) reset timers
   * 2) 预加载 pcap 到内存
   * 3) 构建 dispatcher 调度计划
   * 4) 启动并等待所有 dispatcher
   * 5) 广播 worker 队列 finished
   * 6) 清理预加载内存与统计锁
   */
  reset_reader_timers(ctx);
  ctx->failed = false;
  pthread_mutex_init(&ctx->stats_lock, NULL);

  uint64_t t_load0 = get_time_ns();
  dispatch_packet_t *packets = NULL;
  size_t packet_count = 0;
  if (!load_pcap_packets(ctx, &packets, &packet_count)) {
    ctx->failed = true;
    /* 预处理失败时要显式终止 worker，防止 worker 永久阻塞。 */
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    pthread_mutex_destroy(&ctx->stats_lock);
    finalize_reader_timers(ctx);
    return NULL;
  }

  ctx->packets = packets;
  ctx->packet_count = packet_count;

  uint64_t t_sched0 = get_time_ns();
  if (!build_dispatch_schedule(ctx, packets, packet_count)) {
    ctx->failed = true;
    fprintf(stderr, "Error: failed to build dispatcher schedule\n");
    /* schedule 构建失败同样需要通知 worker 收尾退出。 */
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    cleanup_preloaded_packets(ctx);
    pthread_mutex_destroy(&ctx->stats_lock);
    finalize_reader_timers(ctx);
    return NULL;
  }
  uint64_t t_sched1 = get_time_ns();
  ctx->preprocess_schedule_ns += (t_sched1 - t_sched0);

  uint64_t t_load1 = get_time_ns();
  ctx->preprocess_ns += (t_load1 - t_load0);

  pthread_t dispatchers[MAX_WORKERS];
  dispatcher_arg_t dargs[MAX_WORKERS];

  for (uint32_t i = 0; i < ctx->num_dispatchers; i++) {
    dargs[i].ctx = ctx;
    dargs[i].dispatcher_id = i;
    dargs[i].cpu_core = ctx->dispatcher_cores ? ctx->dispatcher_cores[i] : UINT32_MAX;
    if (pthread_create(&dispatchers[i], NULL, dispatcher_thread_entry, &dargs[i]) != 0) {
      ctx->failed = true;
      fprintf(stderr, "Error: pthread_create(dispatcher=%u) failed\n", i);
      /* 部分 dispatcher 已启动时，先 join 已启动线程再触发 worker finish。 */
      for (uint32_t j = 0; j < i; j++) {
        pthread_join(dispatchers[j], NULL);
      }
      for (uint32_t w = 0; w < ctx->num_workers; w++) {
        packet_queue_finish(ctx->workers[w].queue);
      }
      cleanup_preloaded_packets(ctx);
      pthread_mutex_destroy(&ctx->stats_lock);
      finalize_reader_timers(ctx);
      return NULL;
    }
  }

  for (uint32_t i = 0; i < ctx->num_dispatchers; i++) {
    pthread_join(dispatchers[i], NULL);
  }

  /* 所有 dispatcher 已完成入队，worker 仅需 drain 队列即可退出。 */
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_finish(ctx->workers[i].queue);
  }

  cleanup_preloaded_packets(ctx);
  pthread_mutex_destroy(&ctx->stats_lock);
  finalize_reader_timers(ctx);
  return NULL;
}
