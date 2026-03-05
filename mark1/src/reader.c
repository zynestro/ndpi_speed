#include "benchmark_internal.h"

/* 流式 reader：
 * - 直接从磁盘 pcap_next_ex() 读取
 * - 做链路层标准化
 * - 根据流哈希和 RSS 表把包投递到目标 worker 队列
 *
 * 线程模型：
 * - 单 reader 生产者
 * - 多 worker 消费者（每个 worker 一条独立队列）
 */
static void *reader_thread_stream(void *arg) {
  reader_context_t *ctx = (reader_context_t *)arg;
  if (ctx->reader_core != UINT32_MAX) {
    set_thread_affinity(ctx->reader_core);
  }
#ifdef NDPI_BENCHMARK_BATCH
  /* batch 版本使用 producer 本地缓存，降低 head 原子更新频率。 */
  packet_queue_prod_t prod[MAX_WORKERS];
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_init(ctx->workers[i].queue, &prod[i]);
  }
#endif

  char errbuf[PCAP_ERRBUF_SIZE];
  uint64_t t_start = get_time_us();
  pcap_t *handle = pcap_open_offline(ctx->pcap_file, errbuf);
  if (!handle) {
    /* 打不开输入时必须 finish 所有队列，否则 worker 会永久阻塞在 peek。 */
    fprintf(stderr, "Error opening PCAP: %s\n", errbuf);
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    ctx->read_time_us = 0;
    ctx->pcap_read_us = 0;
    ctx->enqueue_us = 0;
    ctx->enqueue_hash_us = 0;
    ctx->enqueue_queue_wait_us = 0;
    ctx->enqueue_queue_write_us = 0;
    return NULL;
  }

  struct pcap_pkthdr *header = NULL;
  const u_char *data = NULL;
  int linktype = pcap_datalink(handle);
  uint8_t scratch[MAX_PACKET_SIZE];
  int rc;

  /* 主循环：读一个包 -> 规范化 -> 选 worker -> 入队。 */
  while ((rc = pcap_next_ex(handle, &header, &data)) > 0) {
    uint64_t t_read_end = get_time_us();
    ctx->pcap_read_us += (t_read_end - t_start);

    const uint8_t *pkt_data = data;
    uint16_t pkt_caplen = (uint16_t)header->caplen;
    uint16_t pkt_wirelen = (uint16_t)header->len;

    /* 支持 DLT_NULL/LOOP/RAW 等，统一补成 Ethernet 视图。 */
    if (!normalize_to_ethernet(linktype, data, pkt_caplen, pkt_wirelen,
                               &pkt_data, &pkt_caplen, &pkt_wirelen,
                               scratch, sizeof(scratch))) {
      t_start = get_time_us();
      continue;
    }

    /* 防御式检查：队列槽位的 data[] 最大就是 MAX_PACKET_SIZE。 */
    if (pkt_caplen > MAX_PACKET_SIZE) {
      t_start = get_time_us();
      continue;
    }

    uint64_t t_enqueue_start = get_time_us();
    /* 时间戳同时保留 us（入队）和 ms（喂给 RSS/ndpi）。 */
    uint64_t ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
    uint64_t ts_ms = ts_us / 1000ULL;

    /* 两个 hash 值用于“两候选 worker 选更轻负载”的分流策略。 */
    uint32_t h1 = compute_flow_hash(pkt_data, pkt_caplen, 0);
    uint32_t h2 = rss_mix32(h1 ^ 0x9e3779b9U);
    uint64_t key = ((uint64_t)h1 << 32) | h2;
    uint32_t worker_id = rss_table_lookup_or_assign(ctx->rss, ctx, key, h1, h2, ts_ms);
    uint64_t t_enqueue_dispatch_end = get_time_us();
    uint64_t queue_wait_us = 0;
    uint64_t queue_write_us = 0;
    ctx->enqueue_hash_us += (t_enqueue_dispatch_end - t_enqueue_start);

#ifdef NDPI_BENCHMARK_BATCH
    /* batch 版：先写本地 head，批量发布到共享 head。 */
    (void)packet_queue_push_cached_timed(ctx->workers[worker_id].queue,
                                         &prod[worker_id],
                                         pkt_data,
                                         pkt_caplen,
                                         pkt_wirelen,
                                         ts_us,
                                         &queue_wait_us,
                                         &queue_write_us);
#else
    /* 普通版：每包直接发布。 */
    (void)packet_queue_push_timed(ctx->workers[worker_id].queue,
                                  pkt_data,
                                  pkt_caplen,
                                  pkt_wirelen,
                                  ts_us,
                                  &queue_wait_us,
                                  &queue_write_us);
#endif
    ctx->enqueue_queue_wait_us += queue_wait_us;
    ctx->enqueue_queue_write_us += queue_write_us;
    ctx->enqueue_us += (t_enqueue_dispatch_end - t_enqueue_start) + queue_wait_us + queue_write_us;
    t_start = get_time_us();
  }

  if (rc == -1 && !g_quiet_mode) {
    /* libpcap 读错: 给警告但继续收尾。 */
    fprintf(stderr, "Warning: pcap_next_ex() failed: %s\n", pcap_geterr(handle));
  }

  if (rc != 0) {
    /* EOF(-2) 或 error(-1) 都要补记最后一次 read 区间。 */
    uint64_t t_read_end = get_time_us();
    ctx->pcap_read_us += (t_read_end - t_start);
  }

#ifdef NDPI_BENCHMARK_BATCH
  /* 确保缓存中的最后一批包都发布。 */
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_flush(ctx->workers[i].queue, &prod[i]);
  }
#endif

  pcap_close(handle);
  /* 通知每个 worker：不会再有新包。 */
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_finish(ctx->workers[i].queue);
  }

  ctx->enqueue_us = ctx->enqueue_hash_us + ctx->enqueue_queue_wait_us + ctx->enqueue_queue_write_us;
  ctx->read_time_us = ctx->pcap_read_us + ctx->enqueue_us;
  return NULL;
}

#ifdef NDPI_BENCHMARK_MEMREADER
/* 内存 reader 专用：一次性把 pcap 文件读入内存。 */
typedef struct {
  uint8_t *data;
  size_t size;
} pcap_blob_t;

/* 把整个 pcap 文件读入连续内存，便于后续 fmemopen + pcap_fopen_offline。
 * 目的：把“磁盘 I/O 抖动”从测量中剥离，更接近纯处理吞吐。
 */
static bool read_file_to_memory(const char *path, pcap_blob_t *out, char *errbuf, size_t errbuf_len) {
  struct stat st;
  if (stat(path, &st) != 0) {
    snprintf(errbuf, errbuf_len, "stat(%s) failed: %s", path, strerror(errno));
    return false;
  }

  if (st.st_size <= 0) {
    snprintf(errbuf, errbuf_len, "file is empty: %s", path);
    return false;
  }

  size_t size = (size_t)st.st_size;
  FILE *fp = fopen(path, "rb");
  if (!fp) {
    snprintf(errbuf, errbuf_len, "fopen(%s) failed: %s", path, strerror(errno));
    return false;
  }

  uint8_t *buf = (uint8_t *)malloc(size);
  if (!buf) {
    snprintf(errbuf, errbuf_len, "malloc(%zu) failed", size);
    fclose(fp);
    return false;
  }

  size_t off = 0;
  while (off < size) {
    size_t n = fread(buf + off, 1, size - off, fp);
    if (n == 0) break;
    off += n;
  }

  if (off != size) {
    snprintf(errbuf, errbuf_len, "fread(%s) failed: read %zu/%zu", path, off, size);
    free(buf);
    fclose(fp);
    return false;
  }

  fclose(fp);
  out->data = buf;
  out->size = size;
  return true;
}

static void *reader_thread_mem(void *arg) {
  reader_context_t *ctx = (reader_context_t *)arg;
  if (ctx->reader_core != UINT32_MAX) {
    set_thread_affinity(ctx->reader_core);
  }
#ifdef NDPI_BENCHMARK_BATCH
  /* 与 stream 模式一致：batch 版本使用 producer 缓存。 */
  packet_queue_prod_t prod[MAX_WORKERS];
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_init(ctx->workers[i].queue, &prod[i]);
  }
#endif

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_blob_t blob = {0};
  uint64_t t_start = get_time_us();

  /* 第一步：把 PCAP 全量加载到内存。 */
  if (!read_file_to_memory(ctx->pcap_file, &blob, errbuf, sizeof(errbuf))) {
    fprintf(stderr, "Error reading PCAP into memory: %s\n", errbuf);
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    ctx->read_time_us = 0;
    ctx->pcap_read_us = 0;
    ctx->enqueue_us = 0;
    ctx->enqueue_hash_us = 0;
    ctx->enqueue_queue_wait_us = 0;
    ctx->enqueue_queue_write_us = 0;
    return NULL;
  }

  /* 第二步：把内存块包装成 FILE*，再交给 libpcap。 */
  FILE *memfp = fmemopen(blob.data, blob.size, "rb");
  if (!memfp) {
    fprintf(stderr, "Error: fmemopen() failed: %s\n", strerror(errno));
    free(blob.data);
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    ctx->read_time_us = 0;
    ctx->pcap_read_us = 0;
    ctx->enqueue_us = 0;
    ctx->enqueue_hash_us = 0;
    ctx->enqueue_queue_wait_us = 0;
    ctx->enqueue_queue_write_us = 0;
    return NULL;
  }

  pcap_t *handle = pcap_fopen_offline(memfp, errbuf);
  if (!handle) {
    fprintf(stderr, "Error opening PCAP from memory: %s\n", errbuf);
    fclose(memfp);
    free(blob.data);
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    ctx->read_time_us = 0;
    ctx->pcap_read_us = 0;
    ctx->enqueue_us = 0;
    ctx->enqueue_hash_us = 0;
    ctx->enqueue_queue_wait_us = 0;
    ctx->enqueue_queue_write_us = 0;
    return NULL;
  }

  struct pcap_pkthdr *header = NULL;
  const u_char *data = NULL;
  int linktype = pcap_datalink(handle);
  uint8_t scratch[MAX_PACKET_SIZE];
  int rc;

  /* 第三步：后续处理路径与 stream 模式一致。 */
  while ((rc = pcap_next_ex(handle, &header, &data)) > 0) {
    uint64_t t_read_end = get_time_us();
    ctx->pcap_read_us += (t_read_end - t_start);

    const uint8_t *pkt_data = data;
    uint16_t pkt_caplen = (uint16_t)header->caplen;
    uint16_t pkt_wirelen = (uint16_t)header->len;

    if (!normalize_to_ethernet(linktype, data, pkt_caplen, pkt_wirelen,
                               &pkt_data, &pkt_caplen, &pkt_wirelen,
                               scratch, sizeof(scratch))) {
      t_start = get_time_us();
      continue;
    }

    if (pkt_caplen > MAX_PACKET_SIZE) {
      t_start = get_time_us();
      continue;
    }

    uint64_t t_enqueue_start = get_time_us();
    uint64_t ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
    uint64_t ts_ms = ts_us / 1000ULL;

    /* 与 stream 版本保持同一分流算法，便于横向对比。 */
    uint32_t h1 = compute_flow_hash(pkt_data, pkt_caplen, 0);
    uint32_t h2 = rss_mix32(h1 ^ 0x9e3779b9U);
    uint64_t key = ((uint64_t)h1 << 32) | h2;
    uint32_t worker_id = rss_table_lookup_or_assign(ctx->rss, ctx, key, h1, h2, ts_ms);
    uint64_t t_enqueue_dispatch_end = get_time_us();
    uint64_t queue_wait_us = 0;
    uint64_t queue_write_us = 0;
    ctx->enqueue_hash_us += (t_enqueue_dispatch_end - t_enqueue_start);

#ifdef NDPI_BENCHMARK_BATCH
    (void)packet_queue_push_cached_timed(ctx->workers[worker_id].queue,
                                         &prod[worker_id],
                                         pkt_data,
                                         pkt_caplen,
                                         pkt_wirelen,
                                         ts_us,
                                         &queue_wait_us,
                                         &queue_write_us);
#else
    (void)packet_queue_push_timed(ctx->workers[worker_id].queue,
                                  pkt_data,
                                  pkt_caplen,
                                  pkt_wirelen,
                                  ts_us,
                                  &queue_wait_us,
                                  &queue_write_us);
#endif
    ctx->enqueue_queue_wait_us += queue_wait_us;
    ctx->enqueue_queue_write_us += queue_write_us;
    ctx->enqueue_us += (t_enqueue_dispatch_end - t_enqueue_start) + queue_wait_us + queue_write_us;
    t_start = get_time_us();
  }

  if (rc == -1 && !g_quiet_mode) {
    fprintf(stderr, "Warning: pcap_next_ex() failed: %s\n", pcap_geterr(handle));
  }

#ifdef NDPI_BENCHMARK_BATCH
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_flush(ctx->workers[i].queue, &prod[i]);
  }
#endif

  pcap_close(handle);
  free(blob.data);

  /* 通知 worker 生产端结束。 */
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_finish(ctx->workers[i].queue);
  }

  ctx->enqueue_us = ctx->enqueue_hash_us + ctx->enqueue_queue_wait_us + ctx->enqueue_queue_write_us;
  ctx->read_time_us = ctx->pcap_read_us + ctx->enqueue_us;
  return NULL;
}
#endif

/* 编译期开关决定 reader 实现：
 * - NDPI_BENCHMARK_MEMREADER: 内存预读模式
 * - 其它: 传统流式读取模式
 */
void *reader_thread_entry(void *arg) {
#ifdef NDPI_BENCHMARK_MEMREADER
  return reader_thread_mem(arg);
#else
  return reader_thread_stream(arg);
#endif
}
