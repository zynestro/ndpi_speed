#include "benchmark_internal.h"

static inline void reset_reader_timers(reader_context_t *ctx) {
  ctx->read_time_ns = 0;
  ctx->pcap_read_ns = 0;
  ctx->normalize_ns = 0;
  ctx->hash_ns = 0;
  ctx->rss_lookup_ns = 0;
  ctx->enqueue_ns = 0;
  ctx->read_other_ns = 0;
}

static inline void finalize_reader_timers(reader_context_t *ctx) {
  ctx->read_time_ns = ctx->pcap_read_ns + ctx->normalize_ns + ctx->hash_ns +
                      ctx->rss_lookup_ns + ctx->enqueue_ns + ctx->read_other_ns;
}

/* 流式 reader：
 * - 直接从磁盘 pcap_next_ex() 读取
 * - 做链路层标准化
 * - 根据流哈希和 RSS 表把包投递到目标 worker 队列
 *
 * 线程模型：
 * - 单 reader 生产者
 * - 多 worker 消费者（每个 worker 一条独立队列）
 */
#ifndef NDPI_BENCHMARK_MEMREADER
static void *reader_thread_stream(void *arg) {
  reader_context_t *ctx = (reader_context_t *)arg;
  if (ctx->reader_core != UINT32_MAX) {
    set_thread_affinity(ctx->reader_core);
  }
#ifdef NDPI_BENCHMARK_BATCH
  packet_queue_prod_t prod[MAX_WORKERS];
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_init(ctx->workers[i].queue, &prod[i]);
  }
#endif

  reset_reader_timers(ctx);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle = pcap_open_offline(ctx->pcap_file, errbuf);
  if (!handle) {
    fprintf(stderr, "Error opening PCAP: %s\n", errbuf);
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    return NULL;
  }

  struct pcap_pkthdr *header = NULL;
  const u_char *data = NULL;
  int linktype = pcap_datalink(handle);
  uint8_t scratch[MAX_PACKET_SIZE];

  while (1) {
    uint64_t loop_start_ns = get_time_ns();

    uint64_t t_pcap0 = get_time_ns();
    int rc = pcap_next_ex(handle, &header, &data);
    uint64_t t_pcap1 = get_time_ns();
    uint64_t pcap_ns = t_pcap1 - t_pcap0;
    ctx->pcap_read_ns += pcap_ns;

    if (rc <= 0) {
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
      if (loop_ns > known_ns) ctx->read_other_ns += (loop_ns - known_ns);
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
      uint64_t loop_end_ns = get_time_ns();
      uint64_t loop_ns = loop_end_ns - loop_start_ns;
      if (loop_ns > known_ns) ctx->read_other_ns += (loop_ns - known_ns);
      continue;
    }

    uint64_t ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
    uint64_t ts_ms = ts_us / 1000ULL;

    uint64_t t_hash0 = get_time_ns();
    uint32_t h1 = compute_flow_hash(pkt_data, pkt_caplen, 0);
    uint32_t h2 = rss_mix32(h1 ^ 0x9e3779b9U);
    uint64_t key = ((uint64_t)h1 << 32) | h2;
    uint64_t t_hash1 = get_time_ns();
    uint64_t hash_ns = t_hash1 - t_hash0;
    ctx->hash_ns += hash_ns;
    known_ns += hash_ns;

    uint64_t t_rss0 = get_time_ns();
    uint32_t worker_id = rss_table_lookup_or_assign(ctx->rss, ctx, key, h1, h2, ts_ms);
    uint64_t t_rss1 = get_time_ns();
    uint64_t rss_ns = t_rss1 - t_rss0;
    ctx->rss_lookup_ns += rss_ns;
    known_ns += rss_ns;

    uint64_t t_enq0 = get_time_ns();
#ifdef NDPI_BENCHMARK_BATCH
    (void)packet_queue_push_cached(ctx->workers[worker_id].queue,
                                   &prod[worker_id],
                                   pkt_data,
                                   pkt_caplen,
                                   pkt_wirelen,
                                   ts_us);
#else
    (void)packet_queue_push(ctx->workers[worker_id].queue,
                            pkt_data,
                            pkt_caplen,
                            pkt_wirelen,
                            ts_us);
#endif
    uint64_t t_enq1 = get_time_ns();
    uint64_t enq_ns = t_enq1 - t_enq0;
    ctx->enqueue_ns += enq_ns;
    known_ns += enq_ns;

    uint64_t loop_end_ns = get_time_ns();
    uint64_t loop_ns = loop_end_ns - loop_start_ns;
    if (loop_ns > known_ns) ctx->read_other_ns += (loop_ns - known_ns);
  }

#ifdef NDPI_BENCHMARK_BATCH
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_flush(ctx->workers[i].queue, &prod[i]);
  }
#endif

  pcap_close(handle);
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_finish(ctx->workers[i].queue);
  }
  finalize_reader_timers(ctx);
  return NULL;
}
#endif

#ifdef NDPI_BENCHMARK_MEMREADER
typedef struct {
  uint8_t *data;
  size_t size;
} pcap_blob_t;

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
  fclose(fp);

  if (off != size) {
    snprintf(errbuf, errbuf_len, "fread(%s) failed: read %zu/%zu", path, off, size);
    free(buf);
    return false;
  }

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
  packet_queue_prod_t prod[MAX_WORKERS];
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_init(ctx->workers[i].queue, &prod[i]);
  }
#endif

  reset_reader_timers(ctx);

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_blob_t blob = {0};

  /* 内存版额外步骤：文件读入内存。记到 read_other_ns。 */
  uint64_t t_load0 = get_time_ns();
  if (!read_file_to_memory(ctx->pcap_file, &blob, errbuf, sizeof(errbuf))) {
    fprintf(stderr, "Error reading PCAP into memory: %s\n", errbuf);
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    return NULL;
  }
  uint64_t t_load1 = get_time_ns();
  ctx->read_other_ns += (t_load1 - t_load0);

  FILE *memfp = fmemopen(blob.data, blob.size, "rb");
  if (!memfp) {
    fprintf(stderr, "Error: fmemopen() failed: %s\n", strerror(errno));
    free(blob.data);
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
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
    return NULL;
  }

  struct pcap_pkthdr *header = NULL;
  const u_char *data = NULL;
  int linktype = pcap_datalink(handle);
  uint8_t scratch[MAX_PACKET_SIZE];

  while (1) {
    uint64_t loop_start_ns = get_time_ns();

    uint64_t t_pcap0 = get_time_ns();
    int rc = pcap_next_ex(handle, &header, &data);
    uint64_t t_pcap1 = get_time_ns();
    uint64_t pcap_ns = t_pcap1 - t_pcap0;
    ctx->pcap_read_ns += pcap_ns;

    if (rc <= 0) {
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
      if (loop_ns > known_ns) ctx->read_other_ns += (loop_ns - known_ns);
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
      uint64_t loop_end_ns = get_time_ns();
      uint64_t loop_ns = loop_end_ns - loop_start_ns;
      if (loop_ns > known_ns) ctx->read_other_ns += (loop_ns - known_ns);
      continue;
    }

    uint64_t ts_us = (uint64_t)header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
    uint64_t ts_ms = ts_us / 1000ULL;

    uint64_t t_hash0 = get_time_ns();
    uint32_t h1 = compute_flow_hash(pkt_data, pkt_caplen, 0);
    uint32_t h2 = rss_mix32(h1 ^ 0x9e3779b9U);
    uint64_t key = ((uint64_t)h1 << 32) | h2;
    uint64_t t_hash1 = get_time_ns();
    uint64_t hash_ns = t_hash1 - t_hash0;
    ctx->hash_ns += hash_ns;
    known_ns += hash_ns;

    uint64_t t_rss0 = get_time_ns();
    uint32_t worker_id = rss_table_lookup_or_assign(ctx->rss, ctx, key, h1, h2, ts_ms);
    uint64_t t_rss1 = get_time_ns();
    uint64_t rss_ns = t_rss1 - t_rss0;
    ctx->rss_lookup_ns += rss_ns;
    known_ns += rss_ns;

    uint64_t t_enq0 = get_time_ns();
#ifdef NDPI_BENCHMARK_BATCH
    (void)packet_queue_push_cached(ctx->workers[worker_id].queue,
                                   &prod[worker_id],
                                   pkt_data,
                                   pkt_caplen,
                                   pkt_wirelen,
                                   ts_us);
#else
    (void)packet_queue_push(ctx->workers[worker_id].queue,
                            pkt_data,
                            pkt_caplen,
                            pkt_wirelen,
                            ts_us);
#endif
    uint64_t t_enq1 = get_time_ns();
    uint64_t enq_ns = t_enq1 - t_enq0;
    ctx->enqueue_ns += enq_ns;
    known_ns += enq_ns;

    uint64_t loop_end_ns = get_time_ns();
    uint64_t loop_ns = loop_end_ns - loop_start_ns;
    if (loop_ns > known_ns) ctx->read_other_ns += (loop_ns - known_ns);
  }

#ifdef NDPI_BENCHMARK_BATCH
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_flush(ctx->workers[i].queue, &prod[i]);
  }
#endif

  pcap_close(handle);
  free(blob.data);
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_finish(ctx->workers[i].queue);
  }
  finalize_reader_timers(ctx);
  return NULL;
}
#endif

void *reader_thread_entry(void *arg) {
#ifdef NDPI_BENCHMARK_MEMREADER
  return reader_thread_mem(arg);
#else
  return reader_thread_stream(arg);
#endif
}
