#include "benchmark_internal.h"

typedef struct {
  uint64_t timestamp_us;
  uint16_t caplen;
  uint16_t wirelen;
  uint8_t data[MAX_PACKET_SIZE];
} dispatch_packet_t;

typedef struct {
  reader_context_t *ctx;
  uint32_t dispatcher_id;
  uint32_t cpu_core;
} dispatcher_arg_t;

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

static bool append_packet(dispatch_packet_t **pkts, size_t *count, size_t *cap,
                          const uint8_t *data, uint16_t caplen,
                          uint16_t wirelen, uint64_t ts_us) {
  if (*count == *cap) {
    size_t new_cap = (*cap == 0) ? 8192 : (*cap * 2);
    dispatch_packet_t *next =
        (dispatch_packet_t *)realloc(*pkts, new_cap * sizeof(dispatch_packet_t));
    if (!next) return false;
    *pkts = next;
    *cap = new_cap;
  }

  dispatch_packet_t *p = &(*pkts)[*count];
  p->timestamp_us = ts_us;
  p->caplen = caplen;
  p->wirelen = wirelen;
  memcpy(p->data, data, caplen);
  (*count)++;
  return true;
}

static bool load_pcap_packets(reader_context_t *ctx,
                              dispatch_packet_t **out_packets,
                              size_t *out_count) {
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

    uint64_t t_copy0 = get_time_ns();
    bool pushed = append_packet(&packets, &count, &cap, pkt_data, pkt_caplen, pkt_wirelen, ts_us);
    uint64_t t_copy1 = get_time_ns();
    known_ns += (t_copy1 - t_copy0);
    if (!pushed) {
      fprintf(stderr, "Error: out of memory while loading packets\n");
      free(packets);
      pcap_close(handle);
      return false;
    }

    uint64_t loop_end_ns = get_time_ns();
    uint64_t loop_ns = loop_end_ns - loop_start_ns;
    if (loop_ns > known_ns) ctx->read_other_ns += (loop_ns - known_ns);
  }

  pcap_close(handle);
  *out_packets = packets;
  *out_count = count;
  return true;
}

static void merge_dispatcher_stats(reader_context_t *ctx,
                                   uint64_t hash_ns,
                                   uint64_t rss_lookup_ns,
                                   uint64_t enqueue_ns,
                                   uint64_t read_other_ns) {
  pthread_mutex_lock(&ctx->stats_lock);
  ctx->hash_ns += hash_ns;
  ctx->rss_lookup_ns += rss_lookup_ns;
  ctx->enqueue_ns += enqueue_ns;
  ctx->read_other_ns += read_other_ns;
  pthread_mutex_unlock(&ctx->stats_lock);
}

static void *dispatcher_thread_entry(void *arg) {
  dispatcher_arg_t *darg = (dispatcher_arg_t *)arg;
  reader_context_t *ctx = darg->ctx;

  if (darg->cpu_core != UINT32_MAX) {
    set_thread_affinity(darg->cpu_core);
  }

#ifdef NDPI_BENCHMARK_BATCH
  packet_queue_prod_t prod[MAX_WORKERS];
  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_prod_init(ctx->workers[i].queue, &prod[i]);
  }
#endif

  uint64_t hash_ns = 0;
  uint64_t rss_lookup_ns = 0;
  uint64_t enqueue_ns = 0;
  uint64_t read_other_ns = 0;

  while (1) {
    uint64_t loop_start_ns = get_time_ns();

    size_t idx = atomic_fetch_add_explicit(&ctx->next_packet_idx, 1, memory_order_relaxed);
    if (idx >= ctx->packet_count) break;

    const dispatch_packet_t *packets = (const dispatch_packet_t *)ctx->packets;
    const dispatch_packet_t *pkt = &packets[idx];
    uint64_t known_ns = 0;

    uint64_t t_hash0 = get_time_ns();
    uint32_t h1 = compute_flow_hash(pkt->data, pkt->caplen, 0);
    uint32_t h2 = rss_mix32(h1 ^ 0x9e3779b9U);
    uint64_t key = ((uint64_t)h1 << 32) | h2;
    uint64_t t_hash1 = get_time_ns();
    uint64_t d_hash_ns = t_hash1 - t_hash0;
    hash_ns += d_hash_ns;
    known_ns += d_hash_ns;

    uint64_t ts_ms = pkt->timestamp_us / 1000ULL;

    uint64_t t_rss0 = get_time_ns();
    uint32_t worker_id = rss_table_lookup_or_assign(ctx->rss, ctx, key, ts_ms);
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
                                   pkt->timestamp_us);
#else
    (void)packet_queue_push(ctx->workers[worker_id].queue,
                            pkt->data,
                            pkt->caplen,
                            pkt->wirelen,
                            pkt->timestamp_us);
#endif
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

  merge_dispatcher_stats(ctx, hash_ns, rss_lookup_ns, enqueue_ns, read_other_ns);
  return NULL;
}

void *reader_thread_entry(void *arg) {
  reader_context_t *ctx = (reader_context_t *)arg;
  reset_reader_timers(ctx);
  pthread_mutex_init(&ctx->stats_lock, NULL);

  uint64_t t_load0 = get_time_ns();
  dispatch_packet_t *packets = NULL;
  size_t packet_count = 0;
  if (!load_pcap_packets(ctx, &packets, &packet_count)) {
    for (uint32_t i = 0; i < ctx->num_workers; i++) {
      packet_queue_finish(ctx->workers[i].queue);
    }
    pthread_mutex_destroy(&ctx->stats_lock);
    finalize_reader_timers(ctx);
    return NULL;
  }
  ctx->packets = packets;
  ctx->packet_count = packet_count;
  uint64_t t_load1 = get_time_ns();
  ctx->read_other_ns += (t_load1 - t_load0);

  atomic_store_explicit(&ctx->next_packet_idx, 0, memory_order_relaxed);

  pthread_t dispatchers[MAX_WORKERS];
  dispatcher_arg_t dargs[MAX_WORKERS];

  for (uint32_t i = 0; i < ctx->num_dispatchers; i++) {
    dargs[i].ctx = ctx;
    dargs[i].dispatcher_id = i;
    dargs[i].cpu_core = ctx->dispatcher_cores ? ctx->dispatcher_cores[i] : UINT32_MAX;
    if (pthread_create(&dispatchers[i], NULL, dispatcher_thread_entry, &dargs[i]) != 0) {
      fprintf(stderr, "Error: pthread_create(dispatcher=%u) failed\n", i);
      for (uint32_t j = 0; j < i; j++) {
        pthread_join(dispatchers[j], NULL);
      }
      for (uint32_t w = 0; w < ctx->num_workers; w++) {
        packet_queue_finish(ctx->workers[w].queue);
      }
      free(ctx->packets);
      ctx->packets = NULL;
      ctx->packet_count = 0;
      pthread_mutex_destroy(&ctx->stats_lock);
      finalize_reader_timers(ctx);
      return NULL;
    }
  }

  for (uint32_t i = 0; i < ctx->num_dispatchers; i++) {
    pthread_join(dispatchers[i], NULL);
  }

  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    packet_queue_finish(ctx->workers[i].queue);
  }

  free(ctx->packets);
  ctx->packets = NULL;
  ctx->packet_count = 0;
  pthread_mutex_destroy(&ctx->stats_lock);
  finalize_reader_timers(ctx);
  return NULL;
}
