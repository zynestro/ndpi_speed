#ifndef BENCHMARK_INTERNAL_H
#define BENCHMARK_INTERNAL_H

#include "ndpi_benchmark.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define RSS_TABLE_INIT_CAP (1u << 18)

struct rss_table;
typedef struct rss_table rss_table_t;

typedef struct {
  const char *pcap_file;
  worker_context_t *workers;
  uint32_t num_workers;
  uint32_t reader_core;
  struct rss_table *rss;
  uint64_t read_time_us;
  uint64_t pcap_read_us;
  uint64_t enqueue_us;
  uint64_t enqueue_hash_us;
  uint64_t enqueue_queue_wait_us;
  uint64_t enqueue_queue_write_us;
} reader_context_t;

extern pthread_mutex_t g_print_mutex;
extern uint64_t g_samples_printed;
extern const uint64_t g_sample_limit;
extern bool g_quiet_mode;

void maybe_print_flow_sample(worker_context_t *w, const bench_flow_t *f);
void set_thread_affinity(uint32_t core);

bool normalize_to_ethernet(int linktype,
                           const uint8_t *data, uint16_t caplen, uint16_t wirelen,
                           const uint8_t **out_data, uint16_t *out_caplen,
                           uint16_t *out_wirelen, uint8_t *scratch,
                           size_t scratch_len);
parse_result_t parse_ethernet_frame(const uint8_t *data, uint16_t caplen, parsed_packet_t *out);
void flow_key_from_packet(const parsed_packet_t *p, flow_key_t *out_key, endpoint_t *out_src, endpoint_t *out_dst);
bool endpoint_equal(const endpoint_t *a, const endpoint_t *b);

uint64_t flow_key_hash(const flow_key_t *k);
struct flow_table *flow_table_create(size_t initial_capacity);
void flow_table_destroy(struct flow_table *ft,
                        void (*on_free)(bench_flow_t *flow, void *user),
                        void *user);
bool flow_table_delete(struct flow_table *ft,
                       const flow_key_t *key,
                       uint64_t key_hash,
                       void (*on_free)(bench_flow_t *flow, void *user),
                       void *user);
bench_flow_t *flow_table_get_or_create(struct flow_table *ft,
                                       const flow_key_t *key,
                                       uint64_t key_hash,
                                       bool *is_new);

#ifdef NDPI_BENCHMARK_CLASSIFIED
struct classified_table *classified_table_create(size_t initial_capacity);
void classified_table_destroy(struct classified_table *ct);
bool classified_table_lookup(const struct classified_table *ct,
                             const flow_key_t *key,
                             uint64_t key_hash,
                             uint16_t *out_app_proto);
void classified_table_insert(struct classified_table *ct,
                             const flow_key_t *key,
                             uint64_t key_hash,
                             uint16_t app_proto);
#endif

rss_table_t *rss_table_create(size_t initial_capacity);
void rss_table_destroy(rss_table_t *rt);
uint32_t rss_mix32(uint32_t x);
uint32_t rss_table_lookup_or_assign(rss_table_t *rt,
                                    const reader_context_t *ctx,
                                    uint64_t key,
                                    uint32_t h1,
                                    uint32_t h2,
                                    uint64_t ts_ms);

void *worker_thread_entry(void *arg);
void *reader_thread_entry(void *arg);

#endif
