#ifndef NDPI_BENCHMARK_H
#define NDPI_BENCHMARK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "ndpi_api.h"

#define MAX_PACKET_SIZE 65535

/* Parsed view of a packet (Ethernet -> IPv4/IPv6 -> TCP/UDP). */
typedef struct {
  uint8_t ip_version;
  uint8_t l4_proto;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t src_ip[16];
  uint8_t dst_ip[16];
  const uint8_t *l3;
  uint16_t l3_len;
} parsed_packet_t;

typedef enum {
  PARSE_OK = 0,
  PARSE_UNSUPPORTED = 1,
  PARSE_TRUNCATED = 2
} parse_result_t;

typedef struct {
  uint8_t ip_version;
  uint8_t l4_proto;
  uint16_t port_a;
  uint16_t port_b;
  uint8_t addr_a[16];
  uint8_t addr_b[16];
} flow_key_t;

typedef struct {
  uint8_t ip_version;
  uint16_t port;
  uint8_t addr[16];
} endpoint_t;

typedef struct {
  flow_key_t key;

  endpoint_t client;
  endpoint_t server;

  struct ndpi_flow_struct *ndpi_flow;

  uint64_t last_seen_ms;
  uint64_t c2s_packets;
  uint64_t s2c_packets;
  uint64_t c2s_bytes;
  uint64_t s2c_bytes;
  uint64_t seen_packets;

  bool protocol_counted;
  uint64_t first_seen_ns;
  uint64_t detection_latency_ns;
  uint64_t detection_packet_in_flow;
  uint64_t detection_packet_global;
  uint16_t detected_master_proto;
  uint16_t detected_app_proto;
  ndpi_protocol_category_t detected_category;
} bench_flow_t;

struct flow_table;

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
bench_flow_t *flow_table_get_or_create(struct flow_table *ft,
                                       const flow_key_t *key,
                                       uint64_t key_hash,
                                       bool *is_new);

typedef void (*flow_table_iter_cb)(bench_flow_t *flow, void *user);
void flow_table_foreach(struct flow_table *ft, flow_table_iter_cb cb, void *user);
size_t flow_table_size(const struct flow_table *ft);

static inline uint64_t get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#endif
