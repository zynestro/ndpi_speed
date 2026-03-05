#ifndef FLOW_TABLE_H
#define FLOW_TABLE_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "ndpi_benchmark.h"
#include "packet_parser.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Canonical bidirectional flow key (so both directions map to the same entry) */
typedef struct {
  uint8_t ip_version; /* 4 or 6 */
  uint8_t l4_proto;   /* IPPROTO_TCP, IPPROTO_UDP, ... */
  uint16_t port_a;
  uint16_t port_b;
  uint8_t addr_a[16];
  uint8_t addr_b[16];
} flow_key_t;

/* Endpoint in original direction (client/server determination) */
typedef struct {
  uint8_t ip_version; /* 4 or 6 */
  uint16_t port;      /* host-order */
  uint8_t addr[16];
} endpoint_t;

/* Flow entry (owned by a worker thread) */
typedef struct {
  flow_key_t key;

  endpoint_t client;
  endpoint_t server;

  /* nDPI per-flow state */
  struct ndpi_flow_struct *ndpi_flow;

  /* Bookkeeping */
  uint64_t last_seen_ms;
  uint64_t c2s_packets;
  uint64_t s2c_packets;
  uint64_t c2s_bytes;
  uint64_t s2c_bytes;
  uint64_t seen_packets;

  /* Set to true once we have counted this flow as "protocol detected" */
  bool protocol_counted;
} bench_flow_t;

typedef struct flow_table flow_table_t;

flow_table_t *flow_table_create(size_t initial_capacity);
void flow_table_destroy(flow_table_t *ft, void (*on_free)(bench_flow_t *flow, void *user), void *user);

/* Clears all flows (calls on_free for each entry). */
void flow_table_clear(flow_table_t *ft, void (*on_free)(bench_flow_t *flow, void *user), void *user);

/* Current number of live flows */
size_t flow_table_size(const flow_table_t *ft);

/*
 * Lookup or create a flow.
 *
 * - If it exists: returns existing pointer.
 * - If not: creates a new bench_flow_t, calls on_new(flow,...), inserts, and returns it.
 */
bench_flow_t *flow_table_get_or_create(flow_table_t *ft,
                                      const flow_key_t *key,
                                      uint64_t key_hash,
                                      void (*on_new)(bench_flow_t *flow, void *user),
                                      void *user,
                                      bool *is_new);

/* Small helpers */
uint64_t flow_key_hash(const flow_key_t *k);
void flow_key_from_packet(const parsed_packet_t *p, flow_key_t *out_key, endpoint_t *out_src, endpoint_t *out_dst);
bool endpoint_equal(const endpoint_t *a, const endpoint_t *b);

#ifdef __cplusplus
}
#endif

#endif /* FLOW_TABLE_H */
