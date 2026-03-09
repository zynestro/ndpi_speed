/*
 * ndpi_benchmark.h
 *
 * Standalone nDPI throughput benchmark (decoupled from nDPI example/reader_util).
 *
 * This project is meant to be built as a third-party application that links
 * against libndpi.
 */

#ifndef NDPI_BENCHMARK_H
#define NDPI_BENCHMARK_H
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif
#include <sys/types.h>
#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Public nDPI API */
#include "ndpi_api.h"

/* Configuration constants */
#define MAX_WORKERS 64
#define PREFETCH_OFFSET 4

/* Memory-resident packet structure */
typedef struct {
  uint32_t packet_id;
  uint64_t timestamp_us;
  uint16_t caplen;
  uint16_t wirelen;
  uint8_t data[]; /* Flexible array for packet data */
} mem_packet_t;

/* Packet pool in memory */
typedef struct {
  uint32_t num_packets;
  uint64_t total_bytes;
  mem_packet_t **packets;
  uint8_t *raw_data;
  size_t raw_data_size;
} packet_pool_t;

/* Forward declaration (defined in flow_table.h) */
struct flow_table;

/* Per-worker context */
typedef struct {
  uint32_t worker_id;
  uint32_t cpu_core;

  /* nDPI */
  struct ndpi_detection_module_struct *ndpi;
  struct ndpi_global_context *g_ctx;

  /* Flow table (owned by the worker) */
  struct flow_table *flows;

  /* Packet assignment */
  uint32_t *packet_indices;
  uint32_t num_packets;

  /* Test configuration */
  packet_pool_t *pool;
  uint32_t num_loops;
  bool flow_randomization;
  bool timestamp_jitter;

  /* Optional nDPI protocols file */
  const char *proto_file;

  /* Performance counters */
  uint64_t packets_processed;
  uint64_t bytes_processed;
  uint64_t flows_created_total;
  uint64_t flows_with_protocol_total;
  uint64_t cycles_start;
  uint64_t cycles_end;

  pthread_t thread;
} worker_context_t;

/* Global benchmark configuration */
typedef struct {
  const char *pcap_file;
  uint32_t num_workers;
  uint32_t num_loops;
  uint32_t *core_list; /* optional list of cores (length num_workers) */
  bool flow_randomization;
  bool timestamp_jitter;
  bool quiet_mode;
  const char *proto_file;
  uint32_t demo_packets; /* if >0, run demo on a single flow */
} benchmark_config_t;

/* benchmark_util.c */
packet_pool_t *load_pcap_to_memory(const char *pcap_file);
void free_packet_pool(packet_pool_t *pool);

uint32_t compute_flow_hash(const uint8_t *data, uint16_t len, uint32_t seed);
void assign_packets_to_workers(packet_pool_t *pool, worker_context_t *workers, uint32_t num_workers);

void randomize_packet_tuple(mem_packet_t *pkt, uint32_t loop_id, uint32_t worker_id);
void adjust_packet_timestamp(mem_packet_t *pkt, uint32_t loop_id);

/* worker */
void *worker_thread(void *arg);

void init_worker_ndpi(worker_context_t *worker);
void cleanup_worker(worker_context_t *worker);

void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                             uint64_t total_cycles, double elapsed_sec);

/* Utility */
static inline uint64_t rdtsc(void) {
#ifdef __x86_64__
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
#else
  return 0;
#endif
}

#endif /* NDPI_BENCHMARK_H */
