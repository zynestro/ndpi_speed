/*
 * ndpiBenchmark.h
 *
 * High-performance nDPI throughput benchmark tool
 * Copyright (C) 2026
 *
 * This file is part of nDPI, an open source deep packet inspection library
 */

#ifndef __NDPI_BENCHMARK_H__
#define __NDPI_BENCHMARK_H__

#include "ndpi_config.h"
#include "ndpi_api.h"
#include "reader_util.h"
#include <pcap.h>
#include <pthread.h>
#include <stdint.h>

/* Configuration constants */
#define MAX_WORKERS 64
#define PREFETCH_OFFSET 4

/* Memory-resident packet structure */
typedef struct {
    uint32_t packet_id;
    uint64_t timestamp_us;
    uint16_t caplen;
    uint16_t wirelen;
    uint8_t data[];  /* Flexible array for packet data */
} mem_packet_t;

/* Packet pool in memory */
typedef struct {
    uint32_t num_packets;
    uint64_t total_bytes;
    mem_packet_t **packets;
    uint8_t *raw_data;
    size_t raw_data_size;
} packet_pool_t;

/* Per-worker context */
typedef struct {
    uint32_t worker_id;
    uint32_t cpu_core;
    
    /* nDPI workflow */
    ndpi_workflow_t *workflow;
    struct ndpi_global_context *g_ctx;
    
    /* Packet assignment */
    uint32_t *packet_indices;
    uint32_t num_packets;
    
    /* Test configuration */
    packet_pool_t *pool;
    uint32_t num_loops;
    uint8_t flow_randomization;
    uint8_t timestamp_jitter;
    
    /* Performance counters */
    uint64_t packets_processed;
    uint64_t flows_detected;
    uint64_t bytes_processed;
    uint64_t cycles_start;
    uint64_t cycles_end;
    
    pthread_t thread;
} worker_context_t;

/* Global benchmark configuration */
typedef struct {
    char *pcap_file;
    uint32_t num_workers;
    uint32_t num_loops;
    uint32_t *core_list;
    uint8_t flow_randomization;
    uint8_t timestamp_jitter;
    uint8_t quiet_mode;
} benchmark_config_t;

/* Function prototypes */

/* Memory management */
packet_pool_t* load_pcap_to_memory(const char *pcap_file);
void free_packet_pool(packet_pool_t *pool);

/* Flow distribution */
uint32_t compute_flow_hash(const uint8_t *data, uint16_t len, uint32_t seed);
void assign_packets_to_workers(packet_pool_t *pool, 
                              worker_context_t *workers,
                              uint32_t num_workers);

/* Flow randomization to avoid cache cheating */
void randomize_packet_tuple(mem_packet_t *pkt, uint32_t loop_id, uint32_t worker_id);
void adjust_packet_timestamp(mem_packet_t *pkt, uint32_t loop_id);

/* Worker thread */
void* worker_thread(void *arg);

/* Initialization */
void init_worker_workflow(worker_context_t *worker);
void cleanup_worker(worker_context_t *worker);

/* Results */
void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                            uint64_t total_cycles, double elapsed_sec);

/* Utility */
static inline uint64_t rdtsc(void) {
#ifdef __x86_64__
    uint32_t lo, hi;
    __asm__ __volatile__ ("rdtsc" : "=a"(lo), "=d"(hi));
    return ((uint64_t)hi << 32) | lo;
#else
    return 0;
#endif
}

#endif /* __NDPI_BENCHMARK_H__ */
