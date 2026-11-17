/*
 * ndpi_benchmark.h
 *
 * Single-header interface for the streaming nDPI benchmark.
 * All structs and function declarations live here.
 */

#ifndef NDPI_BENCHMARK_H
#define NDPI_BENCHMARK_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/types.h>
#include <sys/time.h>

#include <pcap.h>
#include <pthread.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdatomic.h>
#include <sched.h>
#include <time.h>

#include "ndpi_api.h"

#define MAX_WORKERS 64
#define PROCESS_TIME_CORE_SLOTS 32
#define QUEUE_CAPACITY 4096
#define QUEUE_COMMIT_BATCH 8

struct flow_table;
#ifdef NDPI_BENCHMARK_CLASSIFIED
struct classified_table;
#endif

/* ========================= Packet Queue ========================= */
/* 队列中每个元素的最大包大小 */
#define MAX_PACKET_SIZE 65535

/* 队列元素：包含完整的包数据副本 */
typedef struct {
  uint64_t timestamp_us;
  uint16_t caplen;
  uint16_t wirelen;
  uint8_t data[MAX_PACKET_SIZE];
} queue_packet_t;

/* 线程安全的环形队列 */
typedef struct {
  queue_packet_t *buffer;     /* 环形缓冲区 */
  uint32_t capacity;          /* 队列容量 */
  uint32_t mask;              /* capacity - 1 (power of two) */
  _Atomic uint32_t head;      /* 写入位置（单调递增） */
  _Atomic uint32_t tail;      /* 读取位置（单调递增） */
  _Atomic bool finished;      /* 生产者已结束标志 */
} packet_queue_t;

typedef struct {
  uint32_t head;     /* 本地写指针（未发布） */
  uint32_t pending;  /* 未发布元素数 */
} packet_queue_prod_t;

static inline void packet_queue_pause(void) {
#if defined(__x86_64__) || defined(__i386__)
  __builtin_ia32_pause();
#else
  sched_yield();
#endif
}

static inline uint32_t queue_round_pow2_u32(uint32_t v) {
  if (v < 2) return 2;
  v--;
  v |= v >> 1;
  v |= v >> 2;
  v |= v >> 4;
  v |= v >> 8;
  v |= v >> 16;
  return v + 1;
}

/* 创建队列 */
static inline packet_queue_t *packet_queue_create(uint32_t capacity) {
  packet_queue_t *q = (packet_queue_t *)calloc(1, sizeof(packet_queue_t));
  if (!q) return NULL;

  q->capacity = queue_round_pow2_u32(capacity);
  q->mask = q->capacity - 1;
  q->buffer = (queue_packet_t *)calloc(q->capacity, sizeof(queue_packet_t));
  if (!q->buffer) {
    free(q);
    return NULL;
  }

  atomic_init(&q->head, 0);
  atomic_init(&q->tail, 0);
  atomic_init(&q->finished, false);

  return q;
}

/* 销毁队列 */
static inline void packet_queue_destroy(packet_queue_t *q) {
  if (!q) return;
  free(q->buffer);
  free(q);
}

/* 入队（生产者调用）- 阻塞直到有空间 */
static inline bool packet_queue_push(packet_queue_t *q,
                                     const uint8_t *data, uint16_t caplen, uint16_t wirelen,
                                     uint64_t timestamp_us) {
  uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  while ((head - tail) >= q->capacity) {
    if (atomic_load_explicit(&q->finished, memory_order_relaxed)) return false;
    packet_queue_pause();
    tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  }

  queue_packet_t *slot = &q->buffer[head & q->mask];
  slot->timestamp_us = timestamp_us;
  slot->caplen = caplen;
  slot->wirelen = wirelen;
  memcpy(slot->data, data, caplen);

  atomic_store_explicit(&q->head, head + 1, memory_order_release);

  return true;
}

/* 观察队首（消费者调用）- 阻塞直到有数据或结束 */
static inline bool packet_queue_peek(packet_queue_t *q, queue_packet_t **out) {
  uint32_t tail = atomic_load_explicit(&q->tail, memory_order_relaxed);
  while (tail == atomic_load_explicit(&q->head, memory_order_acquire)) {
    if (atomic_load_explicit(&q->finished, memory_order_relaxed)) return false;
    packet_queue_pause();
  }

  *out = &q->buffer[tail & q->mask];
  return true;
}

/* 消费一个元素（消费者调用） */
static inline void packet_queue_consume(packet_queue_t *q) {
  atomic_fetch_add_explicit(&q->tail, 1, memory_order_release);
}

/* 队列深度（近似负载） */
static inline uint32_t packet_queue_depth(const packet_queue_t *q) {
  uint32_t head = atomic_load_explicit(&q->head, memory_order_acquire);
  uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  return head - tail;
}

/* 标记队列结束（生产者调用） */
static inline void packet_queue_finish(packet_queue_t *q) {
  atomic_store_explicit(&q->finished, true, memory_order_release);
}

/* Producer 缓存初始化 */
static inline void packet_queue_prod_init(packet_queue_t *q, packet_queue_prod_t *p) {
  p->head = atomic_load_explicit(&q->head, memory_order_relaxed);
  p->pending = 0;
}

/* Producer 提交未发布的元素 */
static inline void packet_queue_prod_flush(packet_queue_t *q, packet_queue_prod_t *p) {
  if (p->pending > 0) {
    atomic_store_explicit(&q->head, p->head, memory_order_release);
    p->pending = 0;
  }
}

/* 入队（生产者调用）- 批量提交版本 */
static inline bool packet_queue_push_cached(packet_queue_t *q,
                                            packet_queue_prod_t *p,
                                            const uint8_t *data, uint16_t caplen,
                                            uint16_t wirelen, uint64_t timestamp_us) {
  uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  while ((p->head - tail) >= q->capacity) {
    if (atomic_load_explicit(&q->finished, memory_order_relaxed)) return false;
    packet_queue_prod_flush(q, p);
    packet_queue_pause();
    tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  }

  queue_packet_t *slot = &q->buffer[p->head & q->mask];
  slot->timestamp_us = timestamp_us;
  slot->caplen = caplen;
  slot->wirelen = wirelen;
  memcpy(slot->data, data, caplen);

  p->head++;
  p->pending++;
  if (p->pending >= QUEUE_COMMIT_BATCH) {
    atomic_store_explicit(&q->head, p->head, memory_order_release);
    p->pending = 0;
  }

  return true;
}

/* Parsed view of a packet (Ethernet -> IPv4/IPv6 -> TCP/UDP) */
typedef struct {
  uint8_t ip_version; /* 4 or 6 */
  uint8_t l4_proto;   /* IPPROTO_TCP, IPPROTO_UDP, ... */

  /* host-order ports (0 if not TCP/UDP or not available) */
  uint16_t src_port;
  uint16_t dst_port;

  /* src/dst address bytes. For IPv4 only first 4 bytes are used. */
  uint8_t src_ip[16];
  uint8_t dst_ip[16];

  /* pointer to L3 header (IP header) within original packet buffer */
  const uint8_t *l3;
  uint16_t l3_len; /* bytes from l3 to end of captured buffer */
} parsed_packet_t;

typedef enum {
  PARSE_OK = 0,
  PARSE_UNSUPPORTED = 1,
  PARSE_TRUNCATED = 2
} parse_result_t;

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

/* Per-worker context */
typedef struct {
  uint32_t worker_id;
  uint32_t cpu_core;

  struct ndpi_detection_module_struct *ndpi;
  struct ndpi_global_context *g_ctx;

  struct flow_table *flows;
#ifdef NDPI_BENCHMARK_CLASSIFIED
  struct classified_table *classified;
#endif
  packet_queue_t *queue;

  const char *proto_file;

  uint64_t packets_processed;
  uint64_t bytes_processed;
  uint64_t flows_created_total;
  uint64_t flows_with_protocol_total;
  uint64_t processing_time_ns;
  uint64_t parse_time_ns;
  uint64_t keybuild_time_ns;
  uint64_t flow_lookup_time_ns;
  uint64_t flow_init_time_ns;
  uint64_t flow_time_ns;
  uint64_t ndpi_call_time_ns;
  uint64_t proto_check_time_ns;
  uint64_t ndpi_time_ns;
  uint64_t classified_fastpath_ns;
  uint64_t other_time_ns;
  _Atomic uint32_t active_flows;   /* reader 侧负载感知用 */
  _Atomic uint64_t proc_ewma_us;   /* 微秒/包的 EWMA */

  pthread_t thread;
} worker_context_t;

/* Global benchmark configuration */
typedef struct {
  const char *pcap_file;
  uint32_t num_workers;
  uint32_t *core_list;
  uint32_t reader_core;
  bool quiet_mode;
  const char *proto_file;
} benchmark_config_t;

uint32_t compute_flow_hash(const uint8_t *data, uint16_t len, uint32_t seed);

void init_worker_ndpi(worker_context_t *worker);
void cleanup_worker(worker_context_t *worker);

void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                             uint64_t total_cycles, double elapsed_sec,
                             uint64_t read_time_ns,
                             uint64_t pcap_read_ns,
                             uint64_t normalize_ns,
                             uint64_t hash_ns,
                             uint64_t rss_lookup_ns,
                             uint64_t enqueue_ns,
                             uint64_t read_other_ns);

static inline uint64_t rdtsc(void) {
#ifdef __x86_64__
  uint32_t lo, hi;
  __asm__ __volatile__("rdtsc" : "=a"(lo), "=d"(hi));
  return ((uint64_t)hi << 32) | lo;
#else
  return 0;
#endif
}

static inline uint64_t get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#endif /* NDPI_BENCHMARK_H */
