/*
 * ndpi_benchmark.h
 *
 * Single-header interface for the streaming nDPI benchmark.
 * All structs and function declarations live here.
 *
 * mark3 视角：
 * - 定义多线程 pipeline 的公共数据结构
 * - 定义 queue / flow / worker / config 等核心对象
 * - 被 reader / worker / parser / flow_table / main 共用
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
#include <stdalign.h>
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
#ifndef QUEUE_PACKET_DATA_SIZE
#define QUEUE_PACKET_DATA_SIZE MAX_PACKET_SIZE
#endif
#ifndef QUEUE_PACKET_USE_REF
#define QUEUE_PACKET_USE_REF 0
#endif

/* 队列元素：默认复制包数据；QUEUE_PACKET_USE_REF=1 时只保存预加载包指针。 */
typedef struct {
  uint64_t timestamp_us;
  const uint8_t *data;
  uint16_t caplen;
  uint16_t wirelen;
  uint32_t retire_cost_x1000;
#if !QUEUE_PACKET_USE_REF
  uint8_t storage[QUEUE_PACKET_DATA_SIZE];
#endif
} queue_packet_t;

/* 线程安全的环形队列 */
typedef struct {
  queue_packet_t *buffer;     /* 环形缓冲区 */
  uint32_t capacity;          /* 队列容量 */
  uint32_t mask;              /* capacity - 1 (power of two) */
  _Atomic uint32_t head;      /* 写入位置（单调递增） */
  _Atomic uint32_t tail;      /* 读取位置（单调递增） */
  _Atomic bool finished;      /* 生产者已结束标志 */
  pthread_mutex_t prod_lock;  /* 多生产者互斥入队 */
} packet_queue_t;

typedef struct {
  uint32_t head;     /* 本地写指针（未发布） */
  uint32_t pending;  /* 未发布元素数 */
  bool locked;       /* 当前 producer 是否持有队列生产者锁 */
} packet_queue_prod_t;

typedef struct {
  const uint8_t *data;
  uint64_t timestamp_us;
  uint16_t caplen;
  uint16_t wirelen;
  uint32_t retire_cost_x1000;
} packet_queue_batch_item_t;

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
  pthread_mutex_init(&q->prod_lock, NULL);

  return q;
}

/* 销毁队列 */
static inline void packet_queue_destroy(packet_queue_t *q) {
  if (!q) return;
  pthread_mutex_destroy(&q->prod_lock);
  free(q->buffer);
  free(q);
}

/* 入队（生产者调用）- 阻塞直到有空间 */
static inline bool packet_queue_push(packet_queue_t *q,
                                     const uint8_t *data, uint16_t caplen, uint16_t wirelen,
                                     uint64_t timestamp_us, uint32_t retire_cost_x1000) {
#if !QUEUE_PACKET_USE_REF
  if (caplen > QUEUE_PACKET_DATA_SIZE) return false;
#endif

  pthread_mutex_lock(&q->prod_lock);

  uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  while ((head - tail) >= q->capacity) {
    if (atomic_load_explicit(&q->finished, memory_order_relaxed)) {
      pthread_mutex_unlock(&q->prod_lock);
      return false;
    }
    packet_queue_pause();
    head = atomic_load_explicit(&q->head, memory_order_relaxed);
    tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  }

  queue_packet_t *slot = &q->buffer[head & q->mask];
  slot->timestamp_us = timestamp_us;
  slot->data = data;
  slot->caplen = caplen;
  slot->wirelen = wirelen;
  slot->retire_cost_x1000 = retire_cost_x1000;
#if !QUEUE_PACKET_USE_REF
  memcpy(slot->storage, data, caplen);
  slot->data = slot->storage;
#endif

  atomic_store_explicit(&q->head, head + 1, memory_order_release);
  pthread_mutex_unlock(&q->prod_lock);

  return true;
}

static inline bool packet_queue_push_batch(packet_queue_t *q,
                                           const packet_queue_batch_item_t *items,
                                           uint32_t count) {
  if (count == 0) return true;
  if (count > q->capacity) return false;
#if !QUEUE_PACKET_USE_REF
  for (uint32_t i = 0; i < count; i++) {
    if (items[i].caplen > QUEUE_PACKET_DATA_SIZE) return false;
  }
#endif

  pthread_mutex_lock(&q->prod_lock);

  uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
  uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  while ((head + count - tail) > q->capacity) {
    if (atomic_load_explicit(&q->finished, memory_order_relaxed)) {
      pthread_mutex_unlock(&q->prod_lock);
      return false;
    }
    packet_queue_pause();
    tail = atomic_load_explicit(&q->tail, memory_order_acquire);
  }

  for (uint32_t i = 0; i < count; i++) {
    const packet_queue_batch_item_t *item = &items[i];
    queue_packet_t *slot = &q->buffer[(head + i) & q->mask];
    slot->timestamp_us = item->timestamp_us;
    slot->data = item->data;
    slot->caplen = item->caplen;
    slot->wirelen = item->wirelen;
    slot->retire_cost_x1000 = item->retire_cost_x1000;
#if !QUEUE_PACKET_USE_REF
    memcpy(slot->storage, item->data, item->caplen);
    slot->data = slot->storage;
#endif
  }

  atomic_store_explicit(&q->head, head + count, memory_order_release);
  pthread_mutex_unlock(&q->prod_lock);

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
  (void)q;
  p->head = 0;
  p->pending = 0;
  p->locked = false;
}

/* Producer 提交未发布的元素 */
static inline void packet_queue_prod_flush(packet_queue_t *q, packet_queue_prod_t *p) {
  if (p->locked) {
    atomic_store_explicit(&q->head, p->head, memory_order_release);
    pthread_mutex_unlock(&q->prod_lock);
    p->locked = false;
  }
  p->pending = 0;
}

/* 入队（生产者调用）- 批量提交版本 */
static inline bool packet_queue_push_cached(packet_queue_t *q,
                                            packet_queue_prod_t *p,
                                            const uint8_t *data, uint16_t caplen,
                                            uint16_t wirelen, uint64_t timestamp_us,
                                            uint32_t retire_cost_x1000) {
#if !QUEUE_PACKET_USE_REF
  if (caplen > QUEUE_PACKET_DATA_SIZE) return false;
#endif

  if (!p->locked) {
    pthread_mutex_lock(&q->prod_lock);

    uint32_t head = atomic_load_explicit(&q->head, memory_order_relaxed);
    uint32_t batch_space = QUEUE_COMMIT_BATCH;
    if (batch_space == 0 || batch_space > q->capacity) batch_space = 1;
    uint32_t tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    while ((head + batch_space - tail) > q->capacity) {
      if (atomic_load_explicit(&q->finished, memory_order_relaxed)) {
        pthread_mutex_unlock(&q->prod_lock);
        return false;
      }
      packet_queue_pause();
      tail = atomic_load_explicit(&q->tail, memory_order_acquire);
    }

    p->head = head;
    p->pending = 0;
    p->locked = true;
  }

  queue_packet_t *slot = &q->buffer[p->head & q->mask];
  slot->timestamp_us = timestamp_us;
  slot->data = data;
  slot->caplen = caplen;
  slot->wirelen = wirelen;
  slot->retire_cost_x1000 = retire_cost_x1000;
#if !QUEUE_PACKET_USE_REF
  memcpy(slot->storage, data, caplen);
  slot->data = slot->storage;
#endif

  p->head++;
  p->pending++;
  if (p->pending >= QUEUE_COMMIT_BATCH) {
    packet_queue_prod_flush(q, p);
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

  /* payload bytes after TCP/UDP header, for lightweight signature lookup */
  const uint8_t *payload;
  uint16_t payload_len;
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

typedef enum {
  CORE_TYPE_P = 0,
  CORE_TYPE_E = 1
} core_type_t;

typedef enum {
  COST_BUCKET_EASY = 0,
  COST_BUCKET_MIDDLE = 1,
  COST_BUCKET_HARD = 2
} cost_bucket_t;

typedef enum {
  DISPATCH_POLICY_RSS = 0,
  DISPATCH_POLICY_JSQ = 1,
  DISPATCH_POLICY_STATIC_POOL = 2,
  DISPATCH_POLICY_OURS = 3,
  DISPATCH_POLICY_ORACLE = 4
} dispatch_policy_t;

#define COST_EASY_X1000   2000U
#define COST_MIDDLE_X1000 7000U
#define COST_HARD_X1000   15000U

#define SPEED_FACTOR_P_X1000 1000U
#define SPEED_FACTOR_E_X1000 1000U
#define COST_CORE_TYPES 2
#define COST_BUCKET_COUNT 3

typedef struct __attribute__((aligned(64))) {
  _Atomic uint64_t added_cost_x1000;
  _Atomic uint64_t retired_cost_x1000;
  _Atomic uint32_t queue_depth;
  uint8_t core_type;
  uint8_t core_id;
  uint16_t speed_factor_x1000;
  uint32_t reserved0;
  uint8_t reserved1[40];
} worker_runtime_state_t;

typedef struct {
  uint16_t port;
  uint8_t prefix[4];
  uint8_t prefix_len;
  uint8_t bucket;
} cost_special_rule_t;

typedef struct {
  uint8_t default_bucket;
  uint8_t port_bucket[65536];
  uint8_t port_present[65536];
  cost_special_rule_t *special_rules;
  size_t num_special_rules;
  size_t cap_special_rules;
} cost_table_t;

typedef struct {
  uint32_t cost_x1000[COST_CORE_TYPES][COST_BUCKET_COUNT];
  bool present[COST_CORE_TYPES][COST_BUCKET_COUNT];
} cost_profile_t;

typedef struct {
  uint64_t lookups;
  uint64_t new_flow_assignments;
  uint64_t existing_flow_hits;
  uint64_t fallback_packets;
  uint64_t oracle_hits;
  uint64_t oracle_misses;
  uint64_t bucket_flow_counts[3];
  uint64_t worker_flow_counts[MAX_WORKERS];
} dispatch_stats_t;

typedef struct {
  uint32_t worker_id;
  uint32_t retire_cost_x1000;
  bool is_new_flow;
} dispatch_result_t;

/* Per-worker context */
typedef struct {
  /* 线程身份信息 */
  uint32_t worker_id;
  uint32_t cpu_core;

  /* 每 worker 独立 nDPI 实例，避免跨线程共享可变状态 */
  struct ndpi_detection_module_struct *ndpi;
  struct ndpi_global_context *g_ctx;

  /* 每 worker 私有状态容器 */
  struct flow_table *flows;
#ifdef NDPI_BENCHMARK_CLASSIFIED
  struct classified_table *classified;
#endif
  packet_queue_t *queue;
  worker_runtime_state_t *runtime;

  /* 可选协议配置文件路径 */
  const char *proto_file;

  /* 核心处理统计（用于最终汇总） */
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

  /* 预留给 reader 侧的负载感知（当前主要用于扩展） */
  _Atomic uint32_t active_flows;   /* reader 侧负载感知用 */
  _Atomic uint64_t proc_ewma_us;   /* 微秒/包的 EWMA */

  pthread_t thread;
} worker_context_t;

/* Global benchmark configuration */
typedef struct {
  const char *pcap_file;
  uint32_t num_workers;
  uint32_t *core_list;
  uint32_t num_dispatchers;
  uint32_t *dispatcher_core_list;
  bool quiet_mode;
  const char *proto_file;
  const char *lookup_file;
  const char *cost_profile_file;
  const char *oracle_file;
  dispatch_policy_t policy;
} benchmark_config_t;

uint32_t compute_flow_hash(const uint8_t *data, uint16_t len, uint32_t seed);

void init_worker_ndpi(worker_context_t *worker);
void cleanup_worker(worker_context_t *worker);

void print_benchmark_results(worker_context_t *workers, uint32_t num_workers,
                             uint64_t total_cycles, double elapsed_sec,
                             uint64_t preprocess_ns,
                             uint64_t preprocess_pcap_read_ns,
                             uint64_t preprocess_normalize_ns,
                             uint64_t preprocess_hash_ns,
                             uint64_t preprocess_dispatch_rss_ns,
                             uint64_t preprocess_store_ns,
                             uint64_t preprocess_schedule_ns,
                             uint64_t preprocess_other_ns,
                             uint64_t dispatch_time_ns,
                             uint64_t dispatch_rss_lookup_ns,
                             uint64_t dispatch_enqueue_ns,
                             uint64_t dispatch_other_ns);

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
