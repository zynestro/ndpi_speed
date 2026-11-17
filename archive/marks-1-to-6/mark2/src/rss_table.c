#include "benchmark_internal.h"

/* flow 在 RSS 表中的粘性映射超时时间：
 * 超时后允许该 key 重新选择 worker，避免长期粘在过载 worker。
 */
#define RSS_FLOW_TIMEOUT_MS 120000ULL

/* RSS 哈希表槽位状态。 */
typedef enum {
  RSS_EMPTY = 0,
  RSS_USED = 1,
  RSS_DELETED = 2
} rss_state_t;

typedef struct {
  uint64_t key;
  uint32_t worker_id;
  uint64_t last_seen_ms;
  rss_state_t state;
} rss_slot_t;

struct rss_table {
  rss_slot_t *slots;
  size_t capacity; /* 槽位总数（2 的幂） */
  size_t size;     /* 当前有效映射数（USED） */
  size_t used;     /* USED + DELETED，用于扩容判断 */
};

/* 容量归整到 2 的幂，便于位与寻址。 */
static size_t next_pow2(size_t x) {
  if (x < 2) return 2;
  x--;
  for (size_t i = 1; i < sizeof(size_t) * 8; i <<= 1) x |= x >> i;
  return x + 1;
}

/* 创建 RSS 表。 */
rss_table_t *rss_table_create(size_t initial_capacity) {
  rss_table_t *rt = (rss_table_t *)calloc(1, sizeof(rss_table_t));
  if (!rt) return NULL;

  rt->capacity = next_pow2(initial_capacity > 16 ? initial_capacity : 16);
  rt->slots = (rss_slot_t *)calloc(rt->capacity, sizeof(rss_slot_t));
  if (!rt->slots) {
    free(rt);
    return NULL;
  }

  rt->size = 0;
  rt->used = 0;
  return rt;
}

/* 销毁 RSS 表。 */
void rss_table_destroy(rss_table_t *rt) {
  if (!rt) return;
  free(rt->slots);
  free(rt);
}

/* RSS 表扩容重哈希，清理 DELETED 槽位。 */
static void rss_table_rehash(rss_table_t *rt, size_t new_cap) {
  if (!rt) return;

  new_cap = next_pow2(new_cap);
  rss_slot_t *old = rt->slots;
  size_t old_cap = rt->capacity;

  rt->slots = (rss_slot_t *)calloc(new_cap, sizeof(rss_slot_t));
  if (!rt->slots) {
    rt->slots = old;
    return;
  }

  rt->capacity = new_cap;
  rt->size = 0;
  rt->used = 0;

  for (size_t i = 0; i < old_cap; i++) {
    if (old[i].state != RSS_USED) continue;
    size_t mask = new_cap - 1;
    size_t idx = (size_t)old[i].key & mask;
    while (rt->slots[idx].state == RSS_USED) {
      idx = (idx + 1) & mask;
    }
    rt->slots[idx] = old[i];
    rt->slots[idx].state = RSS_USED;
    rt->size++;
    rt->used++;
  }

  free(old);
}

/* 32-bit 混合函数，用于构造第二候选哈希。 */
uint32_t rss_mix32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

#ifdef NDPI_BENCHMARK_AGGRESSIVE_LB
/* 激进负载均衡参数：
 * - 多候选选择降低碰撞概率
 * - 候选都较拥塞时退化为全局扫描最浅队列
 */
#define RSS_LB_CANDIDATES 4u
#define RSS_LB_SCAN_THRESHOLD (QUEUE_CAPACITY / 3u)

static inline uint32_t worker_queue_depth(const reader_context_t *ctx, uint32_t wid) {
  return packet_queue_depth(ctx->workers[wid].queue);
}

static uint32_t rss_select_worker_aggressive(const reader_context_t *ctx, uint32_t h1, uint32_t h2) {
  if (ctx->num_workers == 1) return 0;

  uint32_t cand[RSS_LB_CANDIDATES];
  cand[0] = h1 % ctx->num_workers;
  cand[1] = h2 % ctx->num_workers;
  cand[2] = rss_mix32(h1 ^ 0x85ebca6bU) % ctx->num_workers;
  cand[3] = rss_mix32(h2 ^ 0xc2b2ae35U) % ctx->num_workers;

  uint32_t best = cand[0];
  uint32_t best_depth = worker_queue_depth(ctx, best);

  for (uint32_t i = 1; i < RSS_LB_CANDIDATES; i++) {
    uint32_t w = cand[i];
    uint32_t d = worker_queue_depth(ctx, w);
    if (d < best_depth || (d == best_depth && w < best)) {
      best = w;
      best_depth = d;
    }
  }

  /* 候选都偏满时，做一次全局最浅队列兜底。 */
  if (best_depth >= RSS_LB_SCAN_THRESHOLD) {
    for (uint32_t w = 0; w < ctx->num_workers; w++) {
      uint32_t d = worker_queue_depth(ctx, w);
      if (d < best_depth || (d == best_depth && w < best)) {
        best = w;
        best_depth = d;
      }
    }
  }

  return best;
}
#endif

/* 两候选 worker 选择策略（power-of-two choices）：
 * - 候选: w0 = h1 % N, w1 = h2 % N
 * - 选择队列更浅者
 *
 * 这样做通常比单哈希取模更均衡，同时只多做一次队列深度读取。
 */
static uint32_t rss_select_worker(const reader_context_t *ctx, uint32_t h1, uint32_t h2) {
  if (ctx->num_workers == 1) return 0;

  uint32_t w0 = h1 % ctx->num_workers;
#ifdef NDPI_BENCHMARK_SINGLEHASH
  /* 单哈希版本：直接按 h1 映射到 worker。 */
  (void)h2;
  return w0;
#elif defined(NDPI_BENCHMARK_AGGRESSIVE_LB)
  return rss_select_worker_aggressive(ctx, h1, h2);
#else
  uint32_t w1 = h2 % ctx->num_workers;
  if (w0 == w1) return w0;

  uint32_t d0 = packet_queue_depth(ctx->workers[w0].queue);
  uint32_t d1 = packet_queue_depth(ctx->workers[w1].queue);
  return (d0 <= d1) ? w0 : w1;
#endif
}

/* 查询或分配 flow->worker 映射：
 * - 命中: 返回已有 worker，必要时按超时规则重选
 * - 未命中: 选 worker 后插入新映射
 *
 * 一致性目标：
 * - 同一活跃流尽量保持粘性，避免跨 worker 迁移破坏缓存局部性
 * - 长时间未见流可重分配，避免历史映射拖累负载均衡
 */
uint32_t rss_table_lookup_or_assign(rss_table_t *rt,
                                    const reader_context_t *ctx,
                                    uint64_t key,
                                    uint32_t h1,
                                    uint32_t h2,
                                    uint64_t ts_ms) {
  if (!rt) return 0;

  /* used 负载因子超过约 0.7 时扩容。 */
  if ((rt->used + 1) * 10 >= rt->capacity * 7) {
    rss_table_rehash(rt, rt->capacity * 2);
  }

  size_t mask = rt->capacity - 1;
  size_t idx = (size_t)key & mask;
  size_t first_deleted = (size_t)-1;

  while (true) {
    rss_slot_t *s = &rt->slots[idx];

    if (s->state == RSS_EMPTY) {
      /* 新 key：插入并返回所选 worker。 */
      size_t ins = (first_deleted != (size_t)-1) ? first_deleted : idx;
      rss_slot_t *dst = &rt->slots[ins];
      uint32_t wid = rss_select_worker(ctx, h1, h2);

      dst->state = RSS_USED;
      dst->key = key;
      dst->worker_id = wid;
      dst->last_seen_ms = ts_ms;

      rt->size++;
      if (first_deleted == (size_t)-1) {
        rt->used++;
      }
      return wid;
    }

    if (s->state == RSS_DELETED) {
      if (first_deleted == (size_t)-1) first_deleted = idx;
    } else if (s->key == key) {
      /* 已有 key：超时则允许重选 worker，然后刷新 last_seen。 */
      if (ts_ms > s->last_seen_ms && (ts_ms - s->last_seen_ms) > RSS_FLOW_TIMEOUT_MS) {
        s->worker_id = rss_select_worker(ctx, h1, h2);
      }
      s->last_seen_ms = ts_ms;
      return s->worker_id;
    }

    idx = (idx + 1) & mask;
  }
}
