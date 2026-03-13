#include "benchmark_internal.h"

#define RSS_FLOW_TIMEOUT_MS 120000ULL

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
  size_t capacity;
  size_t size;
  size_t used;
  uint64_t rng_state;
  pthread_mutex_t lock;
};

static size_t next_pow2(size_t x) {
  if (x < 2) return 2;
  x--;
  for (size_t i = 1; i < sizeof(size_t) * 8; i <<= 1) x |= x >> i;
  return x + 1;
}

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
  rt->rng_state = 0x9e3779b97f4a7c15ULL;
  pthread_mutex_init(&rt->lock, NULL);
  return rt;
}

void rss_table_destroy(rss_table_t *rt) {
  if (!rt) return;
  pthread_mutex_destroy(&rt->lock);
  free(rt->slots);
  free(rt);
}

static void rss_table_rehash(rss_table_t *rt, size_t new_cap) {
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

uint32_t rss_mix32(uint32_t x) {
  x ^= x >> 16;
  x *= 0x7feb352dU;
  x ^= x >> 15;
  x *= 0x846ca68bU;
  x ^= x >> 16;
  return x;
}

static uint32_t rss_select_worker_random(rss_table_t *rt, uint32_t num_workers) {
  if (num_workers <= 1) return 0;

  rt->rng_state = rt->rng_state * 6364136223846793005ULL + 1ULL;
  uint32_t r = (uint32_t)(rt->rng_state >> 32);
  return r % num_workers;
}

static uint32_t rss_select_worker_p2c(const reader_context_t *ctx, uint64_t key) {
  if (!ctx || ctx->num_workers <= 1) return 0;

  uint32_t h1 = (uint32_t)key;
  uint32_t h2 = rss_mix32((uint32_t)(key >> 32) ^ 0x9e3779b9U);
  uint32_t w0 = h1 % ctx->num_workers;
  uint32_t w1 = h2 % ctx->num_workers;
  if (w0 == w1) return w0;

  uint32_t d0 = packet_queue_depth(ctx->workers[w0].queue);
  uint32_t d1 = packet_queue_depth(ctx->workers[w1].queue);
  return (d0 <= d1) ? w0 : w1;
}

uint32_t rss_table_lookup_or_assign(rss_table_t *rt,
                                    const reader_context_t *ctx,
                                    uint64_t key,
                                    uint64_t ts_ms) {
  if (!rt || !ctx || ctx->num_workers == 0) return 0;

  pthread_mutex_lock(&rt->lock);

  if ((rt->used + 1) * 10 >= rt->capacity * 7) {
    rss_table_rehash(rt, rt->capacity * 2);
  }

  size_t mask = rt->capacity - 1;
  size_t idx = (size_t)key & mask;
  size_t first_deleted = (size_t)-1;
  uint32_t out = 0;

  while (true) {
    rss_slot_t *s = &rt->slots[idx];

    if (s->state == RSS_EMPTY) {
      size_t ins = (first_deleted != (size_t)-1) ? first_deleted : idx;
      rss_slot_t *dst = &rt->slots[ins];
      uint32_t wid = rss_select_worker_p2c(ctx, key);

      dst->state = RSS_USED;
      dst->key = key;
      dst->worker_id = wid;
      dst->last_seen_ms = ts_ms;

      rt->size++;
      if (first_deleted == (size_t)-1) {
        rt->used++;
      }
      out = wid;
      break;
    }

    if (s->state == RSS_DELETED) {
      if (first_deleted == (size_t)-1) first_deleted = idx;
    } else if (s->key == key) {
      if (ts_ms > s->last_seen_ms && (ts_ms - s->last_seen_ms) > RSS_FLOW_TIMEOUT_MS) {
        s->worker_id = rss_select_worker_p2c(ctx, key);
      }
      s->last_seen_ms = ts_ms;
      out = s->worker_id;
      break;
    }

    idx = (idx + 1) & mask;
  }

  pthread_mutex_unlock(&rt->lock);
  return out;
}

uint32_t rss_table_lookup_or_assign_target(rss_table_t *rt,
                                           uint32_t num_targets,
                                           uint64_t key,
                                           uint64_t ts_ms) {
  if (!rt || num_targets == 0) return 0;

  pthread_mutex_lock(&rt->lock);

  if ((rt->used + 1) * 10 >= rt->capacity * 7) {
    rss_table_rehash(rt, rt->capacity * 2);
  }

  size_t mask = rt->capacity - 1;
  size_t idx = (size_t)key & mask;
  size_t first_deleted = (size_t)-1;
  uint32_t out = 0;

  while (true) {
    rss_slot_t *s = &rt->slots[idx];

    if (s->state == RSS_EMPTY) {
      size_t ins = (first_deleted != (size_t)-1) ? first_deleted : idx;
      rss_slot_t *dst = &rt->slots[ins];
      uint32_t wid = rss_select_worker_random(rt, num_targets);

      dst->state = RSS_USED;
      dst->key = key;
      dst->worker_id = wid;
      dst->last_seen_ms = ts_ms;

      rt->size++;
      if (first_deleted == (size_t)-1) {
        rt->used++;
      }
      out = wid;
      break;
    }

    if (s->state == RSS_DELETED) {
      if (first_deleted == (size_t)-1) first_deleted = idx;
    } else if (s->key == key) {
      if (ts_ms > s->last_seen_ms && (ts_ms - s->last_seen_ms) > RSS_FLOW_TIMEOUT_MS) {
        s->worker_id = rss_select_worker_random(rt, num_targets);
      }
      s->last_seen_ms = ts_ms;
      out = s->worker_id;
      break;
    }

    idx = (idx + 1) & mask;
  }

  pthread_mutex_unlock(&rt->lock);
  return out;
}
