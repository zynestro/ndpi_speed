#include "benchmark_internal.h"

/* 开放寻址哈希表槽位状态。 */
typedef enum {
  SLOT_EMPTY = 0,
  SLOT_USED = 1,
  SLOT_DELETED = 2
} slot_state_t;

typedef struct {
  slot_state_t state;
  uint64_t hash;
  flow_key_t key;
  bench_flow_t *flow;
} slot_t;

struct flow_table {
  slot_t *slots;
  size_t capacity; /* 槽位总数（2 的幂） */
  size_t size;     /* 当前有效元素数（USED） */
  size_t used;     /* USED + DELETED，用于负载因子/扩容判断 */
};

/* 64-bit FNV-1a：用于 flow_key 哈希。 */
static inline uint64_t fnv1a64(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

/* flow_key 的稳定哈希函数。 */
uint64_t flow_key_hash(const flow_key_t *k) {
  return fnv1a64(k, sizeof(*k));
}

/* flow_key 全字段比较。 */
static inline bool flow_key_equal(const flow_key_t *a, const flow_key_t *b) {
  return memcmp(a, b, sizeof(*a)) == 0;
}

/* 把容量规整到 2 的幂，便于位与取模。 */
static size_t next_pow2(size_t x) {
  if (x < 2) return 2;
  x--;
  for (size_t i = 1; i < sizeof(size_t) * 8; i <<= 1) x |= x >> i;
  return x + 1;
}

/* 扩容重哈希：
 * 只搬迁 USED 槽位，丢弃 DELETED tombstone，恢复探测性能。
 */
static void flow_table_rehash(struct flow_table *ft, size_t new_cap) {
  new_cap = next_pow2(new_cap);
  slot_t *old = ft->slots;
  size_t old_cap = ft->capacity;

  ft->slots = (slot_t *)calloc(new_cap, sizeof(slot_t));
  ft->capacity = new_cap;
  ft->size = 0;
  ft->used = 0;

  for (size_t i = 0; i < old_cap; i++) {
    if (old[i].state != SLOT_USED) continue;

    uint64_t h = old[i].hash;
    size_t mask = new_cap - 1;
    size_t idx = (size_t)h & mask;
    while (ft->slots[idx].state == SLOT_USED) {
      idx = (idx + 1) & mask;
    }

    ft->slots[idx] = old[i];
    ft->slots[idx].state = SLOT_USED;
    ft->size++;
    ft->used++;
  }

  free(old);
}

/* 创建 flow table（最小容量 16，且为 2 的幂）。 */
struct flow_table *flow_table_create(size_t initial_capacity) {
  struct flow_table *ft = (struct flow_table *)calloc(1, sizeof(struct flow_table));
  if (!ft) return NULL;

  ft->capacity = next_pow2(initial_capacity > 16 ? initial_capacity : 16);
  ft->slots = (slot_t *)calloc(ft->capacity, sizeof(slot_t));
  if (!ft->slots) {
    free(ft);
    return NULL;
  }

  ft->size = 0;
  ft->used = 0;
  return ft;
}

/* 清空表并通过回调释放 flow 对象。 */
static void flow_table_clear(struct flow_table *ft,
                             void (*on_free)(bench_flow_t *flow, void *user),
                             void *user) {
  if (!ft) return;

  if (on_free) {
    for (size_t i = 0; i < ft->capacity; i++) {
      if (ft->slots[i].state == SLOT_USED && ft->slots[i].flow) {
        on_free(ft->slots[i].flow, user);
      }
    }
  }

  for (size_t i = 0; i < ft->capacity; i++) {
    ft->slots[i].state = SLOT_EMPTY;
    ft->slots[i].hash = 0;
    ft->slots[i].flow = NULL;
  }

  ft->size = 0;
  ft->used = 0;
}

/* 销毁表。 */
void flow_table_destroy(struct flow_table *ft,
                        void (*on_free)(bench_flow_t *flow, void *user),
                        void *user) {
  if (!ft) return;
  flow_table_clear(ft, on_free, user);
  free(ft->slots);
  free(ft);
}

/* 删除指定 key：
 * 命中后标记为 DELETED（tombstone），保持探测链正确性。
 */
bool flow_table_delete(struct flow_table *ft,
                       const flow_key_t *key,
                       uint64_t key_hash,
                       void (*on_free)(bench_flow_t *flow, void *user),
                       void *user) {
  if (!ft) return false;

  size_t mask = ft->capacity - 1;
  size_t idx = (size_t)key_hash & mask;

  while (true) {
    slot_t *s = &ft->slots[idx];
    if (s->state == SLOT_EMPTY) {
      return false;
    }
    if (s->state == SLOT_USED && s->hash == key_hash && flow_key_equal(&s->key, key)) {
      if (on_free && s->flow) on_free(s->flow, user);
      s->state = SLOT_DELETED;
      s->flow = NULL;
      ft->size--;
      return true;
    }
    idx = (idx + 1) & mask;
  }
}

/* 查找或创建 flow：
 * - 命中返回已有 flow，is_new=false
 * - 未命中创建新 flow，is_new=true
 *
 * 探测策略：
 * - 线性探测
 * - 记录 first_deleted，实现“延迟复用 tombstone”
 */
bench_flow_t *flow_table_get_or_create(struct flow_table *ft,
                                       const flow_key_t *key,
                                       uint64_t key_hash,
                                       bool *is_new) {
  if (!ft) return NULL;

  /* used 负载因子超过约 0.7 时扩容。 */
  if ((ft->used + 1) * 10 >= ft->capacity * 7) {
    flow_table_rehash(ft, ft->capacity * 2);
  }

  size_t mask = ft->capacity - 1;
  size_t idx = (size_t)key_hash & mask;
  size_t first_deleted = (size_t)-1;

  while (true) {
    slot_t *s = &ft->slots[idx];

    if (s->state == SLOT_EMPTY) {
      /* 插入优先复用第一个 tombstone，减少 used 膨胀。 */
      size_t ins = (first_deleted != (size_t)-1) ? first_deleted : idx;
      slot_t *dst = &ft->slots[ins];

      bench_flow_t *f = (bench_flow_t *)calloc(1, sizeof(bench_flow_t));
      if (!f) return NULL;
      f->key = *key;

      dst->state = SLOT_USED;
      dst->hash = key_hash;
      dst->key = *key;
      dst->flow = f;

      ft->size++;
      if (first_deleted == (size_t)-1) {
        ft->used++;
      }

      if (is_new) *is_new = true;
      return f;
    }

    if (s->state == SLOT_DELETED) {
      if (first_deleted == (size_t)-1) first_deleted = idx;
    } else if (s->hash == key_hash && flow_key_equal(&s->key, key)) {
      if (is_new) *is_new = false;
      return s->flow;
    }

    idx = (idx + 1) & mask;
  }
}

#ifdef NDPI_BENCHMARK_CLASSIFIED
/* classified table:
 * 仅保存“已识别协议”的 flow_key -> app_proto 映射，
 * 让后续同流包可绕过 nDPI 重复处理。
 *
 * 该表只在 worker 线程内访问，与 worker 的 flow_table 生命周期一致。
 */
typedef enum {
  CLASS_EMPTY = 0,
  CLASS_USED = 1,
  CLASS_DELETED = 2
} class_state_t;

typedef struct {
  class_state_t state;
  uint64_t hash;
  flow_key_t key;
  uint16_t app_proto;
} class_slot_t;

struct classified_table {
  class_slot_t *slots;
  size_t capacity;
  size_t size;
  size_t used;
};

/* 创建 classified table。 */
struct classified_table *classified_table_create(size_t initial_capacity) {
  struct classified_table *ct = (struct classified_table *)calloc(1, sizeof(struct classified_table));
  if (!ct) return NULL;

  ct->capacity = next_pow2(initial_capacity > 16 ? initial_capacity : 16);
  ct->slots = (class_slot_t *)calloc(ct->capacity, sizeof(class_slot_t));
  if (!ct->slots) {
    free(ct);
    return NULL;
  }

  ct->size = 0;
  ct->used = 0;
  return ct;
}

/* 销毁 classified table。 */
void classified_table_destroy(struct classified_table *ct) {
  if (!ct) return;
  free(ct->slots);
  free(ct);
}

/* 查询已分类流。 */
bool classified_table_lookup(const struct classified_table *ct,
                             const flow_key_t *key,
                             uint64_t key_hash,
                             uint16_t *out_app_proto) {
  if (!ct) return false;
  size_t mask = ct->capacity - 1;
  size_t idx = (size_t)key_hash & mask;

  while (true) {
    const class_slot_t *s = &ct->slots[idx];
    if (s->state == CLASS_EMPTY) return false;
    if (s->state == CLASS_USED && s->hash == key_hash && flow_key_equal(&s->key, key)) {
      if (out_app_proto) *out_app_proto = s->app_proto;
      return true;
    }
    idx = (idx + 1) & mask;
  }
}

/* classified 扩容重哈希。 */
static void classified_table_rehash(struct classified_table *ct, size_t new_cap) {
  if (!ct) return;
  new_cap = next_pow2(new_cap);
  class_slot_t *old = ct->slots;
  size_t old_cap = ct->capacity;

  ct->slots = (class_slot_t *)calloc(new_cap, sizeof(class_slot_t));
  if (!ct->slots) {
    ct->slots = old;
    return;
  }

  ct->capacity = new_cap;
  ct->size = 0;
  ct->used = 0;

  for (size_t i = 0; i < old_cap; i++) {
    if (old[i].state != CLASS_USED) continue;
    size_t mask = new_cap - 1;
    size_t idx = (size_t)old[i].hash & mask;
    while (ct->slots[idx].state == CLASS_USED) {
      idx = (idx + 1) & mask;
    }
    ct->slots[idx] = old[i];
    ct->slots[idx].state = CLASS_USED;
    ct->size++;
    ct->used++;
  }

  free(old);
}

/* 写入或更新已分类流记录。 */
void classified_table_insert(struct classified_table *ct,
                             const flow_key_t *key,
                             uint64_t key_hash,
                             uint16_t app_proto) {
  if (!ct) return;
  if ((ct->used + 1) * 10 >= ct->capacity * 7) {
    classified_table_rehash(ct, ct->capacity * 2);
  }

  size_t mask = ct->capacity - 1;
  size_t idx = (size_t)key_hash & mask;
  size_t first_deleted = (size_t)-1;

  while (true) {
    class_slot_t *s = &ct->slots[idx];
    if (s->state == CLASS_EMPTY) {
      size_t ins = (first_deleted != (size_t)-1) ? first_deleted : idx;
      class_slot_t *dst = &ct->slots[ins];
      dst->state = CLASS_USED;
      dst->hash = key_hash;
      dst->key = *key;
      dst->app_proto = app_proto;
      ct->size++;
      if (first_deleted == (size_t)-1) ct->used++;
      return;
    }
    if (s->state == CLASS_DELETED) {
      if (first_deleted == (size_t)-1) first_deleted = idx;
    } else if (s->hash == key_hash && flow_key_equal(&s->key, key)) {
      s->app_proto = app_proto;
      return;
    }
    idx = (idx + 1) & mask;
  }
}
#endif
