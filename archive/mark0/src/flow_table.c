#include "flow_table.h"

#include <stdlib.h>
#include <string.h>

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
  size_t capacity; /* always power of two */
  size_t size;     /* live entries */
  size_t used;     /* used + deleted, for resizing */
};

/* ---------- Utility ---------- */

static inline uint64_t fnv1a64(const void *data, size_t len) {
  const uint8_t *p = (const uint8_t *)data;
  uint64_t h = 1469598103934665603ULL;
  for (size_t i = 0; i < len; i++) {
    h ^= (uint64_t)p[i];
    h *= 1099511628211ULL;
  }
  return h;
}

uint64_t flow_key_hash(const flow_key_t *k) {
  return fnv1a64(k, sizeof(*k));
}

static inline bool flow_key_equal(const flow_key_t *a, const flow_key_t *b) {
  return memcmp(a, b, sizeof(*a)) == 0;
}

static size_t next_pow2(size_t x) {
  if (x < 2) return 2;
  x--;
  for (size_t i = 1; i < sizeof(size_t) * 8; i <<= 1) x |= x >> i;
  return x + 1;
}

static void flow_table_rehash(flow_table_t *ft, size_t new_cap) {
  new_cap = next_pow2(new_cap);
  slot_t *old = ft->slots;
  size_t old_cap = ft->capacity;

  ft->slots = (slot_t *)calloc(new_cap, sizeof(slot_t));
  ft->capacity = new_cap;
  ft->size = 0;
  ft->used = 0;

  for (size_t i = 0; i < old_cap; i++) {
    if (old[i].state != SLOT_USED) continue;

    /* re-insert */
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

flow_table_t *flow_table_create(size_t initial_capacity) {
  flow_table_t *ft = (flow_table_t *)calloc(1, sizeof(flow_table_t));
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

void flow_table_destroy(flow_table_t *ft, void (*on_free)(bench_flow_t *flow, void *user), void *user) {
  if (!ft) return;
  flow_table_clear(ft, on_free, user);
  free(ft->slots);
  free(ft);
}

void flow_table_clear(flow_table_t *ft, void (*on_free)(bench_flow_t *flow, void *user), void *user) {
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

size_t flow_table_size(const flow_table_t *ft) {
  return ft ? ft->size : 0;
}

bench_flow_t *flow_table_get_or_create(flow_table_t *ft,
                                      const flow_key_t *key,
                                      uint64_t key_hash,
                                      void (*on_new)(bench_flow_t *flow, void *user),
                                      void *user,
                                      bool *is_new) {
  if (!ft) return NULL;

  /* Resize if table is getting full (used includes tombstones). */
  if ((ft->used + 1) * 10 >= ft->capacity * 7) {
    flow_table_rehash(ft, ft->capacity * 2);
  }

  size_t mask = ft->capacity - 1;
  size_t idx = (size_t)key_hash & mask;
  size_t first_deleted = (size_t)-1;

  while (true) {
    slot_t *s = &ft->slots[idx];

    if (s->state == SLOT_EMPTY) {
      /* insert here (or at first tombstone) */
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
      if (first_deleted != (size_t)-1) {
        /* used already counted */
      } else {
        ft->used++;
      }

      if (on_new) on_new(f, user);
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

/* ---------- Key building ---------- */

static int endpoint_cmp(const endpoint_t *a, const endpoint_t *b) {
  /* Compare address bytes first, then port. */
  int r;
  if (a->ip_version == 4) {
    r = memcmp(a->addr, b->addr, 4);
  } else {
    r = memcmp(a->addr, b->addr, 16);
  }
  if (r != 0) return r;
  if (a->port < b->port) return -1;
  if (a->port > b->port) return 1;
  return 0;
}

void flow_key_from_packet(const parsed_packet_t *p, flow_key_t *out_key, endpoint_t *out_src, endpoint_t *out_dst) {
  memset(out_key, 0, sizeof(*out_key));
  memset(out_src, 0, sizeof(*out_src));
  memset(out_dst, 0, sizeof(*out_dst));

  out_src->ip_version = p->ip_version;
  out_dst->ip_version = p->ip_version;
  out_src->port = p->src_port;
  out_dst->port = p->dst_port;
  memcpy(out_src->addr, p->src_ip, 16);
  memcpy(out_dst->addr, p->dst_ip, 16);

  endpoint_t a = *out_src;
  endpoint_t b = *out_dst;

  if (endpoint_cmp(&a, &b) > 0) {
    endpoint_t tmp = a;
    a = b;
    b = tmp;
  }

  out_key->ip_version = p->ip_version;
  out_key->l4_proto = p->l4_proto;
  out_key->port_a = a.port;
  out_key->port_b = b.port;
  memcpy(out_key->addr_a, a.addr, 16);
  memcpy(out_key->addr_b, b.addr, 16);
}

bool endpoint_equal(const endpoint_t *a, const endpoint_t *b) {
  if (a->ip_version != b->ip_version) return false;
  if (a->port != b->port) return false;
  if (a->ip_version == 4) return memcmp(a->addr, b->addr, 4) == 0;
  return memcmp(a->addr, b->addr, 16) == 0;
}

