#include "benchmark_internal.h"

typedef enum {
  DISPATCH_EMPTY = 0,
  DISPATCH_USED = 1,
  DISPATCH_DELETED = 2
} dispatch_slot_state_t;

typedef struct {
  dispatch_slot_state_t state;
  uint64_t hash;
  flow_key_t key;
  uint32_t worker_id;
} dispatch_slot_t;

struct dispatch_context {
  dispatch_slot_t *slots;
  size_t capacity;
  size_t size;
  size_t used;
  pthread_mutex_t lock;

  const cost_table_t *cost_table;
  const cost_profile_t *cost_profile;
  worker_context_t *workers;
  uint32_t num_workers;
  uint32_t rr_cursor;

  dispatch_stats_t stats;
};

static size_t next_pow2(size_t x) {
  if (x < 2) return 2;
  x--;
  for (size_t i = 1; i < sizeof(size_t) * 8; i <<= 1) x |= x >> i;
  return x + 1;
}

uint8_t core_type_from_core_id(uint32_t core_id) {
  return (core_id < 16U) ? CORE_TYPE_P : CORE_TYPE_E;
}

uint16_t core_speed_factor_x1000(uint32_t core_id) {
  return (core_type_from_core_id(core_id) == CORE_TYPE_P)
             ? SPEED_FACTOR_P_X1000
             : SPEED_FACTOR_E_X1000;
}

static uint32_t choose_min_queue_worker(const dispatch_context_t *ctx) {
  uint32_t best_worker = 0;
  uint32_t best_depth = UINT32_MAX;

  for (uint32_t offset = 0; offset < ctx->num_workers; offset++) {
    uint32_t i = (ctx->rr_cursor + offset) % ctx->num_workers;
    uint32_t depth =
        atomic_load_explicit(&ctx->workers[i].runtime->queue_depth, memory_order_relaxed);
    if (depth < best_depth) {
      best_depth = depth;
      best_worker = i;
    }
  }

  return best_worker;
}

static uint32_t choose_cost_jsw_worker(const dispatch_context_t *ctx,
                                       uint8_t bucket,
                                       uint32_t *out_retire_cost_x1000) {
  uint32_t best_worker = UINT32_MAX;
  uint64_t best_score = UINT64_MAX;

  for (uint32_t offset = 0; offset < ctx->num_workers; offset++) {
    uint32_t i = (ctx->rr_cursor + offset) % ctx->num_workers;
    const worker_runtime_state_t *state = ctx->workers[i].runtime;
    uint32_t depth = atomic_load_explicit(&state->queue_depth, memory_order_relaxed);
    if (depth > DISPATCH_QUEUE_GUARD) continue;

    uint64_t added = atomic_load_explicit(&state->added_cost_x1000, memory_order_relaxed);
    uint64_t retired = atomic_load_explicit(&state->retired_cost_x1000, memory_order_relaxed);
    uint64_t pending = (added >= retired) ? (added - retired) : 0;

    uint32_t core_cost_x1000 =
        cost_profile_value_x1000(ctx->cost_profile, state->core_type, bucket);

    uint64_t score = pending + core_cost_x1000;
    if (state->core_type == CORE_TYPE_P) score += DISPATCH_P_BIAS_X1000;

    if (score < best_score) {
      best_score = score;
      best_worker = i;
      *out_retire_cost_x1000 = core_cost_x1000;
    }
  }

  if (best_worker == UINT32_MAX) {
    best_worker = choose_min_queue_worker(ctx);
    const worker_runtime_state_t *state = ctx->workers[best_worker].runtime;
    *out_retire_cost_x1000 =
        cost_profile_value_x1000(ctx->cost_profile, state->core_type, bucket);
  }

  return best_worker;
}

static void dispatch_rehash(dispatch_context_t *ctx, size_t new_cap) {
  new_cap = next_pow2(new_cap);
  dispatch_slot_t *old_slots = ctx->slots;
  size_t old_cap = ctx->capacity;

  dispatch_slot_t *new_slots = (dispatch_slot_t *)calloc(new_cap, sizeof(dispatch_slot_t));
  if (!new_slots) return;

  ctx->slots = new_slots;
  ctx->capacity = new_cap;
  ctx->size = 0;
  ctx->used = 0;

  for (size_t i = 0; i < old_cap; i++) {
    if (old_slots[i].state != DISPATCH_USED) continue;

    size_t mask = ctx->capacity - 1;
    size_t idx = (size_t)old_slots[i].hash & mask;
    while (ctx->slots[idx].state == DISPATCH_USED) {
      idx = (idx + 1) & mask;
    }
    ctx->slots[idx] = old_slots[i];
    ctx->slots[idx].state = DISPATCH_USED;
    ctx->size++;
    ctx->used++;
  }

  free(old_slots);
}

dispatch_context_t *dispatch_context_create(const cost_table_t *table,
                                            const cost_profile_t *profile,
                                            worker_context_t *workers,
                                            uint32_t num_workers) {
  if (!table || !workers || num_workers == 0) return NULL;

  dispatch_context_t *ctx = (dispatch_context_t *)calloc(1, sizeof(*ctx));
  if (!ctx) return NULL;

  ctx->capacity = next_pow2(DISPATCH_TABLE_INIT_CAP);
  ctx->slots = (dispatch_slot_t *)calloc(ctx->capacity, sizeof(dispatch_slot_t));
  if (!ctx->slots) {
    free(ctx);
    return NULL;
  }

  ctx->cost_table = table;
  ctx->cost_profile = profile;
  ctx->workers = workers;
  ctx->num_workers = num_workers;
  ctx->rr_cursor = 0;
  pthread_mutex_init(&ctx->lock, NULL);
  return ctx;
}

void dispatch_context_destroy(dispatch_context_t *ctx) {
  if (!ctx) return;
  pthread_mutex_destroy(&ctx->lock);
  free(ctx->slots);
  free(ctx);
}

dispatch_result_t dispatch_lookup_or_assign(dispatch_context_t *ctx,
                                            const flow_key_t *key,
                                            uint16_t dst_port,
                                            const uint8_t *payload_prefix,
                                            uint8_t payload_prefix_len) {
  dispatch_result_t result = {0};
  if (!ctx || !key) return result;

  uint64_t key_hash = flow_key_hash(key);

  pthread_mutex_lock(&ctx->lock);
  ctx->stats.lookups++;

  if ((ctx->used + 1) * 10 >= ctx->capacity * 7) {
    dispatch_rehash(ctx, ctx->capacity * 2);
  }

  size_t mask = ctx->capacity - 1;
  size_t idx = (size_t)key_hash & mask;
  size_t first_deleted = (size_t)-1;

  while (true) {
    dispatch_slot_t *slot = &ctx->slots[idx];

    if (slot->state == DISPATCH_EMPTY) {
      size_t ins = (first_deleted != (size_t)-1) ? first_deleted : idx;
      dispatch_slot_t *dst = &ctx->slots[ins];

      uint8_t bucket = cost_table_lookup_bucket(ctx->cost_table,
                                                dst_port,
                                                payload_prefix,
                                                payload_prefix_len);
      uint32_t retire_cost_x1000 = 0;
      uint32_t worker_id = 0;

#ifdef MARK6_DISPATCH_HASH_ONLY
      worker_id = (uint32_t)(key_hash % ctx->num_workers);
#else
      worker_id = choose_cost_jsw_worker(ctx, bucket, &retire_cost_x1000);
#endif

      dst->state = DISPATCH_USED;
      dst->hash = key_hash;
      dst->key = *key;
      dst->worker_id = worker_id;
      ctx->size++;
      if (first_deleted == (size_t)-1) ctx->used++;

      atomic_fetch_add_explicit(&ctx->workers[worker_id].runtime->added_cost_x1000,
                                retire_cost_x1000,
                                memory_order_relaxed);

      ctx->stats.new_flow_assignments++;
      ctx->stats.bucket_flow_counts[bucket]++;
      ctx->stats.worker_flow_counts[worker_id]++;
#ifndef MARK6_DISPATCH_HASH_ONLY
      ctx->rr_cursor = (worker_id + 1U) % ctx->num_workers;
#endif

      result.worker_id = worker_id;
      result.retire_cost_x1000 = retire_cost_x1000;
      result.is_new_flow = true;
      break;
    }

    if (slot->state == DISPATCH_DELETED) {
      if (first_deleted == (size_t)-1) first_deleted = idx;
    } else if (slot->hash == key_hash && memcmp(&slot->key, key, sizeof(*key)) == 0) {
      ctx->stats.existing_flow_hits++;
      result.worker_id = slot->worker_id;
      result.retire_cost_x1000 = 0;
      result.is_new_flow = false;
      break;
    }

    idx = (idx + 1) & mask;
  }

  pthread_mutex_unlock(&ctx->lock);
  return result;
}

const dispatch_stats_t *dispatch_get_stats(const dispatch_context_t *ctx) {
  return ctx ? &ctx->stats : NULL;
}
