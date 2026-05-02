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

typedef struct __attribute__((aligned(64))) {
  dispatch_slot_t *slots;
  size_t capacity;
  size_t size;
  size_t used;
  pthread_mutex_t lock;

  uint32_t rr_cursor;
  dispatch_stats_t stats;
} dispatch_shard_t;

struct dispatch_context {
  dispatch_shard_t *shards;
  uint32_t num_shards;

  const cost_table_t *cost_table;
  const cost_profile_t *cost_profile;
  const oracle_cost_table_t *oracle_table;
  dispatch_policy_t policy;
  worker_context_t *workers;
  uint32_t num_workers;

  dispatch_stats_t stats_cache;
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

const char *dispatch_policy_name(dispatch_policy_t policy) {
  switch (policy) {
    case DISPATCH_POLICY_RSS:
      return "rss";
    case DISPATCH_POLICY_JSQ:
      return "jsq";
    case DISPATCH_POLICY_STATIC_POOL:
      return "static-pool";
    case DISPATCH_POLICY_ORACLE:
      return "oracle";
    case DISPATCH_POLICY_OURS:
    default:
      return "ours";
  }
}

bool dispatch_policy_parse(const char *name, dispatch_policy_t *out) {
  if (!name || !out) return false;
  if (strcmp(name, "rss") == 0 || strcmp(name, "hash") == 0) {
    *out = DISPATCH_POLICY_RSS;
    return true;
  }
  if (strcmp(name, "jsq") == 0) {
    *out = DISPATCH_POLICY_JSQ;
    return true;
  }
  if (strcmp(name, "static") == 0 || strcmp(name, "static-pool") == 0 ||
      strcmp(name, "static_pool") == 0) {
    *out = DISPATCH_POLICY_STATIC_POOL;
    return true;
  }
  if (strcmp(name, "ours") == 0 || strcmp(name, "cost-aware-jsw") == 0) {
    *out = DISPATCH_POLICY_OURS;
    return true;
  }
  if (strcmp(name, "oracle") == 0) {
    *out = DISPATCH_POLICY_ORACLE;
    return true;
  }
  return false;
}

static uint32_t choose_min_queue_worker(const dispatch_context_t *ctx,
                                        const dispatch_shard_t *shard) {
  uint32_t best_worker = 0;
  uint32_t best_depth = UINT32_MAX;

  for (uint32_t offset = 0; offset < ctx->num_workers; offset++) {
    uint32_t i = (shard->rr_cursor + offset) % ctx->num_workers;
    uint32_t depth =
        atomic_load_explicit(&ctx->workers[i].runtime->queue_depth, memory_order_relaxed);
    if (depth < best_depth) {
      best_depth = depth;
      best_worker = i;
    }
  }

  return best_worker;
}

static uint32_t choose_static_pool_worker(const dispatch_context_t *ctx,
                                          uint64_t key_hash,
                                          uint8_t bucket) {
  uint8_t want_type = (bucket == COST_BUCKET_EASY) ? CORE_TYPE_E : CORE_TYPE_P;
  uint32_t candidates[MAX_WORKERS];
  uint32_t count = 0;

  for (uint32_t i = 0; i < ctx->num_workers; i++) {
    if (ctx->workers[i].runtime->core_type == want_type) candidates[count++] = i;
  }
  if (count == 0) {
    for (uint32_t i = 0; i < ctx->num_workers; i++) candidates[count++] = i;
  }

  return candidates[key_hash % count];
}

static uint32_t choose_cost_value_worker(const dispatch_context_t *ctx,
                                         const dispatch_shard_t *shard,
                                         uint32_t cost_x1000,
                                         uint32_t *out_retire_cost_x1000) {
  uint32_t best_worker = UINT32_MAX;
  uint64_t best_score = UINT64_MAX;

  for (uint32_t offset = 0; offset < ctx->num_workers; offset++) {
    uint32_t i = (shard->rr_cursor + offset) % ctx->num_workers;
    const worker_runtime_state_t *state = ctx->workers[i].runtime;
    uint32_t depth = atomic_load_explicit(&state->queue_depth, memory_order_relaxed);
    if (depth > DISPATCH_QUEUE_GUARD) continue;

    uint64_t added = atomic_load_explicit(&state->added_cost_x1000, memory_order_relaxed);
    uint64_t retired = atomic_load_explicit(&state->retired_cost_x1000, memory_order_relaxed);
    uint64_t pending = (added >= retired) ? (added - retired) : 0;

    uint64_t score = pending + cost_x1000;
    if (state->core_type == CORE_TYPE_P) score += DISPATCH_P_BIAS_X1000;
    if (score < best_score) {
      best_score = score;
      best_worker = i;
    }
  }

  if (best_worker == UINT32_MAX) best_worker = choose_min_queue_worker(ctx, shard);
  *out_retire_cost_x1000 = cost_x1000;
  return best_worker;
}

static uint32_t choose_cost_jsw_worker(const dispatch_context_t *ctx,
                                       const dispatch_shard_t *shard,
                                       uint8_t bucket,
                                       uint32_t *out_retire_cost_x1000) {
  uint32_t best_worker = UINT32_MAX;
  uint64_t best_score = UINT64_MAX;

  for (uint32_t offset = 0; offset < ctx->num_workers; offset++) {
    uint32_t i = (shard->rr_cursor + offset) % ctx->num_workers;
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
    best_worker = choose_min_queue_worker(ctx, shard);
    const worker_runtime_state_t *state = ctx->workers[best_worker].runtime;
    *out_retire_cost_x1000 =
        cost_profile_value_x1000(ctx->cost_profile, state->core_type, bucket);
  }

  return best_worker;
}

static uint32_t choose_policy_worker(dispatch_context_t *ctx,
                                     dispatch_shard_t *shard,
                                     uint64_t key_hash,
                                     uint8_t bucket,
                                     uint32_t *out_retire_cost_x1000) {
  *out_retire_cost_x1000 = 0;

  switch (ctx->policy) {
    case DISPATCH_POLICY_RSS:
      return (uint32_t)(key_hash % ctx->num_workers);
    case DISPATCH_POLICY_JSQ: {
      uint32_t worker = choose_min_queue_worker(ctx, shard);
      const worker_runtime_state_t *state = ctx->workers[worker].runtime;
      *out_retire_cost_x1000 =
          cost_profile_value_x1000(ctx->cost_profile, state->core_type, bucket);
      return worker;
    }
    case DISPATCH_POLICY_STATIC_POOL: {
      uint32_t worker = choose_static_pool_worker(ctx, key_hash, bucket);
      const worker_runtime_state_t *state = ctx->workers[worker].runtime;
      *out_retire_cost_x1000 =
          cost_profile_value_x1000(ctx->cost_profile, state->core_type, bucket);
      return worker;
    }
    case DISPATCH_POLICY_ORACLE: {
      uint32_t oracle_cost_x1000 = 0;
      if (oracle_cost_table_lookup(ctx->oracle_table, key_hash, &oracle_cost_x1000)) {
        shard->stats.oracle_hits++;
        return choose_cost_value_worker(ctx, shard, oracle_cost_x1000,
                                        out_retire_cost_x1000);
      }
      shard->stats.oracle_misses++;
      return choose_cost_jsw_worker(ctx, shard, bucket, out_retire_cost_x1000);
    }
    case DISPATCH_POLICY_OURS:
    default:
      return choose_cost_jsw_worker(ctx, shard, bucket, out_retire_cost_x1000);
  }
}

static void dispatch_rehash(dispatch_shard_t *shard, size_t new_cap) {
  new_cap = next_pow2(new_cap);
  dispatch_slot_t *old_slots = shard->slots;
  size_t old_cap = shard->capacity;

  dispatch_slot_t *new_slots = (dispatch_slot_t *)calloc(new_cap, sizeof(dispatch_slot_t));
  if (!new_slots) return;

  shard->slots = new_slots;
  shard->capacity = new_cap;
  shard->size = 0;
  shard->used = 0;

  for (size_t i = 0; i < old_cap; i++) {
    if (old_slots[i].state != DISPATCH_USED) continue;

    size_t mask = shard->capacity - 1;
    size_t idx = (size_t)old_slots[i].hash & mask;
    while (shard->slots[idx].state == DISPATCH_USED) {
      idx = (idx + 1) & mask;
    }
    shard->slots[idx] = old_slots[i];
    shard->slots[idx].state = DISPATCH_USED;
    shard->size++;
    shard->used++;
  }

  free(old_slots);
}

static bool dispatch_shard_init(dispatch_shard_t *shard, size_t initial_capacity) {
  memset(shard, 0, sizeof(*shard));
  shard->capacity = next_pow2(initial_capacity);
  shard->slots = (dispatch_slot_t *)calloc(shard->capacity, sizeof(dispatch_slot_t));
  if (!shard->slots) return false;
  pthread_mutex_init(&shard->lock, NULL);
  return true;
}

static void dispatch_shard_destroy(dispatch_shard_t *shard) {
  if (!shard) return;
  pthread_mutex_destroy(&shard->lock);
  free(shard->slots);
  memset(shard, 0, sizeof(*shard));
}

dispatch_context_t *dispatch_context_create(const cost_table_t *table,
                                            const cost_profile_t *profile,
                                            const oracle_cost_table_t *oracle_table,
                                            dispatch_policy_t policy,
                                            worker_context_t *workers,
                                            uint32_t num_workers,
                                            uint32_t num_shards) {
  if (!table || !workers || num_workers == 0) return NULL;
  if (num_shards == 0) num_shards = 1;

  dispatch_context_t *ctx = (dispatch_context_t *)calloc(1, sizeof(*ctx));
  if (!ctx) return NULL;

  if (posix_memalign((void **)&ctx->shards, 64,
                     num_shards * sizeof(*ctx->shards)) != 0) {
    free(ctx);
    return NULL;
  }
  memset(ctx->shards, 0, num_shards * sizeof(*ctx->shards));
  ctx->num_shards = num_shards;

  size_t shard_init_cap = DISPATCH_TABLE_INIT_CAP / num_shards;
  if (shard_init_cap < 1024) shard_init_cap = 1024;
  for (uint32_t i = 0; i < num_shards; i++) {
    if (!dispatch_shard_init(&ctx->shards[i], shard_init_cap)) {
      for (uint32_t j = 0; j < i; j++) dispatch_shard_destroy(&ctx->shards[j]);
      free(ctx->shards);
      free(ctx);
      return NULL;
    }
  }

  ctx->cost_table = table;
  ctx->cost_profile = profile;
  ctx->oracle_table = oracle_table;
  ctx->policy = policy;
  ctx->workers = workers;
  ctx->num_workers = num_workers;
  return ctx;
}

void dispatch_context_destroy(dispatch_context_t *ctx) {
  if (!ctx) return;
  for (uint32_t i = 0; i < ctx->num_shards; i++) {
    dispatch_shard_destroy(&ctx->shards[i]);
  }
  free(ctx->shards);
  free(ctx);
}

dispatch_result_t dispatch_lookup_or_assign(dispatch_context_t *ctx,
                                            uint32_t shard_id,
                                            const flow_key_t *key,
                                            uint64_t key_hash,
                                            uint16_t dst_port,
                                            const uint8_t *payload_prefix,
                                            uint8_t payload_prefix_len) {
  dispatch_result_t result = {0};
  if (!ctx || !key) return result;
  if (ctx->num_shards == 0) return result;

  dispatch_shard_t *shard = &ctx->shards[shard_id % ctx->num_shards];

  /*
   * Preprocess routes packets by flow_hash % num_dispatchers, and main creates
   * the same number of dispatch shards. Each dispatcher therefore owns one
   * shard exclusively during the dispatch phase, so the shard table does not
   * need a hot-path mutex.
   */
  shard->stats.lookups++;

  if ((shard->used + 1) * 10 >= shard->capacity * 7) {
    dispatch_rehash(shard, shard->capacity * 2);
  }

  size_t mask = shard->capacity - 1;
  size_t idx = (size_t)key_hash & mask;
  size_t first_deleted = (size_t)-1;

  while (true) {
    dispatch_slot_t *slot = &shard->slots[idx];

    if (slot->state == DISPATCH_EMPTY) {
      size_t ins = (first_deleted != (size_t)-1) ? first_deleted : idx;
      dispatch_slot_t *dst = &shard->slots[ins];

      uint8_t bucket = cost_table_lookup_bucket(ctx->cost_table,
                                                dst_port,
                                                payload_prefix,
                                                payload_prefix_len);
      uint32_t retire_cost_x1000 = 0;
      uint32_t worker_id = 0;

      worker_id = choose_policy_worker(ctx, shard, key_hash, bucket,
                                       &retire_cost_x1000);

      dst->state = DISPATCH_USED;
      dst->hash = key_hash;
      dst->key = *key;
      dst->worker_id = worker_id;
      shard->size++;
      if (first_deleted == (size_t)-1) shard->used++;

      atomic_fetch_add_explicit(&ctx->workers[worker_id].runtime->added_cost_x1000,
                                retire_cost_x1000,
                                memory_order_relaxed);

      shard->stats.new_flow_assignments++;
      shard->stats.bucket_flow_counts[bucket]++;
      shard->stats.worker_flow_counts[worker_id]++;
      shard->rr_cursor = (worker_id + 1U) % ctx->num_workers;

      result.worker_id = worker_id;
      result.retire_cost_x1000 = retire_cost_x1000;
      result.is_new_flow = true;
      break;
    }

    if (slot->state == DISPATCH_DELETED) {
      if (first_deleted == (size_t)-1) first_deleted = idx;
    } else if (slot->hash == key_hash && memcmp(&slot->key, key, sizeof(*key)) == 0) {
      shard->stats.existing_flow_hits++;
      result.worker_id = slot->worker_id;
      result.retire_cost_x1000 = 0;
      result.is_new_flow = false;
      break;
    }

    idx = (idx + 1) & mask;
  }

  return result;
}

const dispatch_stats_t *dispatch_get_stats(const dispatch_context_t *ctx) {
  if (!ctx) return NULL;

  dispatch_context_t *mutable_ctx = (dispatch_context_t *)ctx;
  memset(&mutable_ctx->stats_cache, 0, sizeof(mutable_ctx->stats_cache));

  for (uint32_t i = 0; i < ctx->num_shards; i++) {
    const dispatch_stats_t *s = &ctx->shards[i].stats;
    mutable_ctx->stats_cache.lookups += s->lookups;
    mutable_ctx->stats_cache.new_flow_assignments += s->new_flow_assignments;
    mutable_ctx->stats_cache.existing_flow_hits += s->existing_flow_hits;
    mutable_ctx->stats_cache.fallback_packets += s->fallback_packets;
    mutable_ctx->stats_cache.oracle_hits += s->oracle_hits;
    mutable_ctx->stats_cache.oracle_misses += s->oracle_misses;
    for (uint32_t b = 0; b < COST_BUCKET_COUNT; b++) {
      mutable_ctx->stats_cache.bucket_flow_counts[b] += s->bucket_flow_counts[b];
    }
    for (uint32_t w = 0; w < MAX_WORKERS; w++) {
      mutable_ctx->stats_cache.worker_flow_counts[w] += s->worker_flow_counts[w];
    }
  }

  return &mutable_ctx->stats_cache;
}
