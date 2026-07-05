#include "benchmark_internal.h"

#include <ctype.h>
#include <math.h>

typedef struct {
  bool used;
  uint64_t flow_hash;
  uint32_t cost_x1000;
} oracle_cost_slot_t;

struct oracle_cost_table {
  oracle_cost_slot_t *slots;
  size_t capacity;
  size_t size;
};

static size_t oracle_next_pow2(size_t x) {
  if (x < 2) return 2;
  x--;
  for (size_t i = 1; i < sizeof(size_t) * 8; i <<= 1) x |= x >> i;
  return x + 1;
}

static char *oracle_trim(char *s) {
  if (!s) return s;
  while (*s && isspace((unsigned char)*s)) s++;
  if (!*s) return s;
  char *end = s + strlen(s) - 1;
  while (end >= s && isspace((unsigned char)*end)) *end-- = '\0';
  return s;
}

static bool oracle_insert(oracle_cost_table_t *table, uint64_t flow_hash,
                          uint32_t cost_x1000) {
  if (!table || table->capacity == 0) return false;
  size_t mask = table->capacity - 1;
  size_t idx = (size_t)flow_hash & mask;
  while (table->slots[idx].used) {
    if (table->slots[idx].flow_hash == flow_hash) {
      table->slots[idx].cost_x1000 = cost_x1000;
      return true;
    }
    idx = (idx + 1) & mask;
  }
  table->slots[idx].used = true;
  table->slots[idx].flow_hash = flow_hash;
  table->slots[idx].cost_x1000 = cost_x1000;
  table->size++;
  return true;
}

static bool parse_oracle_row(char *line, uint64_t *out_hash,
                             uint32_t *out_cost_x1000) {
  char *saveptr = NULL;
  char *hash_s = oracle_trim(strtok_r(line, ",", &saveptr));
  char *cost_s = oracle_trim(strtok_r(NULL, ",", &saveptr));
  if (!hash_s || !cost_s || !hash_s[0] || !cost_s[0]) return false;
  if (strcmp(hash_s, "flow_hash") == 0 || strcmp(hash_s, "hash") == 0) return false;

  char *end = NULL;
  uint64_t hash = strtoull(hash_s, &end, 0);
  if (!end || oracle_trim(end)[0] != '\0') return false;

  end = NULL;
  double cost_us = strtod(cost_s, &end);
  if (!end || oracle_trim(end)[0] != '\0' || cost_us < 0.0) return false;

  *out_hash = hash;
  *out_cost_x1000 = (uint32_t)llround(cost_us * 1000.0);
  return true;
}

oracle_cost_table_t *oracle_cost_table_load(const char *path) {
  if (!path || !path[0]) return NULL;

  FILE *fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr, "Error: failed to open oracle table %s: %s\n", path, strerror(errno));
    return NULL;
  }

  size_t rows = 0;
  char line[512];
  while (fgets(line, sizeof(line), fp)) {
    char tmp[512];
    memcpy(tmp, line, sizeof(tmp));
    uint64_t hash = 0;
    uint32_t cost = 0;
    if (parse_oracle_row(tmp, &hash, &cost)) rows++;
  }

  oracle_cost_table_t *table = (oracle_cost_table_t *)calloc(1, sizeof(*table));
  if (!table) {
    fclose(fp);
    return NULL;
  }

  table->capacity = oracle_next_pow2(rows * 2 + 1);
  table->slots = (oracle_cost_slot_t *)calloc(table->capacity, sizeof(*table->slots));
  if (!table->slots) {
    fclose(fp);
    free(table);
    return NULL;
  }

  rewind(fp);
  while (fgets(line, sizeof(line), fp)) {
    uint64_t hash = 0;
    uint32_t cost = 0;
    if (parse_oracle_row(line, &hash, &cost)) {
      (void)oracle_insert(table, hash, cost);
    }
  }
  fclose(fp);
  return table;
}

void oracle_cost_table_destroy(oracle_cost_table_t *table) {
  if (!table) return;
  free(table->slots);
  free(table);
}

bool oracle_cost_table_lookup(const oracle_cost_table_t *table,
                              uint64_t flow_hash,
                              uint32_t *out_cost_x1000) {
  if (!table || !table->slots || table->capacity == 0) return false;
  size_t mask = table->capacity - 1;
  size_t idx = (size_t)flow_hash & mask;
  while (table->slots[idx].used) {
    if (table->slots[idx].flow_hash == flow_hash) {
      if (out_cost_x1000) *out_cost_x1000 = table->slots[idx].cost_x1000;
      return true;
    }
    idx = (idx + 1) & mask;
  }
  return false;
}
