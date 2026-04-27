#include "benchmark_internal.h"

#include <ctype.h>
#include <math.h>
#include <strings.h>

static const char *skip_ws(const char *p) {
  while (p && *p && isspace((unsigned char)*p)) p++;
  return p;
}

static bool parse_json_string(const char **pp, char *out, size_t out_len) {
  const char *p = skip_ws(*pp);
  if (!p || *p != '"') return false;
  p++;

  size_t n = 0;
  while (*p && *p != '"') {
    if (*p == '\\' && p[1]) p++;
    if (n + 1 < out_len) out[n++] = *p;
    p++;
  }

  if (*p != '"') return false;
  out[n] = '\0';
  *pp = p + 1;
  return true;
}

static bool expect_json_char(const char **pp, char ch) {
  const char *p = skip_ws(*pp);
  if (!p || *p != ch) return false;
  *pp = p + 1;
  return true;
}

static char *trim_in_place(char *s) {
  if (!s) return s;

  while (*s && isspace((unsigned char)*s)) s++;
  if (!*s) return s;

  char *end = s + strlen(s) - 1;
  while (end >= s && isspace((unsigned char)*end)) {
    *end = '\0';
    end--;
  }
  return s;
}

static const char *find_key_value_start(const char *text, const char *key) {
  char needle[128];
  snprintf(needle, sizeof(needle), "\"%s\"", key);
  const char *p = strstr(text, needle);
  if (!p) return NULL;
  p = strchr(p + strlen(needle), ':');
  if (!p) return NULL;
  return p + 1;
}

static uint8_t parse_bucket_name_internal(const char *name) {
  if (strcmp(name, "Easy") == 0) return COST_BUCKET_EASY;
  if (strcmp(name, "Hard") == 0) return COST_BUCKET_HARD;
  return COST_BUCKET_MIDDLE;
}

const char *cost_bucket_name(uint8_t bucket) {
  switch (bucket) {
    case COST_BUCKET_EASY:
      return "Easy";
    case COST_BUCKET_HARD:
      return "Hard";
    default:
      return "Middle";
  }
}

uint32_t cost_bucket_value_x1000(uint8_t bucket) {
  switch (bucket) {
    case COST_BUCKET_EASY:
      return COST_EASY_X1000;
    case COST_BUCKET_HARD:
      return COST_HARD_X1000;
    default:
      return COST_MIDDLE_X1000;
  }
}

static bool parse_core_type_name(const char *name, uint8_t *out) {
  if (!name || !out) return false;

  if (strcasecmp(name, "P") == 0 ||
      strcasecmp(name, "P-core") == 0 ||
      strcasecmp(name, "pcore") == 0 ||
      strcmp(name, "0") == 0) {
    *out = CORE_TYPE_P;
    return true;
  }

  if (strcasecmp(name, "E") == 0 ||
      strcasecmp(name, "E-core") == 0 ||
      strcasecmp(name, "ecore") == 0 ||
      strcmp(name, "1") == 0) {
    *out = CORE_TYPE_E;
    return true;
  }

  return false;
}

void cost_profile_init_defaults(cost_profile_t *profile) {
  if (!profile) return;

  memset(profile, 0, sizeof(*profile));
  for (uint8_t core_type = 0; core_type < COST_CORE_TYPES; core_type++) {
    profile->cost_x1000[core_type][COST_BUCKET_EASY] = COST_EASY_X1000;
    profile->cost_x1000[core_type][COST_BUCKET_MIDDLE] = COST_MIDDLE_X1000;
    profile->cost_x1000[core_type][COST_BUCKET_HARD] = COST_HARD_X1000;
  }
}

static void cost_profile_fill_missing(cost_profile_t *profile) {
  if (!profile) return;

  for (uint8_t bucket = 0; bucket < COST_BUCKET_COUNT; bucket++) {
    bool has_p = profile->present[CORE_TYPE_P][bucket];
    bool has_e = profile->present[CORE_TYPE_E][bucket];
    if (has_p && !has_e) {
      profile->cost_x1000[CORE_TYPE_E][bucket] =
          profile->cost_x1000[CORE_TYPE_P][bucket];
      profile->present[CORE_TYPE_E][bucket] = true;
    } else if (has_e && !has_p) {
      profile->cost_x1000[CORE_TYPE_P][bucket] =
          profile->cost_x1000[CORE_TYPE_E][bucket];
      profile->present[CORE_TYPE_P][bucket] = true;
    }
  }
}

bool cost_profile_load_csv(cost_profile_t *profile, const char *path) {
  if (!profile || !path) return false;

  cost_profile_init_defaults(profile);

  FILE *fp = fopen(path, "r");
  if (!fp) {
    fprintf(stderr, "Error: failed to open cost profile %s: %s\n", path, strerror(errno));
    return false;
  }

  char line[512];
  unsigned long line_no = 0;
  while (fgets(line, sizeof(line), fp)) {
    line_no++;

    char *p = trim_in_place(line);
    if (!p[0] || p[0] == '#') continue;
    if (strstr(p, "core_type") && strstr(p, "bucket")) continue;

    char *saveptr = NULL;
    char *core_s = trim_in_place(strtok_r(p, ",", &saveptr));
    char *bucket_s = trim_in_place(strtok_r(NULL, ",", &saveptr));
    char *cost_s = trim_in_place(strtok_r(NULL, ",", &saveptr));

    if (!core_s || !bucket_s || !cost_s) {
      fprintf(stderr, "Error: invalid cost profile row %s:%lu\n", path, line_no);
      fclose(fp);
      return false;
    }

    uint8_t core_type = 0;
    if (!parse_core_type_name(core_s, &core_type)) {
      fprintf(stderr, "Error: invalid core_type '%s' in %s:%lu\n", core_s, path, line_no);
      fclose(fp);
      return false;
    }

    uint8_t bucket = parse_bucket_name_internal(bucket_s);
    char *end = NULL;
    double cost_us = strtod(cost_s, &end);
    if (!end || trim_in_place(end)[0] != '\0' || cost_us < 0.0) {
      fprintf(stderr, "Error: invalid cost_us '%s' in %s:%lu\n", cost_s, path, line_no);
      fclose(fp);
      return false;
    }

    profile->cost_x1000[core_type][bucket] = (uint32_t)llround(cost_us * 1000.0);
    profile->present[core_type][bucket] = true;
  }

  fclose(fp);
  cost_profile_fill_missing(profile);
  return true;
}

uint32_t cost_profile_value_x1000(const cost_profile_t *profile,
                                  uint8_t core_type,
                                  uint8_t bucket) {
  if (!profile) return cost_bucket_value_x1000(bucket);
  if (core_type >= COST_CORE_TYPES) core_type = CORE_TYPE_P;
  if (bucket >= COST_BUCKET_COUNT) bucket = COST_BUCKET_MIDDLE;

  uint32_t value = profile->cost_x1000[core_type][bucket];
  return value ? value : cost_bucket_value_x1000(bucket);
}

static bool append_special_rule(cost_table_t *table,
                                uint16_t port,
                                const uint8_t *prefix,
                                uint8_t prefix_len,
                                uint8_t bucket) {
  if (table->num_special_rules == table->cap_special_rules) {
    size_t new_cap = table->cap_special_rules ? table->cap_special_rules * 2 : 16;
    cost_special_rule_t *next =
        (cost_special_rule_t *)realloc(table->special_rules,
                                       new_cap * sizeof(cost_special_rule_t));
    if (!next) return false;
    table->special_rules = next;
    table->cap_special_rules = new_cap;
  }

  cost_special_rule_t *rule = &table->special_rules[table->num_special_rules++];
  memset(rule, 0, sizeof(*rule));
  rule->port = port;
  rule->prefix_len = prefix_len;
  rule->bucket = bucket;
  if (prefix_len > 0) memcpy(rule->prefix, prefix, prefix_len);
  return true;
}

static bool parse_prefix_key(const char *text, uint8_t *out_prefix, uint8_t *out_len) {
  if (!text || !text[0]) {
    *out_len = 0;
    return true;
  }

  const char *p = text;
  if (p[0] == '0' && (p[1] == 'x' || p[1] == 'X')) p += 2;

  bool all_hex = true;
  size_t hex_len = 0;
  for (const char *q = p; *q; q++) {
    if (!isxdigit((unsigned char)*q)) {
      all_hex = false;
      break;
    }
    hex_len++;
  }

  if (all_hex && (hex_len == 2 || hex_len == 4 || hex_len == 8)) {
    unsigned long v = strtoul(p, NULL, 16);
    size_t bytes = hex_len / 2;
    for (size_t i = 0; i < bytes; i++) {
      size_t shift = (bytes - 1 - i) * 8;
      out_prefix[i] = (uint8_t)((v >> shift) & 0xFFU);
    }
    *out_len = (uint8_t)bytes;
    return true;
  }

  char *end = NULL;
  unsigned long v = strtoul(text, &end, 10);
  if (!end || *end != '\0') return false;

  if (v <= 0xFFU) {
    out_prefix[0] = (uint8_t)v;
    *out_len = 1;
    return true;
  }
  if (v <= 0xFFFFU) {
    out_prefix[0] = (uint8_t)((v >> 8) & 0xFFU);
    out_prefix[1] = (uint8_t)(v & 0xFFU);
    *out_len = 2;
    return true;
  }
  if (v <= 0xFFFFFFFFUL) {
    out_prefix[0] = (uint8_t)((v >> 24) & 0xFFU);
    out_prefix[1] = (uint8_t)((v >> 16) & 0xFFU);
    out_prefix[2] = (uint8_t)((v >> 8) & 0xFFU);
    out_prefix[3] = (uint8_t)(v & 0xFFU);
    *out_len = 4;
    return true;
  }

  return false;
}

static bool parse_port_table_object(cost_table_t *table, const char *start) {
  const char *p = skip_ws(start);
  if (!expect_json_char(&p, '{')) return false;

  while (true) {
    char key[64];
    char value[64];

    p = skip_ws(p);
    if (*p == '}') return true;

    if (!parse_json_string(&p, key, sizeof(key))) return false;
    if (!expect_json_char(&p, ':')) return false;
    if (!parse_json_string(&p, value, sizeof(value))) return false;

    char *end = NULL;
    unsigned long port = strtoul(key, &end, 10);
    if (!end || *end != '\0' || port > 65535U) return false;

    table->port_present[port] = 1;
    table->port_bucket[port] = parse_bucket_name_internal(value);

    p = skip_ws(p);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == '}') return true;
    return false;
  }
}

static bool parse_special_rule_map(cost_table_t *table, uint16_t port, const char **pp) {
  const char *p = skip_ws(*pp);
  if (!expect_json_char(&p, '{')) return false;

  while (true) {
    char prefix_key[64];
    char bucket_name[64];
    uint8_t prefix[4] = {0};
    uint8_t prefix_len = 0;

    p = skip_ws(p);
    if (*p == '}') {
      *pp = p + 1;
      return true;
    }

    if (!parse_json_string(&p, prefix_key, sizeof(prefix_key))) return false;
    if (!expect_json_char(&p, ':')) return false;
    if (!parse_json_string(&p, bucket_name, sizeof(bucket_name))) return false;
    if (!parse_prefix_key(prefix_key, prefix, &prefix_len)) return false;
    if (!append_special_rule(table, port, prefix, prefix_len,
                             parse_bucket_name_internal(bucket_name))) {
      return false;
    }

    p = skip_ws(p);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == '}') {
      *pp = p + 1;
      return true;
    }
    return false;
  }
}

static bool parse_special_rules_object(cost_table_t *table, const char *start) {
  const char *p = skip_ws(start);
  if (!expect_json_char(&p, '{')) return false;

  while (true) {
    char port_key[64];

    p = skip_ws(p);
    if (*p == '}') return true;

    if (!parse_json_string(&p, port_key, sizeof(port_key))) return false;
    if (!expect_json_char(&p, ':')) return false;

    char *end = NULL;
    unsigned long port = strtoul(port_key, &end, 10);
    if (!end || *end != '\0' || port > 65535U) return false;

    if (!expect_json_char(&p, '{')) return false;
    while (true) {
      char rule_key[64];
      char bucket_name[64];
      uint8_t prefix[4] = {0};
      uint8_t prefix_len = 0;

      p = skip_ws(p);
      if (*p == '}') {
        p++;
        break;
      }

      if (!parse_json_string(&p, rule_key, sizeof(rule_key))) return false;
      if (!expect_json_char(&p, ':')) return false;
      p = skip_ws(p);

      if (*p == '"') {
        /*
         * Backward-compatible flat format:
         *   "443": {"0D": "Easy"}
         */
        if (!parse_json_string(&p, bucket_name, sizeof(bucket_name))) return false;
        if (!parse_prefix_key(rule_key, prefix, &prefix_len)) return false;
        if (!append_special_rule(table, (uint16_t)port, prefix, prefix_len,
                                 parse_bucket_name_internal(bucket_name))) {
          return false;
        }
      } else if (*p == '{') {
        /*
         * New mark5/train_port_prefix_lookup.py format:
         *   "443": {"prefix_1": {"0D": "Easy"}, "prefix_2": {}, "prefix_4": {}}
         *
         * The nested key name is informational; the actual prefix length comes
         * from the hex key length, so prefix_4 naturally works as 4 bytes.
         */
        if (!parse_special_rule_map(table, (uint16_t)port, &p)) return false;
      } else {
        return false;
      }

      p = skip_ws(p);
      if (*p == ',') {
        p++;
        continue;
      }
      if (*p == '}') {
        p++;
        break;
      }
      return false;
    }

    p = skip_ws(p);
    if (*p == ',') {
      p++;
      continue;
    }
    if (*p == '}') return true;
    return false;
  }
}

void cost_table_destroy(cost_table_t *table) {
  if (!table) return;
  free(table->special_rules);
  memset(table, 0, sizeof(*table));
}

bool cost_table_load(cost_table_t *table, const char *path) {
  if (!table || !path) return false;

  memset(table, 0, sizeof(*table));
  table->default_bucket = COST_BUCKET_HARD;

  FILE *fp = fopen(path, "rb");
  if (!fp) {
    fprintf(stderr, "Error: failed to open lookup table %s: %s\n", path, strerror(errno));
    return false;
  }

  if (fseek(fp, 0, SEEK_END) != 0) {
    fclose(fp);
    return false;
  }

  long size = ftell(fp);
  if (size < 0) {
    fclose(fp);
    return false;
  }
  rewind(fp);

  char *buf = (char *)calloc((size_t)size + 1, 1);
  if (!buf) {
    fclose(fp);
    return false;
  }

  size_t nr = fread(buf, 1, (size_t)size, fp);
  fclose(fp);
  buf[nr] = '\0';

  const char *default_pos = find_key_value_start(buf, "default_bucket");
  if (default_pos) {
    char bucket_name[64];
    if (parse_json_string(&default_pos, bucket_name, sizeof(bucket_name))) {
      table->default_bucket = parse_bucket_name_internal(bucket_name);
    }
  }

  const char *port_table_pos = find_key_value_start(buf, "port_table");
  if (port_table_pos && !parse_port_table_object(table, port_table_pos)) {
    fprintf(stderr, "Error: failed to parse port_table in %s\n", path);
    free(buf);
    cost_table_destroy(table);
    return false;
  }

  const char *special_rules_pos = find_key_value_start(buf, "special_rules");
  if (special_rules_pos && !parse_special_rules_object(table, special_rules_pos)) {
    fprintf(stderr, "Error: failed to parse special_rules in %s\n", path);
    free(buf);
    cost_table_destroy(table);
    return false;
  }

  free(buf);
  return true;
}

uint8_t cost_table_lookup_bucket(const cost_table_t *table,
                                 uint16_t dst_port,
                                 const uint8_t *payload_prefix,
                                 uint8_t payload_prefix_len) {
  if (!table) return COST_BUCKET_HARD;

  if (table->port_present[dst_port]) {
    return table->port_bucket[dst_port];
  }

  for (uint8_t target_len = 1; target_len <= 4; target_len++) {
    for (size_t i = 0; i < table->num_special_rules; i++) {
      const cost_special_rule_t *rule = &table->special_rules[i];
      if (rule->port != dst_port) continue;
      if (rule->prefix_len != target_len) continue;
      if (payload_prefix_len < rule->prefix_len) continue;
      if (memcmp(rule->prefix, payload_prefix, rule->prefix_len) == 0) {
        return rule->bucket;
      }
    }
  }

  return COST_BUCKET_HARD;
}
