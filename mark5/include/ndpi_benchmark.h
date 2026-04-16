#ifndef NDPI_BENCHMARK_H
#define NDPI_BENCHMARK_H

/*
 * ndpi_benchmark.h（mark4）
 *
 * 角色：
 * - 定义单线程 benchmark 共用的数据结构
 * - 提供 parser / flow_table 的对外接口声明
 * - 作为 main.c 与实现模块之间的公共契约
 */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <time.h>

#include "ndpi_api.h"

#define MAX_PACKET_SIZE 65535

/* Parsed view of a packet (Ethernet -> IPv4/IPv6 -> TCP/UDP). */
typedef struct {
  uint8_t ip_version;
  uint8_t l4_proto;
  uint16_t src_port;
  uint16_t dst_port;
  uint8_t src_ip[16];
  uint8_t dst_ip[16];
  const uint8_t *l3;
  uint16_t l3_len;
  const uint8_t *payload;
  uint16_t payload_len;
} parsed_packet_t;

typedef enum {
  PARSE_OK = 0,
  PARSE_UNSUPPORTED = 1,
  PARSE_TRUNCATED = 2
} parse_result_t;

typedef struct {
  uint8_t ip_version;
  uint8_t l4_proto;
  uint16_t port_a;
  uint16_t port_b;
  uint8_t addr_a[16];
  uint8_t addr_b[16];
} flow_key_t;

typedef struct {
  uint8_t ip_version;
  uint16_t port;
  uint8_t addr[16];
} endpoint_t;

typedef struct {
  uint64_t *items;
  size_t count;
  size_t cap;
} sample_vec_t;

#define MARK5_FIRST_PACKET_SAMPLES 20

typedef struct {
  /* 该 flow 的规范化 key（双向统一） */
  flow_key_t key;

  /* 首包定义出的方向端点（用于后续包方向判断） */
  endpoint_t client;
  endpoint_t server;

  /* nDPI 每流状态 */
  struct ndpi_flow_struct *ndpi_flow;

  /* 双向计数与活跃时间 */
  uint64_t last_seen_ms;
  uint64_t c2s_packets;
  uint64_t s2c_packets;
  uint64_t c2s_bytes;
  uint64_t s2c_bytes;
  uint64_t seen_packets;

  /* 首包签名：用于 mark5 做首包负载画像 */
  bool signature_initialized;
  uint8_t signature_ip_version;
  uint8_t signature_l4_proto;
  uint16_t signature_server_port;
  uint8_t signature_payload_prefix_len;
  uint32_t signature_payload_prefix_u32;

  /* 逐流阶段时间与逐包阶段样本 */
  uint64_t detecting_time_ns_total;
  uint64_t post_time_ns_total;
  uint64_t detecting_detection_time_ns_total;
  uint64_t post_detection_time_ns_total;
  uint64_t detecting_flow_table_time_ns_total;
  uint64_t post_flow_table_time_ns_total;
  uint64_t detecting_bytes_total;
  uint64_t detecting_packets;
  uint64_t post_packets;
  sample_vec_t detecting_packet_samples_ns;
  sample_vec_t post_packet_samples_ns;

#if defined(MARK5_PROFILE_TIME)
  uint8_t first_packet_time_sample_count;
  uint64_t first_packet_total_ns[MARK5_FIRST_PACKET_SAMPLES];
  uint64_t first_packet_detection_ns[MARK5_FIRST_PACKET_SAMPLES];
  uint64_t first_packet_flow_table_ns[MARK5_FIRST_PACKET_SAMPLES];
  uint64_t first_packet_other_ns[MARK5_FIRST_PACKET_SAMPLES];
#endif

#if defined(MARK5_PROFILE_HW)
  uint64_t detecting_instructions_total;
  uint64_t post_instructions_total;
  uint64_t detecting_cycles_total;
  uint64_t post_cycles_total;
  uint64_t detecting_llc_misses_total;
  uint64_t post_llc_misses_total;
  uint64_t detecting_llc_refs_total;
  uint64_t post_llc_refs_total;
  uint64_t detecting_branch_misses_total;
  uint64_t post_branch_misses_total;
  uint8_t first_packet_hw_sample_count;
  uint64_t first_packet_instructions[MARK5_FIRST_PACKET_SAMPLES];
  uint64_t first_packet_cycles[MARK5_FIRST_PACKET_SAMPLES];
  uint64_t first_packet_llc_misses[MARK5_FIRST_PACKET_SAMPLES];
  uint64_t first_packet_llc_refs[MARK5_FIRST_PACKET_SAMPLES];
  uint64_t first_packet_branch_misses[MARK5_FIRST_PACKET_SAMPLES];
#endif

  /* 协议识别结果与识别位置统计 */
  bool protocol_counted;
  uint64_t first_seen_ns;
  uint64_t detection_packet_in_flow;
  uint64_t detection_packet_global;
  uint16_t detected_master_proto;
  uint16_t detected_app_proto;
  ndpi_protocol_category_t detected_category;
} bench_flow_t;

struct flow_table;

bool normalize_to_ethernet(int linktype,
                           const uint8_t *data, uint16_t caplen, uint16_t wirelen,
                           const uint8_t **out_data, uint16_t *out_caplen,
                           uint16_t *out_wirelen, uint8_t *scratch,
                           size_t scratch_len);

parse_result_t parse_ethernet_frame(const uint8_t *data, uint16_t caplen, parsed_packet_t *out);
void flow_key_from_packet(const parsed_packet_t *p, flow_key_t *out_key, endpoint_t *out_src, endpoint_t *out_dst);
bool endpoint_equal(const endpoint_t *a, const endpoint_t *b);

uint64_t flow_key_hash(const flow_key_t *k);
struct flow_table *flow_table_create(size_t initial_capacity);
void flow_table_destroy(struct flow_table *ft,
                        void (*on_free)(bench_flow_t *flow, void *user),
                        void *user);
bench_flow_t *flow_table_get_or_create(struct flow_table *ft,
                                       const flow_key_t *key,
                                       uint64_t key_hash,
                                       bool *is_new);

typedef void (*flow_table_iter_cb)(bench_flow_t *flow, void *user);
void flow_table_foreach(struct flow_table *ft, flow_table_iter_cb cb, void *user);
size_t flow_table_size(const struct flow_table *ft);

static inline uint64_t get_time_ns(void) {
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
  return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#endif
