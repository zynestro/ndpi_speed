#ifndef BENCHMARK_INTERNAL_H
#define BENCHMARK_INTERNAL_H

/*
 * benchmark_internal.h（mark7）
 *
 * 角色：
 * - 给 mark7 各 .c 文件提供内部共享接口
 * - 串联 cost table / dispatch / reader / worker 这些实现层模块
 */

#include "ndpi_benchmark.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define RSS_TABLE_INIT_CAP (1u << 18)
#define DISPATCH_TABLE_INIT_CAP (1u << 20)
#define DISPATCH_QUEUE_GUARD (QUEUE_CAPACITY - 1)
#define DISPATCH_P_BIAS_X1000 10U

struct rss_table;
typedef struct rss_table rss_table_t;
struct dispatch_context;
typedef struct dispatch_context dispatch_context_t;
struct oracle_cost_table;
typedef struct oracle_cost_table oracle_cost_table_t;

typedef struct {
  /* 输入与线程拓扑配置 */
  const char *pcap_file;
  const char *lookup_file;
  worker_context_t *workers;
  uint32_t num_workers;
  uint32_t num_dispatchers;
  uint32_t *dispatcher_cores;

  /* 运行期 flow->worker 调度状态 */
  dispatch_context_t *dispatch;

  /* 预处理阶段产物（reader 先载入，再由 dispatcher 并发消费） */
  void *packets;
  size_t packet_count;
  size_t *dispatcher_offsets; /* [num_dispatchers + 1] */
  size_t *dispatcher_indices; /* [packet_count], 索引到 packets */

  /* dispatcher 汇总统计时的并发保护 */
  pthread_mutex_t stats_lock;

  /* dispatch 阶段计时（ns） */
  uint64_t read_time_ns;
  uint64_t pcap_read_ns;
  uint64_t normalize_ns;
  uint64_t hash_ns;
  uint64_t rss_lookup_ns;
  uint64_t enqueue_ns;
  uint64_t read_other_ns;

  /* preprocess 阶段计时（ns） */
  uint64_t preprocess_ns;
  uint64_t preprocess_dispatch_rss_ns;
  uint64_t preprocess_store_ns;
  uint64_t preprocess_schedule_ns;
  uint64_t preprocess_other_ns;

  /* reader 阶段是否发生致命错误（如 pcap 打开失败） */
  bool failed;
} reader_context_t;

extern pthread_mutex_t g_print_mutex;
extern uint64_t g_samples_printed;
extern const uint64_t g_sample_limit;
extern bool g_quiet_mode;

void maybe_print_flow_sample(worker_context_t *w, const bench_flow_t *f);
void set_thread_affinity(uint32_t core);

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
bool flow_table_delete(struct flow_table *ft,
                       const flow_key_t *key,
                       uint64_t key_hash,
                       void (*on_free)(bench_flow_t *flow, void *user),
                       void *user);
bench_flow_t *flow_table_get_or_create(struct flow_table *ft,
                                       const flow_key_t *key,
                                       uint64_t key_hash,
                                       bool *is_new);

#ifdef NDPI_BENCHMARK_CLASSIFIED
struct classified_table *classified_table_create(size_t initial_capacity);
void classified_table_destroy(struct classified_table *ct);
bool classified_table_lookup(const struct classified_table *ct,
                             const flow_key_t *key,
                             uint64_t key_hash,
                             uint16_t *out_app_proto);
void classified_table_insert(struct classified_table *ct,
                             const flow_key_t *key,
                             uint64_t key_hash,
                             uint16_t app_proto);
#endif

rss_table_t *rss_table_create(size_t initial_capacity);
void rss_table_destroy(rss_table_t *rt);
uint32_t rss_mix32(uint32_t x);
uint32_t rss_table_lookup_or_assign(rss_table_t *rt,
                                    const reader_context_t *ctx,
                                    uint64_t key,
                                    uint64_t ts_ms);
uint32_t rss_table_lookup_or_assign_target(rss_table_t *rt,
                                           uint32_t num_targets,
                                           uint64_t key,
                                           uint64_t ts_ms);

uint8_t core_type_from_core_id(uint32_t core_id);
uint16_t core_speed_factor_x1000(uint32_t core_id);

const char *cost_bucket_name(uint8_t bucket);
uint32_t cost_bucket_value_x1000(uint8_t bucket);
bool cost_table_load(cost_table_t *table, const char *path);
void cost_table_destroy(cost_table_t *table);
uint8_t cost_table_lookup_bucket(const cost_table_t *table,
                                 uint16_t dst_port,
                                 const uint8_t *payload_prefix,
                                 uint8_t payload_prefix_len);
void cost_profile_init_defaults(cost_profile_t *profile);
bool cost_profile_load_csv(cost_profile_t *profile, const char *path);
uint32_t cost_profile_value_x1000(const cost_profile_t *profile,
                                  uint8_t core_type,
                                  uint8_t bucket);

oracle_cost_table_t *oracle_cost_table_load(const char *path);
void oracle_cost_table_destroy(oracle_cost_table_t *table);
bool oracle_cost_table_lookup(const oracle_cost_table_t *table,
                              uint64_t flow_hash,
                              uint32_t *out_cost_x1000);
const char *dispatch_policy_name(dispatch_policy_t policy);
bool dispatch_policy_parse(const char *name, dispatch_policy_t *out);

dispatch_context_t *dispatch_context_create(const cost_table_t *table,
                                            const cost_profile_t *profile,
                                            const oracle_cost_table_t *oracle_table,
                                            dispatch_policy_t policy,
                                            worker_context_t *workers,
                                            uint32_t num_workers,
                                            uint32_t num_shards);
void dispatch_context_destroy(dispatch_context_t *ctx);
dispatch_result_t dispatch_lookup_or_assign(dispatch_context_t *ctx,
                                            uint32_t shard_id,
                                            const flow_key_t *key,
                                            uint64_t key_hash,
                                            uint16_t dst_port,
                                            const uint8_t *payload_prefix,
                                            uint8_t payload_prefix_len);
const dispatch_stats_t *dispatch_get_stats(const dispatch_context_t *ctx);

void *worker_thread_entry(void *arg);
void *reader_thread_entry(void *arg);
void reader_context_cleanup(reader_context_t *ctx);

#endif
