#include "ndpi_benchmark.h"
#include "flow_table.h"
#include "packet_parser.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void endpoint_to_string(const endpoint_t *ep, char *buf, size_t buflen) {
  if (!ep || !buf || buflen == 0) return;

  char ip[INET6_ADDRSTRLEN] = {0};
  if (ep->ip_version == 4) {
    inet_ntop(AF_INET, ep->addr, ip, sizeof(ip));
  } else {
    inet_ntop(AF_INET6, ep->addr, ip, sizeof(ip));
  }

  snprintf(buf, buflen, "%s:%u", ip, (unsigned)ep->port);
}

static bool flow_key_equal_simple(const flow_key_t *a, const flow_key_t *b) {
  if (!a || !b) return false;
  if (a->ip_version != b->ip_version) return false;
  if (a->l4_proto != b->l4_proto) return false;
  if (a->port_a != b->port_a || a->port_b != b->port_b) return false;
  if (memcmp(a->addr_a, b->addr_a, 16) != 0) return false;
  if (memcmp(a->addr_b, b->addr_b, 16) != 0) return false;
  return true;
}

static int endpoint_cmp_local(const endpoint_t *a, const endpoint_t *b) {
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

static void build_flow_key_from_endpoints(uint8_t ip_version,
                                          uint8_t l4_proto,
                                          const endpoint_t *src,
                                          const endpoint_t *dst,
                                          flow_key_t *out_key) {
  endpoint_t a = *src;
  endpoint_t b = *dst;
  if (endpoint_cmp_local(&a, &b) > 0) {
    endpoint_t tmp = a;
    a = b;
    b = tmp;
  }

  memset(out_key, 0, sizeof(*out_key));
  out_key->ip_version = ip_version;
  out_key->l4_proto = l4_proto;
  out_key->port_a = a.port;
  out_key->port_b = b.port;
  memcpy(out_key->addr_a, a.addr, 16);
  memcpy(out_key->addr_b, b.addr, 16);
}

static void set_ndpi_flow_tuple(struct ndpi_flow_struct *flow,
                                const parsed_packet_t *p,
                                const endpoint_t *client,
                                const endpoint_t *server) {
  flow->l4_proto = p->l4_proto;
  flow->is_ipv6 = (p->ip_version == 6);
  flow->c_port = htons(client->port);
  flow->s_port = htons(server->port);

  if (p->ip_version == 4) {
    memcpy(&flow->c_address, client->addr, 4);
    memcpy(&flow->s_address, server->addr, 4);
  } else {
    memcpy(&flow->c_address, client->addr, 16);
    memcpy(&flow->s_address, server->addr, 16);
  }
}

static void dump_flow_state(struct ndpi_detection_module_struct *ndpi,
                            const bench_flow_t *flow,
                            uint32_t matched_index,
                            bool dump_raw,
                            uint32_t dump_bytes) {
  const struct ndpi_flow_struct *f = flow->ndpi_flow;
  if (!f) return;

  uint16_t master = ndpi_get_flow_masterprotocol(flow->ndpi_flow);
  uint16_t app = ndpi_get_flow_appprotocol(flow->ndpi_flow);
  ndpi_master_app_protocol proto = {0};
  proto.master_protocol = master;
  proto.app_protocol = app;

  char proto_name[64];
  memset(proto_name, 0, sizeof(proto_name));
  ndpi_protocol2name(ndpi, proto, proto_name, (u_int)sizeof(proto_name));

  char c[128], s[128];
  endpoint_to_string(&flow->client, c, sizeof(c));
  endpoint_to_string(&flow->server, s, sizeof(s));

  printf("Packet #%u (matched flow)\n", matched_index);
  printf("  5-tuple: %s  <->  %s\n", c, s);
  printf("  detected: %s (master=%u app=%u) confidence=%u\n",
         proto_name[0] ? proto_name : "(unknown)",
         (unsigned)master, (unsigned)app, (unsigned)f->confidence);
  printf("  error_code=%u\n", (unsigned)ndpi_get_flow_error_code(flow->ndpi_flow));
  printf("  flow flags: init_finished=%u protocol_was_guessed=%u already_gaveup=%u\n",
         (unsigned)f->init_finished, (unsigned)f->protocol_was_guessed,
         (unsigned)f->already_gaveup);
  printf("  tuple (ndpi_flow): l4=%u ipv6=%u c_port=%u s_port=%u\n",
         (unsigned)f->l4_proto, (unsigned)f->is_ipv6,
         (unsigned)ntohs(f->c_port), (unsigned)ntohs(f->s_port));
  printf("  counters: seen_packets=%lu ndpi_num_pkts=%u packet_counter=%u all_packets_counter=%u\n",
         (unsigned long)flow->seen_packets,
         (unsigned)f->num_processed_pkts,
         (unsigned)f->packet_counter,
         (unsigned)f->all_packets_counter);
  printf("  dir counters: pkt_dir=[%u,%u] pkt_dir_complete=[%u,%u]\n",
         (unsigned)f->packet_direction_counter[0],
         (unsigned)f->packet_direction_counter[1],
         (unsigned)f->packet_direction_complete_counter[0],
         (unsigned)f->packet_direction_complete_counter[1]);
  printf("  last_packet_time_ms=%llu entropy=%.3f\n",
         (unsigned long long)f->last_packet_time_ms,
         (double)f->entropy);
  printf("  guessed: by_port=%u by_ip=%u fast_cb=%u\n",
         (unsigned)f->guessed_protocol_id,
         (unsigned)f->guessed_protocol_id_by_ip,
         (unsigned)f->fast_callback_protocol_id);
  printf("  category=%u breed=%u risk=0x%llx risk_mask=0x%llx num_risks=%u\n",
         (unsigned)f->category,
         (unsigned)f->breed,
         (unsigned long long)f->risk,
         (unsigned long long)f->risk_mask,
         (unsigned)f->num_risk_infos);
  if (f->host_server_name[0] != '\0') {
    printf("  host_server_name=%s\n", f->host_server_name);
  }

  struct ndpi_proto proto_id = {0};
  ndpi_get_flow_ndpi_proto(flow->ndpi_flow, &proto_id);
  const char *info = ndpi_get_flow_info(flow->ndpi_flow, &proto_id);
  if (info && info[0] != '\0') {
    printf("  flow_info=%s\n", info);
  }

  if (dump_raw) {
    const uint8_t *raw = (const uint8_t *)f;
    uint32_t total = (uint32_t)sizeof(struct ndpi_flow_struct);
    uint32_t n = dump_bytes;
    if (n == 0 || n > total) n = total;

    printf("  raw_struct (%u/%u bytes):\n", (unsigned)n, (unsigned)total);
    for (uint32_t i = 0; i < n; i += 16) {
      printf("    %04x: ", (unsigned)i);
      for (uint32_t j = 0; j < 16 && i + j < n; j++) {
        printf("%02x ", raw[i + j]);
      }
      printf("\n");
    }
  }
  printf("\n");
}

static void free_flow_cb(bench_flow_t *flow, void *user) {
  (void)user;
  if (!flow) return;
  if (flow->ndpi_flow) {
    ndpi_free_flow(flow->ndpi_flow);
    flow->ndpi_flow = NULL;
  }
  free(flow);
}

static void usage(const char *prog) {
  fprintf(stderr,
          "Usage: %s -i <pcap> [--max-pkts N] [--flow <tuple>] [--dump-raw] [--dump-bytes N]\n"
          "  -i <pcap>       Input pcap file\n"
          "  --max-pkts N    Max packets to show for the matched flow (default: 12)\n"
          "  --flow <tuple>  Match a specific flow: srcIP:srcPort-dstIP:dstPort\n"
          "  --dump-raw      Hex dump the ndpi_flow_struct memory\n"
          "  --dump-bytes N  Bytes to dump from struct (default: 256; 0=full)\n",
          prog);
}

static bool parse_endpoint(const char *s, endpoint_t *ep) {
  char *colon = strrchr(s, ':');
  if (!colon) return false;

  char ip_part[128];
  size_t ip_len = (size_t)(colon - s);
  if (ip_len == 0 || ip_len >= sizeof(ip_part)) return false;
  memcpy(ip_part, s, ip_len);
  ip_part[ip_len] = '\0';

  char *end = NULL;
  unsigned long port = strtoul(colon + 1, &end, 10);
  if (!end || *end != '\0' || port > 65535) return false;

  memset(ep, 0, sizeof(*ep));
  if (strchr(ip_part, ':')) {
    ep->ip_version = 6;
    if (inet_pton(AF_INET6, ip_part, ep->addr) != 1) return false;
  } else {
    ep->ip_version = 4;
    if (inet_pton(AF_INET, ip_part, ep->addr) != 1) return false;
  }
  ep->port = (uint16_t)port;
  return true;
}

int main(int argc, char **argv) {
  const char *pcap_file = NULL;
  uint32_t max_pkts = 12;
  const char *flow_tuple = NULL;
  flow_key_t user_key;
  bool user_key_set = false;
  bool dump_raw = false;
  uint32_t dump_bytes = 256;

  for (int i = 1; i < argc; i++) {
    if ((strcmp(argv[i], "-i") == 0 || strcmp(argv[i], "--input") == 0) && i + 1 < argc) {
      pcap_file = argv[++i];
    } else if (strcmp(argv[i], "--max-pkts") == 0 && i + 1 < argc) {
      max_pkts = (uint32_t)strtoul(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "--flow") == 0 && i + 1 < argc) {
      flow_tuple = argv[++i];
    } else if (strcmp(argv[i], "--dump-raw") == 0) {
      dump_raw = true;
    } else if (strcmp(argv[i], "--dump-bytes") == 0 && i + 1 < argc) {
      dump_bytes = (uint32_t)strtoul(argv[++i], NULL, 10);
    } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
      usage(argv[0]);
      return 0;
    } else {
      fprintf(stderr, "Unknown option: %s\n", argv[i]);
      usage(argv[0]);
      return 1;
    }
  }

  if (!pcap_file) {
    usage(argv[0]);
    return 1;
  }

  if (flow_tuple) {
    const char *dash = strchr(flow_tuple, '-');
    if (!dash) {
      fprintf(stderr, "Invalid --flow format. Use srcIP:srcPort-dstIP:dstPort\n");
      return 1;
    }

    char left[160];
    char right[160];
    size_t left_len = (size_t)(dash - flow_tuple);
    size_t right_len = strlen(dash + 1);
    if (left_len == 0 || right_len == 0 || left_len >= sizeof(left) || right_len >= sizeof(right)) {
      fprintf(stderr, "Invalid --flow tuple length\n");
      return 1;
    }

    memcpy(left, flow_tuple, left_len);
    left[left_len] = '\0';
    memcpy(right, dash + 1, right_len + 1);

    endpoint_t src = {0};
    endpoint_t dst = {0};
    if (!parse_endpoint(left, &src) || !parse_endpoint(right, &dst)) {
      fprintf(stderr, "Invalid --flow endpoint(s)\n");
      return 1;
    }
    if (src.ip_version != dst.ip_version) {
      fprintf(stderr, "Invalid --flow: IP versions must match\n");
      return 1;
    }

    build_flow_key_from_endpoints(src.ip_version, IPPROTO_TCP, &src, &dst, &user_key);
    user_key_set = true;
  }

  packet_pool_t *pool = load_pcap_to_memory(pcap_file);
  if (!pool) return 1;

  printf("Flow State Demo\n");
  printf("  pcap: %s\n", pcap_file);
  printf("  packets in pcap: %u\n", pool->num_packets);
  printf("  sizeof(ndpi_flow_struct): %zu bytes\n\n", sizeof(struct ndpi_flow_struct));

  struct ndpi_global_context *g_ctx = ndpi_global_init();
  if (!g_ctx) {
    fprintf(stderr, "Error: ndpi_global_init() failed\n");
    free_packet_pool(pool);
    return 1;
  }

  struct ndpi_detection_module_struct *ndpi = ndpi_init_detection_module(g_ctx);
  if (!ndpi) {
    fprintf(stderr, "Error: ndpi_init_detection_module() failed\n");
    ndpi_global_deinit(g_ctx);
    free_packet_pool(pool);
    return 1;
  }

  (void)ndpi_set_config(ndpi, NULL, "tcp_ack_payload_heuristic", "enable");
  ndpi_finalize_initialization(ndpi);

  flow_table_t *flows = flow_table_create(1024);
  if (!flows) {
    fprintf(stderr, "Error: flow_table_create() failed\n");
    ndpi_exit_detection_module(ndpi);
    ndpi_global_deinit(g_ctx);
    free_packet_pool(pool);
    return 1;
  }

  flow_key_t target_key;
  bool target_set = false;
  uint32_t matched = 0;

  for (uint32_t i = 0; i < pool->num_packets; i++) {
    mem_packet_t *pkt = pool->packets[i];
    parsed_packet_t pp;
    if (parse_ethernet_frame(pkt->data, pkt->caplen, &pp) != PARSE_OK) continue;

    flow_key_t key;
    endpoint_t src_ep, dst_ep;
    flow_key_from_packet(&pp, &key, &src_ep, &dst_ep);

    if (!target_set) {
      target_key = key;
      target_set = true;
    }

    if (user_key_set) {
      if (!flow_key_equal_simple(&key, &user_key)) continue;
    } else {
      if (!flow_key_equal_simple(&key, &target_key)) continue;
    }

    uint64_t h = flow_key_hash(&key);
    bool is_new = false;
    bench_flow_t *flow = flow_table_get_or_create(flows, &key, h, NULL, NULL, &is_new);
    if (!flow) continue;

    if (is_new) {
      flow->client = src_ep;
      flow->server = dst_ep;

      flow->ndpi_flow = (struct ndpi_flow_struct *)ndpi_calloc(1, sizeof(struct ndpi_flow_struct));
      if (!flow->ndpi_flow) {
        fprintf(stderr, "Error: ndpi_calloc(flow) failed\n");
        break;
      }

      set_ndpi_flow_tuple(flow->ndpi_flow, &pp, &flow->client, &flow->server);
    }

    uint8_t dir = endpoint_equal(&src_ep, &flow->client) ? 0 : 1;

    if (dir == 0) {
      flow->c2s_packets++;
      flow->c2s_bytes += pkt->wirelen;
    } else {
      flow->s2c_packets++;
      flow->s2c_bytes += pkt->wirelen;
    }

    uint64_t ts_ms = pkt->timestamp_us / 1000ULL;
    flow->last_seen_ms = ts_ms;

    struct ndpi_flow_input_info in = {0};
    in.in_pkt_dir = dir;
    in.seen_flow_beginning = (flow->seen_packets == 0);

    (void)ndpi_detection_process_packet(ndpi, flow->ndpi_flow,
                                        pp.l3, pp.l3_len,
                                        ts_ms, &in);

    flow->seen_packets++;

    matched++;
    dump_flow_state(ndpi, flow, matched, dump_raw, dump_bytes);

    if (matched >= max_pkts) break;
  }

  if (!target_set) {
    fprintf(stderr, "No parsable packet found in pcap.\n");
  } else if (matched == 0) {
    fprintf(stderr, "No packets matched the first flow key.\n");
  }

  flow_table_destroy(flows, free_flow_cb, NULL);
  ndpi_exit_detection_module(ndpi);
  ndpi_global_deinit(g_ctx);
  free_packet_pool(pool);
  return 0;
}
