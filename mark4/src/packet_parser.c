#include "benchmark_internal.h"

/* 以太网与 VLAN 相关常量。 */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88A8
#define ETH_HDR_LEN 14

/* 统一链路层为 Ethernet 视图：
 * - 已是 DLT_EN10MB: 原样返回
 * - DLT_NULL/LOOP/RAW: 在 scratch 中补一个伪 Ethernet 头
 * - 其它链路层: 返回 false（当前不支持）
 *
 * 设计目的：
 * - worker 解析逻辑只处理一种链路层（Ethernet），减少分支与重复代码
 * - reader 阶段做一次标准化，后续路径统一
 */
bool normalize_to_ethernet(int linktype,
                           const uint8_t *data, uint16_t caplen, uint16_t wirelen,
                           const uint8_t **out_data, uint16_t *out_caplen,
                           uint16_t *out_wirelen, uint8_t *scratch,
                           size_t scratch_len) {
  if (linktype == DLT_EN10MB) {
    *out_data = data;
    *out_caplen = caplen;
    *out_wirelen = wirelen;
    return true;
  }

  /* BSD loopback: 前 4 字节是 address family。 */
  if (linktype == DLT_NULL || linktype == DLT_LOOP) {
    if (caplen < 4) return false;
    uint32_t family = 0;
    memcpy(&family, data, sizeof(family));
    uint16_t ether_type = 0;
    if (family == AF_INET) {
      ether_type = ETHERTYPE_IPV4;
    } else if (family == AF_INET6) {
      ether_type = ETHERTYPE_IPV6;
    } else {
      return false;
    }

    uint16_t new_caplen = (uint16_t)(caplen - 4 + ETH_HDR_LEN);
    if (new_caplen > scratch_len) return false;

    memset(scratch, 0, 12);
    scratch[12] = (uint8_t)(ether_type >> 8);
    scratch[13] = (uint8_t)(ether_type & 0xFF);
    memcpy(scratch + ETH_HDR_LEN, data + 4, caplen - 4);

    *out_data = scratch;
    *out_caplen = new_caplen;
    *out_wirelen = wirelen;
    return true;
  }

  /* RAW: 直接是 IP 包，根据版本号猜 EtherType。 */
  if (linktype == DLT_RAW) {
    if (caplen < 1) return false;
    uint8_t ver = (data[0] >> 4) & 0x0F;
    uint16_t ether_type = 0;
    if (ver == 4) {
      ether_type = ETHERTYPE_IPV4;
    } else if (ver == 6) {
      ether_type = ETHERTYPE_IPV6;
    } else {
      return false;
    }

    uint16_t new_caplen = (uint16_t)(caplen + ETH_HDR_LEN);
    if (new_caplen > scratch_len) return false;

    memset(scratch, 0, 12);
    scratch[12] = (uint8_t)(ether_type >> 8);
    scratch[13] = (uint8_t)(ether_type & 0xFF);
    memcpy(scratch + ETH_HDR_LEN, data, caplen);

    *out_data = scratch;
    *out_caplen = new_caplen;
    *out_wirelen = wirelen;
    return true;
  }

  return false;
}

/* 判断是否是 IPv6 扩展头。 */
static inline bool is_ipv6_ext_header(uint8_t nh) {
  switch (nh) {
    case 0:
    case 43:
    case 44:
    case 50:
    case 51:
    case 60:
      return true;
    default:
      return false;
  }
}

/* 从 IPv6 首部后沿扩展头链寻找真正 L4 首部位置。
 * 该函数只负责“定位”，不解析 TCP/UDP 细节。
 */
static parse_result_t parse_ipv6_find_l4(const uint8_t *pkt, uint16_t caplen,
                                          uint16_t ip6_off,
                                          uint8_t *out_l4_proto,
                                          uint16_t *out_l4_off) {
  if (caplen < ip6_off + sizeof(struct ip6_hdr)) return PARSE_TRUNCATED;

  const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(pkt + ip6_off);
  uint8_t nh = ip6->ip6_nxt;
  uint16_t off = ip6_off + (uint16_t)sizeof(struct ip6_hdr);

  while (is_ipv6_ext_header(nh)) {
    /* Fragment header 固定 8 字节。 */
    if (nh == 44) {
      if (caplen < off + 8) return PARSE_TRUNCATED;
      nh = *(pkt + off);
      off += 8;
      continue;
    }

    /* AH 长度字段单位是 4-byte words（含前 2 words）。 */
    if (nh == 51) {
      if (caplen < off + 2) return PARSE_TRUNCATED;
      uint8_t next = *(pkt + off);
      uint8_t hdrlen = *(pkt + off + 1);
      uint16_t bytes = (uint16_t)(hdrlen + 2U) * 4U;
      if (caplen < off + bytes) return PARSE_TRUNCATED;
      nh = next;
      off += bytes;
      continue;
    }

    /* ESP 负载无法在此处解析到传输层端口，标记为 unsupported。 */
    if (nh == 50) {
      *out_l4_proto = nh;
      *out_l4_off = off;
      return PARSE_UNSUPPORTED;
    }

    /* Hop-by-Hop / Routing / Dest Options 等按 8-byte 单位前进。 */
    if (caplen < off + 2) return PARSE_TRUNCATED;
    uint8_t next = *(pkt + off);
    uint8_t hdrlen = *(pkt + off + 1);
    uint16_t bytes = (uint16_t)(hdrlen + 1U) * 8U;
    if (caplen < off + bytes) return PARSE_TRUNCATED;
    nh = next;
    off += bytes;
  }

  *out_l4_proto = nh;
  *out_l4_off = off;
  return PARSE_OK;
}

/* 解析标准化后的 Ethernet 帧，提取:
 * - IP 版本/协议
 * - 源目地址
 * - TCP/UDP 端口（若可得）
 * - 指向 L3 的指针和长度（给 nDPI 用）
 *
 * 返回语义：
 * - PARSE_OK: 可以进入识别
 * - PARSE_TRUNCATED: 抓包长度不够，无法可靠解析
 * - PARSE_UNSUPPORTED: 报文类型当前不处理（但不是内存越界错误）
 */
parse_result_t parse_ethernet_frame(const uint8_t *data, uint16_t caplen, parsed_packet_t *out) {
  memset(out, 0, sizeof(*out));

  if (caplen < ETH_HDR_LEN) return PARSE_TRUNCATED;

  uint16_t ether_type = (uint16_t)((data[12] << 8) | data[13]);
  uint16_t off = ETH_HDR_LEN;

  /* 最多剥两层 VLAN tag。 */
  for (int i = 0; i < 2 && (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ); i++) {
    if (caplen < off + 4) return PARSE_TRUNCATED;
    ether_type = (uint16_t)((data[off + 2] << 8) | data[off + 3]);
    off += 4;
  }

  /* IPv4 分支。 */
  if (ether_type == ETHERTYPE_IPV4) {
    if (caplen < off + sizeof(struct ip)) return PARSE_TRUNCATED;

    const struct ip *ip4 = (const struct ip *)(data + off);
    uint8_t ihl = (uint8_t)(ip4->ip_hl * 4);
    if (ihl < 20) return PARSE_UNSUPPORTED;
    if (caplen < off + ihl) return PARSE_TRUNCATED;

    out->ip_version = 4;
    out->l4_proto = ip4->ip_p;

    memset(out->src_ip, 0, sizeof(out->src_ip));
    memset(out->dst_ip, 0, sizeof(out->dst_ip));
    memcpy(out->src_ip, &ip4->ip_src, 4);
    memcpy(out->dst_ip, &ip4->ip_dst, 4);

    out->l3 = data + off;
    out->l3_len = (uint16_t)(caplen - off);

    uint16_t l4_off = (uint16_t)(off + ihl);

    /* 仅 TCP/UDP 提取端口，其他 L4 端口置 0。 */
    if (out->l4_proto == IPPROTO_TCP) {
      if (caplen < l4_off + sizeof(struct tcphdr)) return PARSE_TRUNCATED;
      const struct tcphdr *tcp = (const struct tcphdr *)(data + l4_off);
      out->src_port = ntohs(tcp->th_sport);
      out->dst_port = ntohs(tcp->th_dport);
    } else if (out->l4_proto == IPPROTO_UDP) {
      if (caplen < l4_off + sizeof(struct udphdr)) return PARSE_TRUNCATED;
      const struct udphdr *udp = (const struct udphdr *)(data + l4_off);
      out->src_port = ntohs(udp->uh_sport);
      out->dst_port = ntohs(udp->uh_dport);
    } else {
      out->src_port = 0;
      out->dst_port = 0;
    }

    return PARSE_OK;
  }

  /* IPv6 分支。 */
  if (ether_type == ETHERTYPE_IPV6) {
    if (caplen < off + sizeof(struct ip6_hdr)) return PARSE_TRUNCATED;

    const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(data + off);

    out->ip_version = 6;
    memset(out->src_ip, 0, sizeof(out->src_ip));
    memset(out->dst_ip, 0, sizeof(out->dst_ip));
    memcpy(out->src_ip, &ip6->ip6_src, 16);
    memcpy(out->dst_ip, &ip6->ip6_dst, 16);

    out->l3 = data + off;
    out->l3_len = (uint16_t)(caplen - off);

    uint8_t l4_proto = 0;
    uint16_t l4_off = 0;
    parse_result_t r = parse_ipv6_find_l4(data, caplen, off, &l4_proto, &l4_off);
    if (r != PARSE_OK) {
      out->l4_proto = l4_proto;
      out->src_port = 0;
      out->dst_port = 0;
      return r;
    }

    out->l4_proto = l4_proto;

    if (l4_proto == IPPROTO_TCP) {
      if (caplen < l4_off + sizeof(struct tcphdr)) return PARSE_TRUNCATED;
      const struct tcphdr *tcp = (const struct tcphdr *)(data + l4_off);
      out->src_port = ntohs(tcp->th_sport);
      out->dst_port = ntohs(tcp->th_dport);
    } else if (l4_proto == IPPROTO_UDP) {
      if (caplen < l4_off + sizeof(struct udphdr)) return PARSE_TRUNCATED;
      const struct udphdr *udp = (const struct udphdr *)(data + l4_off);
      out->src_port = ntohs(udp->uh_sport);
      out->dst_port = ntohs(udp->uh_dport);
    } else {
      out->src_port = 0;
      out->dst_port = 0;
    }

    return PARSE_OK;
  }

  return PARSE_UNSUPPORTED;
}

/* endpoint 排序比较函数：
 * 为构造双向 canonical key，保证 A<->B 与 B<->A 归并到同一 key。
 * 顺序规则：先地址字节序比较，再比较端口。
 */
static int endpoint_cmp(const endpoint_t *a, const endpoint_t *b) {
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

/* 从解析结果构造:
 * - 原始方向 src/dst endpoint（用于方向判断）
 * - 双向规范化 flow key（用于 flow table 键）
 */
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

/* 比较两个 endpoint 是否完全相同（用于 c2s/s2c 方向判定）。 */
bool endpoint_equal(const endpoint_t *a, const endpoint_t *b) {
  if (a->ip_version != b->ip_version) return false;
  if (a->port != b->port) return false;
  if (a->ip_version == 4) return memcmp(a->addr, b->addr, 4) == 0;
  return memcmp(a->addr, b->addr, 16) == 0;
}

/* reader 侧“快速分流 hash”：
 * - 目标是快，不追求与 flow_table 完全同构
 * - 基于 5 元组主要字段生成 32-bit hash
 *
 * 注意：
 * - 这是“分发 hash”，不是“状态表主键”
 * - 真正的流主键在 worker 中由 flow_key_from_packet + flow_key_hash 决定
 */
uint32_t compute_flow_hash(const uint8_t *data, uint16_t len, uint32_t seed) {
  if (len < 34) return 0;

  uint16_t eth_type = ntohs(*(uint16_t *)(data + 12));

  /* 跳过可能存在的 VLAN/QinQ。 */
  uint16_t offset = 14;
  while (eth_type == 0x8100 || eth_type == 0x88a8) {
    if (offset + 4 > len) return 0;
    eth_type = ntohs(*(uint16_t *)(data + offset + 2));
    offset += 4;
  }

  /* 非 IP 包返回 seed（让上层仍可继续处理）。 */
  if (eth_type != 0x0800 && eth_type != 0x86DD) {
    return seed;
  }

  /* IPv4: 地址 + 协议 + (可选)端口混合。 */
  if (eth_type == 0x0800) {
    if (offset + 20 > len) return seed;

    const uint8_t *ip_hdr = data + offset;
    uint32_t src_ip = *(uint32_t *)(ip_hdr + 12);
    uint32_t dst_ip = *(uint32_t *)(ip_hdr + 16);
    uint8_t proto = ip_hdr[9];

    uint32_t hash = src_ip ^ dst_ip ^ (proto << 16);

    uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
    if (offset + ihl + 4 <= len && (proto == 6 || proto == 17)) {
      const uint8_t *l4_hdr = ip_hdr + ihl;
      uint16_t src_port = ntohs(*(uint16_t *)(l4_hdr + 0));
      uint16_t dst_port = ntohs(*(uint16_t *)(l4_hdr + 2));
      hash ^= (src_port << 16) | dst_port;
      hash ^= src_port ^ dst_port;
    }

    /* Murmur 风格 finalizer，增强 bit 扩散。 */
    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash ^ seed;
  }

  /* IPv6: 当前仅混入地址字段（未解析扩展头端口）。 */
  if (eth_type == 0x86DD) {
    if (offset + 40 > len) return seed;

    const uint8_t *ip6_hdr = data + offset;
    uint32_t hash = 0;

    for (int i = 0; i < 16; i += 4) {
      hash ^= *(uint32_t *)(ip6_hdr + 8 + i);
    }

    for (int i = 0; i < 16; i += 4) {
      hash ^= *(uint32_t *)(ip6_hdr + 24 + i);
    }

    hash ^= hash >> 16;
    hash *= 0x85ebca6b;
    hash ^= hash >> 13;
    hash *= 0xc2b2ae35;
    hash ^= hash >> 16;

    return hash ^ seed;
  }

  return seed;
}
