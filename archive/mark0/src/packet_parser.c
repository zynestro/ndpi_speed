#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _BSD_SOURCE
#define _BSD_SOURCE
#endif

#include "packet_parser.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <string.h>

/* EtherTypes */
#define ETHERTYPE_IPV4 0x0800
#define ETHERTYPE_IPV6 0x86DD
#define ETHERTYPE_VLAN 0x8100
#define ETHERTYPE_QINQ 0x88A8
#define ETH_HDR_LEN 14

/* IPv6 extension headers */
static inline bool is_ipv6_ext_header(uint8_t nh) {
  switch (nh) {
    case 0:   /* Hop-by-hop */
    case 43:  /* Routing */
    case 44:  /* Fragment */
    case 50:  /* ESP */
    case 51:  /* AH */
    case 60:  /* Destination options */
      return true;
    default:
      return false;
  }
}

static parse_result_t parse_ipv6_find_l4(const uint8_t *pkt, uint16_t caplen,
                                        uint16_t ip6_off,
                                        uint8_t *out_l4_proto,
                                        uint16_t *out_l4_off) {
  if (caplen < ip6_off + sizeof(struct ip6_hdr)) return PARSE_TRUNCATED;

  const struct ip6_hdr *ip6 = (const struct ip6_hdr *)(pkt + ip6_off);
  uint8_t nh = ip6->ip6_nxt;
  uint16_t off = ip6_off + (uint16_t)sizeof(struct ip6_hdr);

  /* Walk extension headers (best effort). */
  while (is_ipv6_ext_header(nh)) {
    if (nh == 44) {
      /* Fragment header is fixed 8 bytes. Next header at byte 0. */
      if (caplen < off + 8) return PARSE_TRUNCATED;
      nh = *(pkt + off);
      off += 8;
      continue;
    }

    if (nh == 51) {
      /* AH: (Hdr Ext Len + 2) * 4 */
      if (caplen < off + 2) return PARSE_TRUNCATED;
      uint8_t next = *(pkt + off);
      uint8_t hdrlen = *(pkt + off + 1);
      uint16_t bytes = (uint16_t)(hdrlen + 2U) * 4U;
      if (caplen < off + bytes) return PARSE_TRUNCATED;
      nh = next;
      off += bytes;
      continue;
    }

    if (nh == 50) {
      /* ESP is encrypted; we can't reliably find L4. */
      *out_l4_proto = nh;
      *out_l4_off = off;
      return PARSE_UNSUPPORTED;
    }

    /* Hop-by-hop, Routing, Dest-Opts:
     * header len is (Hdr Ext Len + 1) * 8
     */
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

parse_result_t parse_ethernet_frame(const uint8_t *data, uint16_t caplen, parsed_packet_t *out) {
  memset(out, 0, sizeof(*out));
  if (caplen < ETH_HDR_LEN) return PARSE_TRUNCATED;

  /* EtherType */
  uint16_t ether_type = (uint16_t)((data[12] << 8) | data[13]);
  uint16_t off = ETH_HDR_LEN;

  /* VLAN/QinQ tags (support up to 2 tags; extendable) */
  for (int i = 0; i < 2 && (ether_type == ETHERTYPE_VLAN || ether_type == ETHERTYPE_QINQ); i++) {
    if (caplen < off + 4) return PARSE_TRUNCATED;
    ether_type = (uint16_t)((data[off + 2] << 8) | data[off + 3]);
    off += 4;
  }

  if (ether_type == ETHERTYPE_IPV4) {
    if (caplen < off + sizeof(struct ip)) return PARSE_TRUNCATED;

    const struct ip *ip4 = (const struct ip *)(data + off);
    uint8_t ihl = (uint8_t)(ip4->ip_hl * 4);
    if (ihl < 20) return PARSE_UNSUPPORTED;
    if (caplen < off + ihl) return PARSE_TRUNCATED;

    out->ip_version = 4;
    out->l4_proto = ip4->ip_p;

    /* addresses */
    memset(out->src_ip, 0, sizeof(out->src_ip));
    memset(out->dst_ip, 0, sizeof(out->dst_ip));
    memcpy(out->src_ip, &ip4->ip_src, 4);
    memcpy(out->dst_ip, &ip4->ip_dst, 4);

    /* l3 pointer and length */
    out->l3 = data + off;
    out->l3_len = (uint16_t)(caplen - off);

    /* ports */
    uint16_t l4_off = (uint16_t)(off + ihl);
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
