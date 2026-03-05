#ifndef PACKET_PARSER_H
#define PACKET_PARSER_H

#include <stdbool.h>
#include <stdint.h>

/* Parsed view of a packet (Ethernet -> IPv4/IPv6 -> TCP/UDP) */
typedef struct {
  uint8_t ip_version; /* 4 or 6 */
  uint8_t l4_proto;   /* IPPROTO_TCP, IPPROTO_UDP, ... */

  /* host-order ports (0 if not TCP/UDP or not available) */
  uint16_t src_port;
  uint16_t dst_port;

  /* src/dst address bytes. For IPv4 only first 4 bytes are used. */
  uint8_t src_ip[16];
  uint8_t dst_ip[16];

  /* pointer to L3 header (IP header) within original packet buffer */
  const uint8_t *l3;
  uint16_t l3_len; /* bytes from l3 to end of captured buffer */
} parsed_packet_t;

typedef enum {
  PARSE_OK = 0,
  PARSE_UNSUPPORTED = 1,
  PARSE_TRUNCATED = 2
} parse_result_t;

/*
 * Parse an Ethernet packet.
 *
 * - Supports 802.1Q/802.1ad VLAN tags.
 * - Supports IPv4 and IPv6.
 * - Extracts TCP/UDP ports when possible.
 *
 * On success returns PARSE_OK and fills 'out'.
 */
parse_result_t parse_ethernet_frame(const uint8_t *data, uint16_t caplen, parsed_packet_t *out);

#endif /* PACKET_PARSER_H */
