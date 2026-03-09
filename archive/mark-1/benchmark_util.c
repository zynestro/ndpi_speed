/*
 * benchmark_util.c
 *
 * Utility functions for high-performance benchmark
 */

#include "ndpiBenchmark.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

/* *********************************************** */

packet_pool_t* load_pcap_to_memory(const char *pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_offline(pcap_file, errbuf);
    
    if (!handle) {
        fprintf(stderr, "Error opening PCAP: %s\n", errbuf);
        return NULL;
    }
    
    /* First pass: count packets and total size */
    struct pcap_pkthdr *header;
    const u_char *data;
    uint32_t num_packets = 0;
    uint64_t total_size = 0;
    
    while (pcap_next_ex(handle, &header, &data) > 0) {
        num_packets++;
        total_size += sizeof(mem_packet_t) + header->caplen;
    }
    
    if (num_packets == 0) {
        fprintf(stderr, "Error: No packets in PCAP file\n");
        pcap_close(handle);
        return NULL;
    }
    
    /* Allocate packet pool */
    packet_pool_t *pool = malloc(sizeof(packet_pool_t));
    if (!pool) {
        pcap_close(handle);
        return NULL;
    }
    
    pool->num_packets = num_packets;
    pool->raw_data_size = total_size;
    pool->total_bytes = 0;
    
    /* Allocate aligned memory for packet data */
    if (posix_memalign((void**)&pool->raw_data, 64, total_size) != 0) {
        fprintf(stderr, "Error: Failed to allocate packet buffer\n");
        free(pool);
        pcap_close(handle);
        return NULL;
    }
    
    /* Allocate packet pointer array */
    pool->packets = malloc(sizeof(mem_packet_t*) * num_packets);
    if (!pool->packets) {
        free(pool->raw_data);
        free(pool);
        pcap_close(handle);
        return NULL;
    }
    
    /* Second pass: copy packets to memory */
    pcap_close(handle);
    handle = pcap_open_offline(pcap_file, errbuf);
    if (!handle) {
        free(pool->packets);
        free(pool->raw_data);
        free(pool);
        return NULL;
    }
    
    uint8_t *ptr = pool->raw_data;
    uint32_t pkt_id = 0;
    
    while (pcap_next_ex(handle, &header, &data) > 0) {
        mem_packet_t *pkt = (mem_packet_t*)ptr;
        
        pkt->packet_id = pkt_id;
        pkt->timestamp_us = header->ts.tv_sec * 1000000ULL + header->ts.tv_usec;
        pkt->caplen = header->caplen;
        pkt->wirelen = header->len;
        
        memcpy(pkt->data, data, header->caplen);
        
        pool->packets[pkt_id] = pkt;
        pool->total_bytes += header->caplen;
        
        ptr += sizeof(mem_packet_t) + header->caplen;
        pkt_id++;
    }
    
    pcap_close(handle);
    return pool;
}

/* *********************************************** */

void free_packet_pool(packet_pool_t *pool) {
    if (pool) {
        if (pool->raw_data) free(pool->raw_data);
        if (pool->packets) free(pool->packets);
        free(pool);
    }
}

/* *********************************************** */

/* Simple hash function for flow tuple */
uint32_t compute_flow_hash(const uint8_t *data, uint16_t len, uint32_t seed) {
    if (len < 34) return 0;  /* Too short for IP packet */
    
    /* Parse Ethernet + IP header */
    uint16_t eth_type = ntohs(*(uint16_t*)(data + 12));
    
    /* Skip VLAN tags if present */
    uint16_t offset = 14;
    while (eth_type == 0x8100 || eth_type == 0x88a8) {
        if (offset + 4 > len) return 0;
        eth_type = ntohs(*(uint16_t*)(data + offset + 2));
        offset += 4;
    }
    
    if (eth_type != 0x0800 && eth_type != 0x86DD) {
        return seed;  /* Not IPv4/IPv6 */
    }
    
    /* IPv4 */
    if (eth_type == 0x0800) {
        if (offset + 20 > len) return seed;
        
        const uint8_t *ip_hdr = data + offset;
        uint32_t src_ip = *(uint32_t*)(ip_hdr + 12);
        uint32_t dst_ip = *(uint32_t*)(ip_hdr + 16);
        uint8_t proto = ip_hdr[9];
        
        uint32_t hash = src_ip ^ dst_ip ^ (proto << 16);
        
        /* Add ports for TCP/UDP */
        uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
        if (offset + ihl + 4 <= len && (proto == 6 || proto == 17)) {
            const uint8_t *l4_hdr = ip_hdr + ihl;
            uint16_t src_port = ntohs(*(uint16_t*)(l4_hdr + 0));
            uint16_t dst_port = ntohs(*(uint16_t*)(l4_hdr + 2));
            hash ^= (src_port << 16) | dst_port;
        }
        
        return hash ^ seed;
    }
    
    /* IPv6 - simplified */
    if (eth_type == 0x86DD) {
        if (offset + 40 > len) return seed;
        
        const uint8_t *ip6_hdr = data + offset;
        uint32_t hash = 0;
        
        /* Hash source address */
        for (int i = 0; i < 16; i += 4) {
            hash ^= *(uint32_t*)(ip6_hdr + 8 + i);
        }
        
        /* Hash destination address */
        for (int i = 0; i < 16; i += 4) {
            hash ^= *(uint32_t*)(ip6_hdr + 24 + i);
        }
        
        return hash ^ seed;
    }
    
    return seed;
}

/* *********************************************** */

void assign_packets_to_workers(packet_pool_t *pool, 
                              worker_context_t *workers,
                              uint32_t num_workers) {
    /* First pass: count packets per worker */
    uint32_t *packet_counts = calloc(num_workers, sizeof(uint32_t));
    uint8_t *packet_assignment = malloc(pool->num_packets);
    
    for (uint32_t i = 0; i < pool->num_packets; i++) {
        mem_packet_t *pkt = pool->packets[i];
        uint32_t hash = compute_flow_hash(pkt->data, pkt->caplen, 0);
        uint8_t worker_id = hash % num_workers;
        
        packet_assignment[i] = worker_id;
        packet_counts[worker_id]++;
    }
    
    /* Allocate packet index arrays for each worker */
    for (uint32_t w = 0; w < num_workers; w++) {
        workers[w].packet_indices = malloc(packet_counts[w] * sizeof(uint32_t));
        workers[w].num_packets = 0;
    }
    
    /* Second pass: assign packet indices */
    for (uint32_t i = 0; i < pool->num_packets; i++) {
        uint8_t w = packet_assignment[i];
        workers[w].packet_indices[workers[w].num_packets++] = i;
    }
    
    free(packet_assignment);
    free(packet_counts);
}

/* *********************************************** */

void randomize_packet_tuple(mem_packet_t *pkt, uint32_t loop_id, uint32_t worker_id) {
    if (pkt->caplen < 34) return;
    
    /* Parse Ethernet header */
    uint16_t eth_type = ntohs(*(uint16_t*)(pkt->data + 12));
    uint16_t offset = 14;
    
    /* Skip VLAN tags */
    while (eth_type == 0x8100 || eth_type == 0x88a8) {
        if (offset + 4 > pkt->caplen) return;
        eth_type = ntohs(*(uint16_t*)(pkt->data + offset + 2));
        offset += 4;
    }
    
    if (eth_type != 0x0800) return;  /* Only handle IPv4 for now */
    
    if (offset + 20 > pkt->caplen) return;
    
    uint8_t *ip_hdr = pkt->data + offset;
    uint8_t proto = ip_hdr[9];
    uint8_t ihl = (ip_hdr[0] & 0x0F) * 4;
    
    /* Modify IP ID field to make each loop appear as different flow */
    uint32_t modifier = (loop_id * 65521 + worker_id * 251) & 0xFFFF;
    uint16_t *ip_id = (uint16_t*)(ip_hdr + 4);
    uint16_t orig_id = ntohs(*ip_id);
    *ip_id = htons((orig_id ^ modifier) & 0xFFFF);
    
    /* Modify source port for TCP/UDP to further differentiate flows */
    if ((proto == 6 || proto == 17) && offset + ihl + 4 <= pkt->caplen) {
        uint8_t *l4_hdr = ip_hdr + ihl;
        uint16_t *src_port = (uint16_t*)(l4_hdr + 0);
        uint16_t orig_port = ntohs(*src_port);
        
        /* XOR with loop_id to create unique port */
        uint16_t new_port = orig_port ^ ((loop_id & 0xFF) << 8);
        if (new_port < 1024) new_port += 10000;  /* Avoid privileged ports */
        *src_port = htons(new_port);
    }
    
    /* Note: We don't recalculate checksums as nDPI doesn't validate them */
}

/* *********************************************** */

void adjust_packet_timestamp(mem_packet_t *pkt, uint32_t loop_id) {
    /* Add time offset to avoid flow timeout issues */
    /* Each loop adds 1 hour to timestamp */
    pkt->timestamp_us += (uint64_t)loop_id * 3600 * 1000000;
}
