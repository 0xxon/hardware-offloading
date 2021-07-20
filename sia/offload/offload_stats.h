#pragma once

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_jhash.h>

#include <config.h>
#include <debug.h>
#include <tcp.h>

/** 
 ** offload_stats.h:
 **  Custom wire protocol for reporting offlaod statistics
 **/

/* destination MAC address for custom stats packet proto */
#define OFFLOAD_DROP_STATS_PKT_DST {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
/* source MAC for custom stats packet wire proto */
#define OFFLOAD_DROP_STATS_PKT_SRC {0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
/* EtherType field value for custom stats packet wire protocol */
#define OFFLOAD_DROP_STATS_PKT_ETHERTYPE 0x6666

/* number of entries per packet in custom stats packet wire protocol */
#define OFFLOAD_DROP_STATS_PKT_CAPACITY 57

/* initial value for stats grouping hash table */
#define OFFLOAD_STATS_HASH_INIT_VAL 0

/* These are declared in offload.h, which we can't include because it creates
 * a circular dependency, so we re-define the type only here */
typedef struct offload_pkt_data offload_pkt_data;
typedef struct offload offload;

/* key for stats grouping hash table */
typedef struct offload_stats_key {
    uint32_t src_addr;
    uint32_t dst_addr;
    uint16_t dst_port;
} __attribute__((packed)) offload_stats_key;

/* 
 * Custom stats packets consist of an Ethernet header followed by a
 * tightly-packed list of offload_stats_pkt_entry.
 */

/* entries for each stats packet (tightly-packed) */
typedef struct offload_stats_pkt_entry {
	struct offload_stats_key key; // 10 bytes
	uint64_t count; // 8 bytes
	uint64_t bytes; // 8 bytes
} __attribute__((packed)) offload_stats_pkt_entry;

/* stats packet specification (tightly-packed) */
typedef struct offload_stats_pkt {
    ether_hdr ether;    // 14 bytes
    uint8_t nb_entries; // 1 byte
    offload_stats_pkt_entry entries[OFFLOAD_DROP_STATS_PKT_CAPACITY]; // 26 bytes each
} __attribute__((__packed__)) offload_stats_pkt;


typedef struct offload_stats {
	/* stats packet under construction */
	offload_stats_pkt pkt;
	/* hash table for stats aggregations */
	rte_hash *hash;
	/* offload instance to which this stats collector belongs */
	offload *o;
} offload_stats;


/* compute hash value for stats grouping rte_hash table */
hash_sig_t inline offload_stats_hash(const void *key) {
    return rte_jhash(key, 
                     sizeof(struct offload_stats_key),
                     OFFLOAD_STATS_HASH_INIT_VAL);
}

hash_sig_t inline offload_stats_hash(const tcp_conn *c) {
	offload_stats_key osk = {
		.src_addr = c->orig.ip,
		.dst_addr = c->dest.ip,
		.dst_port = (uint16_t) c->dest.port
	};

    return rte_jhash(&osk, 
                     sizeof(struct offload_stats_key),
                     OFFLOAD_STATS_HASH_INIT_VAL);
}

offload_stats * offload_stats_create(offload *o);
void offload_stats_handle(offload_stats *os, offload_pkt_data *opd);
