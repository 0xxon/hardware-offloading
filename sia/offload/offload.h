#pragma once

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <offload.h>

#include <offload_stats.h>
#include <config.h>
#include <debug.h>
#include <tcp.h>

/* Tightly-packed raw packet data */
struct __attribute__((packed)) offload_pkt_data_inner {
    ether_hdr ether;    // 14 bytes
    ipv4_hdr ipv4;      // 20 bytes
    tcp_hdr tcp;        // 28 bytes
    uint8_t tcp_opts[40]; // 40 bytes of options in header
#if (ETHER_TRAILER_LENGTH > 0)
    uint8_t trailer[ETHER_TRAILER_LENGTH];
#endif
};

typedef struct offload_pkt_data {
    /* raw packet data (packed bytes) */
    struct offload_pkt_data_inner inner_data;
    /* size of raw packet data */
    uint16_t data_len;
    /* packet timestamp from udata field of mbuf */
    uint64_t timestamp;
    /* hash of src, dst and dport for dropped packet stats worker */
    hash_sig_t stats_key_hash;
    /* pointer to mempool this struct is in */
    rte_mempool *pool;
} offload_pkt_data;

typedef struct offload_pkt {
    /* TCP connection being offloaded */
    tcp_conn conn;
    /* hash signature of TCP connection */
    hash_sig_t hs;
    /* packet contents and metadata */
    offload_pkt_data *data;
    /* next packet in offload table (newer) */
    offload_pkt *next;
    /* prev packet in offload table (older) */
    offload_pkt *prev;
} offload_pkt;

typedef struct offload_printstats {
    unsigned size;
    unsigned capacity;
    unsigned long long drop_cnt;
    uint64_t oldest_ts;
    uint64_t newest_ts;
} offload_printstats;

typedef struct offload {
    // Storage for table entry and linked-list metadata
    offload_pkt entries[OFFLOAD_TABLE_SIZE * 2];
    // Number of offload entries
    unsigned len = 0;
    // Number of packets dropped from offload table
    unsigned long long drop_count = 0;
    // Least-recently added offload entry
    offload_pkt *tail = NULL;
    // Most-recently added offload entry
    offload_pkt *head = NULL;
    // DPDK hashtable (rte_hash)
    rte_hash *hash = NULL;
    // Pool to store our offload_pkt_data structs
    // (i.e. where clones of complete packets are stored)
    rte_mempool *pool = NULL;
    // Packet mbuf pool created in EAL main thread
    rte_mempool *pktmbuf_pool = NULL;
    // Stats worker instance to send data
    offload_stats *stats = NULL;
} offload;


/*
 ** Initialize our offload table.
 */
offload * offload_create(rte_mempool *pktmbuf_pool);

/*
 ** Stop tracking the given entry in our offload table.
 */
void offload_remove(offload *o, offload_pkt *p, bool free_data);
void offload_remove(offload *o, offload_pkt *p, hash_sig_t hs, bool free_data);
void offload_remove(offload *o, tcp_conn *c, bool fre_data);
void offload_remove(offload *o, tcp_conn *c, hash_sig_t hs, bool free_data);

/*
 ** Allocate an mbuf in the given pool for a given offload entry.
 */
rte_mbuf * offload_make_mbuf(offload *o, offload_pkt *p);

/*
 ** Start tracking the given packet with the given tcp_connection as the key.
 */
offload_pkt * offload_insert(offload *o, tcp_conn *c, rte_mbuf *m);
offload_pkt * offload_insert(offload *o, tcp_conn *c, rte_mbuf *m, hash_sig_t hs);

/*
 ** Lookup a TCP connection key in the offload table.
 */
offload_pkt * offload_lookup(offload *o, tcp_conn *c);
offload_pkt * offload_lookup(offload *o, tcp_conn *c, hash_sig_t hs);

/*
 ** Compute the rte_hash signature for the given tcp_conn. This hash signature
 ** may then be passed into other offload_* functions that support the `hs`
 ** parameter.
 */
inline hash_sig_t offload_hash_sig(offload *o, tcp_conn *c) {
    return rte_hash_hash(o->hash, c);
}

/*
 ** Fills the given offload_printstats struct with stats information from the
 ** given offload table.
 */
void offload_get_stats(offload *o, offload_printstats *s);

/*
 ** For debug purposes, prints a visual representation of offload table
 ** entries in order from least-recently-inserted to most-recently-inserted.
 */
void offload_print_table(offload *o);
