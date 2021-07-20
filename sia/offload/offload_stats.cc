#include <offload.h>
#include <offload_stats.h>
#include <helpers.h>

#include <rte_mbuf.h>
#include <rte_malloc.h>
#include <rte_hash.h>
#include <rte_ethdev.h>

offload_stats * offload_stats_create(offload *o) {
    offload_stats *os = (offload_stats *)rte_zmalloc(NULL, 
            sizeof(struct offload_stats), RTE_CACHE_LINE_SIZE);

    os->o = o;

    /* initialize hash table for aggregation */
    char name[64];
    snprintf(name, sizeof(name), "offload_stats_hash_%u", rte_lcore_id());
    os->hash = create_hashtable(name,
                               OFFLOAD_DROP_STATS_PKT_CAPACITY,
                               sizeof(struct offload_stats_key));

    /* Initialize stats packet Ethernet header */
    os->pkt.ether.d_addr = OFFLOAD_DROP_STATS_PKT_DST;
    os->pkt.ether.s_addr = OFFLOAD_DROP_STATS_PKT_SRC;
    os->pkt.ether.ether_type = OFFLOAD_DROP_STATS_PKT_ETHERTYPE;

    return os;
}

/* Transmits the current stats packet and resets state for next packet */
static inline void send_stats_pkt(offload_stats *os) {
    /* Create a new mbuf from our mbuf pool */
    rte_mbuf *m = rte_pktmbuf_alloc(os->o->pktmbuf_pool);

    if (m == NULL) {
        rte_exit(EXIT_FAILURE, "offload_make_mbuf could not allocate mbuf");
    }

    /* pointer to data region of new pkt mbuf */
    void *m_data = rte_pktmbuf_append(m, sizeof(os->pkt));

    /* actually copy the packet data into the mbuf */
    rte_memcpy(m_data, &os->pkt, sizeof(os->pkt));

    /* transmit stats packet */
    if (rte_eth_tx_burst(INPUT_PORT^1, 0, &m, 1) < 1)
        rte_pktmbuf_free(m);

    /* reset state */
    rte_hash_reset(os->hash);
    os->pkt.nb_entries = 0;
}

void offload_stats_handle(offload_stats *os, offload_pkt_data *opd) {
    /* Lookup in hash table */
    offload_stats_key key = {
        .src_addr = opd->inner_data.ipv4.src_addr,
        .dst_addr = opd->inner_data.ipv4.dst_addr,
        .dst_port = opd->inner_data.tcp.dst_port
    };

    offload_stats_pkt_entry *entry;

    int ret = rte_hash_lookup_with_hash_data(os->hash, 
            &key, opd->stats_key_hash, (void**)&entry);

    /* Not in hash table => try to insert */
    if (ret < 0) {
        /* if stats packet is full and we need to insert a new group, we send
         * the existing stats packet and reset our state */
        if (os->pkt.nb_entries == OFFLOAD_DROP_STATS_PKT_CAPACITY) {
            send_stats_pkt(os);
        }
        /* insert new group into stats packet and update table */
        entry = &os->pkt.entries[os->pkt.nb_entries++];
        ret = rte_hash_add_key_with_hash_data(os->hash, &key,
                opd->stats_key_hash, entry);
        if (ret < 0)
            rte_exit(EXIT_FAILURE, 
                     "Cannot insert offload_stats group into hash (%s)\n",
                     rte_strerror(rte_errno));
        entry->key = key;
        entry->count = 1;
        entry->bytes = opd->data_len;
    }
    /* Group already in table => update stats for the grouping */
    else if(entry != NULL) {
        entry->count++;
        entry->bytes += opd->data_len;
    }
}
