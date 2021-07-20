#pragma once

#include <rte_mbuf.h>
#include <rte_ethdev.h>

#include <config.h>

/*
 * Simple struct for dealing with a burst of packets and inlined
 * helper functions for manipulating/sending packet bursts.
 */

// in the worst case, we might have to add 1 SYN 
// for every ACK in a RX'd burst => 2x packets
#define BURST_BUF_CAPACITY (BURST_SIZE*2)

typedef struct burst {
    // give some leeway
    struct rte_mbuf* bufs[BURST_BUF_CAPACITY]; 
    unsigned count; // number of mbufs in the burst
} burst;

// Add the given packet to the given burst
static inline void burst_add(struct burst *b, struct rte_mbuf *m) {
    if (b->count >= BURST_BUF_CAPACITY)
        rte_exit(EXIT_FAILURE, "Couldn't add packet to burst (burst is full)\n");
    b->bufs[b->count++] = m;
}

// Transmit the given burst on the given port
// Return number of packets not transmitted
static inline uint16_t burst_send(struct burst *b, uint16_t port) {
    // don't even bother with empty bursts
    if (b->count == 0)
        return 0;
    // TODO: check if we want a different TX queue?
    uint16_t nb_sent = rte_eth_tx_burst(port, rte_lcore_id(), 
            b->bufs, b->count);
    uint16_t ret = b->count - nb_sent;
    // free unsent packets
    while (nb_sent < b->count)
        rte_pktmbuf_free(b->bufs[nb_sent++]);
    // reset the burst
    b->count = 0;
    // return the number of packets NOT sent
    return ret;
}

// Enqueue the given burst on the given ring
// Return number of packets NOT enqueued
static inline uint16_t burst_enqueue(struct burst *b, rte_ring *ring) {
    // don't even bother with empty bursts
    if (b->count == 0)
        return 0;
    // enqueue the burst of packets onto the given rte_ring
    uint16_t nb_qd = rte_ring_enqueue_burst(ring, (void**)b->bufs, 
            b->count, NULL);
    uint16_t ret = b->count - nb_qd;
    // free packets that couldn't be queued
    while (nb_qd < b->count)
        rte_pktmbuf_free(b->bufs[nb_qd++]);
    // reset the burst
    b->count = 0;
    // return the number of packets NOT queued on the ring
    return ret;
}
