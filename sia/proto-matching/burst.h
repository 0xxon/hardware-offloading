/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2015 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

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
