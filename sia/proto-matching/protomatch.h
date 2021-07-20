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
#include <rte_hash.h>

#include <re2/re2.h>

#include <config.h>
#include <debug.h>
#include <tcp.h>

/* Protomatch TCP flow table entry */
/* NOTE: The table itself is an ordered hashmap, using a doubly-linked-list to
 *       provide the order. The right of the list (head) is the most recently 
 *       active flow, and the left (tail) is least recently active. */
typedef struct protomatch_flow {
    /* @key: originator tcp_conn key corresponding to @key_h */
    tcp_conn key;
    /* @key_h: rte_hash_hash signature of key, so we can avoid expensive
     *         unnecessary multiple hashing operations in the data plane */
    hash_sig_t key_h;
    /* @data: true if data matches regexp, false if data not yet seen */
    bool data;
    /* @seq_orig: TCP initial sequence number of connection originator, 
      *           in CPU endianness */
    uint32_t seq_orig;
    /* @prev, @next: linked-list pointers */
    protomatch_flow *prev;
    protomatch_flow *next;
    /* @timestamp: 8-byte packet timestamp */
    uint64_t timestamp;
} protomatch_flow;

/* Protomatch instance struct */
typedef struct protomatch {
    /* Storage for table entry and linked-list metadata */
    protomatch_flow entries[FLOW_TABLE_SIZE * 2];
    /* Number of flow entries */
    unsigned len = 0;
    /* Least-recently added flow entry (LEFT-MOST) */
    protomatch_flow *tail = NULL;
    /* Most-recently added flow entry (RIGHT-MOST) */
    protomatch_flow *head = NULL;
    /* DPDK hashtable (rte_hash) */
    rte_hash *hash = NULL;
    /* regexp to match on first originator data packet */
    RE2 *regexp = NULL;
    /* Statistics tracking */
    unsigned long long stats_flowdropped = 0; // # of flow tbl entries dropped
    unsigned long long stats_pktdropped = 0;  // # of discarded packets
    unsigned long long stats_regmatch = 0;
    unsigned long long stats_regnomatch = 0;
    unsigned long long stats_syndata = 0;
    unsigned long long stats_nontcpipv4 = 0;
} protomatch;

/* Statistics pertaining to a protocol matcher instance */
typedef struct protomatch_stats {
    unsigned size;
    unsigned capacity;
    unsigned long long flow_drop_cnt;
    unsigned long long pkt_discard_cnt;
    unsigned long long regexp_match_cnt;
    unsigned long long regexp_nonmatch_cnt;
    unsigned long long syndata_cnt;
    unsigned long long nontcpipv4_cnt;
    uint64_t oldest_ts;
    uint64_t newest_ts;
} protomatch_stats;


/*
 ** Initialize our protomatch table.
 */
protomatch * protomatch_init(char const * name);

/*
 ** Insert and initialize a new flow entry.
 **
 ** NOTE: @seq_orig should already be converted to CPU endianness before
 **       calling this function.
 */
protomatch_flow * protomatch_insert_flow(protomatch *pm,
                                         tcp_conn *key,
                                         bool data,
                                         uint32_t seq_orig,
                                         uint64_t timestamp);

/*
 ** Look up whether a flow exists with the given key. Returns the flow, or
 ** a NULL pointer if there is no match in the flow table.
 **
 ** @originator_out is an output variable, true if key matches on originator
 **                 flow, false if it matches for responder flow.
 */
protomatch_flow * protomatch_lookup_flow(protomatch *pm,
                                         tcp_conn *key,
                                         bool *originator_out);

/*
 ** Moves the specified flow to the front of the flow queue. Should be called
 ** when a packet is received for an existing flow entry, to stop the entry
 ** from expiring.
 */
void protomatch_touch_flow(protomatch *pm,
                           protomatch_flow *flow,
                           uint64_t timestamp);

/*
 ** Remove an existing flow from the protomatching flow table.
 */
void protomatch_remove_flow(protomatch *pm, protomatch_flow *flow);

/*
 ** Handle packet burst.
 ** out_pkts should be pointer to array of capacity >= |in_pkts|
 ** Returns number of output packets.
 */
uint16_t protomatch_burst(protomatch *pm, 
                          rte_mbuf **in_pkts, 
                          const uint16_t nb_in_pkts, 
                          rte_mbuf **out_pkts);

/*
 ** Fills the given protomatch_stats struct with stats information from the
 ** given protocol matching instance.
 */
void protomatch_get_stats(protomatch *pm, protomatch_stats *s);
