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

#include <iostream>

#include <assert.h>

#include <rte_mbuf.h>
#include <rte_hash.h>
#include <rte_cycles.h>
#include <rte_memcpy.h>
#include <rte_jhash.h>
#include <rte_malloc.h>
#include <rte_errno.h>

#include <re2/re2.h>

#include <config.h>
#include <debug.h>
#include <tcp.h>
#include <protomatch.h>

//// Function definitions

/*
 ** Initialize a DPDPK hashtable with keys being tcp_conns.
 */
static inline rte_hash * create_hashtable(char const * name, uint32_t size) {
    // h will store the pointer to our new hash
    struct rte_hash *h;

    // initialize parameters for new hash table
    struct rte_hash_parameters hash_params = {0};
    hash_params.name = name;
    hash_params.entries = size * 2; // keep load <50% to avoid excessive collisions
    hash_params.key_len = sizeof(struct tcp_conn);
    hash_params.socket_id = rte_socket_id();
    hash_params.hash_func = rte_jhash;
    hash_params.hash_func_init_val = 0;
    hash_params.extra_flag = RTE_HASH_EXTRA_FLAGS_TRANS_MEM_SUPPORT;

    // actually create the table
    // NOT MULTI-THREAD-SAFE
    h = rte_hash_create(&hash_params);

    if (h == NULL) {
        rte_exit(EXIT_FAILURE, "Problem creating hash table (%s) (%i)\n",
                rte_strerror(rte_errno), rte_errno);
    }

    return h;
}

/* Remove flow entry from PM linked list */
static inline void ll_unlink(protomatch *pm, protomatch_flow *flow) {
    if (flow->prev != NULL)
        flow->prev->next = flow->next;

    if (flow->next != NULL)
        flow->next->prev = flow->prev;

    if (pm->head == flow)
        pm->head = flow->prev;

    if (pm->tail == flow)
        pm->tail = flow->next;
}

static inline void ll_link_head(protomatch *pm, protomatch_flow *flow) {
    /* New head => no next flow */
    flow->next = NULL;

    /* Prev flow is old head */
    flow->prev = pm->head;

    /* Next flow of old head is this new head */
    if (pm->head != NULL)
        pm->head->next = flow;

    /* This is the new head */
    pm->head = flow;

    /* If there was no tail before, this is now the new tail */
    if (pm->tail == NULL)
        pm->tail = flow;
}

protomatch * protomatch_init(char const * name) {
    // Allocate a new protomatch struct
    protomatch *pm = (protomatch *)rte_zmalloc(NULL, sizeof(struct protomatch),
            RTE_CACHE_LINE_SIZE);

    char hname[RTE_HASH_NAMESIZE];
    snprintf(hname, sizeof(hname), "%s_pm_lcore_%u", name, rte_lcore_id());

    pm->hash = create_hashtable(hname, FLOW_TABLE_SIZE);
    // Concatenated Zeek originator regexps for HTTP, TLS, SSH, and SMTP
    // NOTE: to match a single byte, . doesn't work and we need to use \C
    pm->regexp = new RE2(
            /* HTTP */
            "(^[[:space:]]*(OPTIONS|GET|HEAD|POST|PUT|DELETE|TRACE|CONNECT|"
                "PROPFIND|PROPPATCH|MKCOL|COPY|MOVE|LOCK|UNLOCK|VERSION-CONTROL|"
                "REPORT|CHECKOUT|CHECKIN|UNCHECKOUT|MKWORKSPACE|UPDATE|LABEL|MERGE|"
                "BASELINE-CONTROL|MKACTIVITY|ORDERPATCH|ACL|PATCH|SEARCH|BCOPY|BDELETE|BMOVE|"
                "BPROPFIND|BPROPPATCH|NOTIFY|POLL|SUBSCRIBE|UNSUBSCRIBE|X-MS-ENUMATTS|"
                "RPC_OUT_DATA|RPC_IN_DATA)[[:space:]]*)"
            /* TLS */
            "|(^(\\x16\\x03[\\x00\\x01\\x02\\x03]\\C\\C\\x01\\C\\C\\C\\x03[\\x00"
                "\\x01\\x02\\x03]|\\C\\C\\C?\\x01[\\x00\\x03][\\x00\\x01\\x02\\x03\\x04])\\C*)"
            /* SSH */
            "|(^[sS][sS][hH]-[12]\\.)"
            /* SMTP originator (second data in stream but 1st from originator) */
            "|(^((|\\C*[\\n\\r])[[:space:]]*([hH][eE][lL][oO]|[eE][hH][lL][oO])))"
    );
    return pm;
}

protomatch_flow * protomatch_insert_flow(protomatch *pm,
                                         tcp_conn *key,
                                         bool data,
                                         uint32_t seq_orig,
                                         uint64_t timestamp) {

    /* Pre-compute rte_hash key */
    hash_sig_t key_h = rte_hash_hash(pm->hash, key);

    /* Do rte_hash insertion */
    int idx = rte_hash_lookup_with_hash(pm->hash, key, key_h);

    /* If the flow does not exist, insert a new table entry */
    if (idx < 0) {
        /* If table is full, drop the least-recently-touched flow */
        if (pm->len == FLOW_TABLE_SIZE)
            protomatch_remove_flow(pm, pm->tail);

        idx = rte_hash_add_key_with_hash(pm->hash, key, key_h);

        if (idx == -ENOSPC)
            rte_exit(EXIT_FAILURE, "Hash insertion error (-ENOSPC)");

        if (idx == -EINVAL)
            rte_exit(EXIT_FAILURE, "Hash insertion error (-EINVAL)");

        if (idx < 0)
            rte_exit(EXIT_FAILURE, "Hash insertion error");

        /* Increment number of flow entries */
        pm->len++;
    } else {
        /* If the flow already exists, existing flow table entry needs to be
         * unlinked from the linkedlist */
        ll_unlink(pm, &pm->entries[idx]);
    }

    /* Copy flow fields to flow entry struct */
    pm->entries[idx] = {
        .key = *key,
        .key_h = key_h,
        .data = data,
        .seq_orig = seq_orig,
        .prev = NULL,
        .next = NULL,
        .timestamp = timestamp,
    };

    /* Insert into linked list */
    ll_link_head(pm, &pm->entries[idx]);

    /* Return pointer to flow entry */
    return &pm->entries[idx];
}

// NOTE: originator is output bool
protomatch_flow * protomatch_lookup_flow(protomatch *pm,
                                         tcp_conn *key,
                                         bool *originator_out) {
    int idx = rte_hash_lookup(pm->hash, key);

    if (idx >= 0 && originator_out != NULL)
        *originator_out = true;

    /* No hit; try looking up reverse direction */
    if (idx < 0) {
        tcp_conn rev_key {
            .orig = key->dest,
            .dest = key->orig,
        };

        idx = rte_hash_lookup(pm->hash, &rev_key);

        /* No hit for originator or responder, return NULL */
        if (idx < 0)
            return NULL;

        /* If we did get a hit for responder (reverse), try set the out bool */
        else if (originator_out != NULL)
            *originator_out = false;
    }

    /* We got a match, return the entry */
    return &pm->entries[idx];
}

void protomatch_remove_flow(protomatch *pm, protomatch_flow *flow) {
    int ret = rte_hash_del_key_with_hash(pm->hash, &flow->key, flow->key_h);

    if (ret < 0) {
        rte_exit(EXIT_FAILURE,
                 "Tried to remove non-existent protomatch flow entry");
    }

    /* Decrement number of flow entries */
    pm->len--;

    /* Remove from linked list */
    ll_unlink(pm, flow);

    /* Increment counter of number of dropped flow entries */
    pm->stats_flowdropped++;
}

void protomatch_touch_flow(protomatch *pm,
                           protomatch_flow *flow,
                           uint64_t timestamp) {
    flow->timestamp = timestamp;

    /* Move to head of linked list */
    ll_unlink(pm, flow);
    ll_link_head(pm, flow);
}

/* Returns true if packet data matches regexp, false otherwise */
static bool match_packet(protomatch *pm, tcp_ip_hdrs *hdrs) {
    std::string data(hdrs->tcp_data, hdrs->tcp_datalen);
    return RE2::PartialMatch(data, *pm->regexp);
}

/* Returns true if packet is first originator data packet in flow,
 * false otherwise. Should only be called on a non-SYN packet. 
 * For SYN packets, it is sufficient to just check if datalen > 0 */
static bool is_first_data_packet(protomatch_flow *flow,
                                 tcp_ip_hdrs *hdrs,
                                 bool originator) {
    return ( originator &&
             !flow->data &&
             hdrs->tcp_datalen > 0 &&
             rte_be_to_cpu_32(hdrs->tcp_hdr->sent_seq) == flow->seq_orig+1 );
}

uint16_t protomatch_burst(protomatch *pm, rte_mbuf **in_pkts, const uint16_t
        nb_in_pkts, rte_mbuf **out_pkts) {
    uint16_t in = 0, out = 0;

    while (in < nb_in_pkts) {
        rte_mbuf *m = in_pkts[in++];

        /* Process TCP/IPv4 packets only */
        if (RTE_ETH_IS_IPV4_HDR(m->packet_type) && 
                (m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {

            struct tcp_ip_hdrs hdrs;
            tcp_get_ipv4_headers(m, &hdrs);

            tcp_conn conn = {
                .orig = {.ip = hdrs.ipv4_hdr->src_addr, .port = hdrs.tcp_hdr->src_port},
                .dest = {.ip = hdrs.ipv4_hdr->dst_addr, .port = hdrs.tcp_hdr->dst_port},
            };

            if ((hdrs.tcp_hdr->tcp_flags & TCP_SYN_FLAG) != 0 &&
                    (hdrs.tcp_hdr->tcp_flags & TCP_ACK_FLAG) == 0) {

                /* check if there's data in the SYN packet (e.g. TCP Fast Open) */
                /* if there is data, we need to already run a regexp match now */
                if (hdrs.tcp_datalen > 0) {
                    /* NOTE: we know this is from originator bc it's the first SYN */
                    pm->stats_syndata++;
                    if (match_packet(pm, &hdrs)) {
                        PT_LOG(DEBUG, "REGEXP MATCHED [SYN]: ");
                        TCP_LOG_PKT(DEBUG, m, true);
                        pm->stats_regmatch++;
                    } else {
                        /* NOTE: if this was the first data packet and there
                         * was no regexp match, then it should NOT be inserted
                         * into the flow table in the first place, and all
                         * future packets of the stream should be dropped */
                        PT_LOG(DEBUG, "Failed to match: ");
                        TCP_LOG_PKT(DEBUG, m, true);
                        rte_pktmbuf_free(m);
                        pm->stats_pktdropped++;
                        pm->stats_flowdropped++;
                        pm->stats_regnomatch++;
                        /* Halt processing of this pkt and continue to next pkt */
                        /* NOTE: this means that the flow is never inserted */
                        continue;
                    }
                }

                /* insert flow into flow table */
                protomatch_insert_flow( pm,
                                        &conn,
                                        (hdrs.tcp_datalen > 0 ? true : false),
                                        rte_be_to_cpu_32(hdrs.tcp_hdr->sent_seq),
                                        m->udata64 );

                out_pkts[out++] = m;

                PT_LOG(DEBUG, "Inserting SYN: ");
                TCP_LOG_PKT(DEBUG, m, false);
            }

            /* any other (non-SYN-only) flag combination */
            else {
                bool originator;

                /* Look up the flow in our flow table */
                protomatch_flow * flow = protomatch_lookup_flow(pm, &conn, &originator);

                /* Unknown flow => drop packet and continue on to the next one */
                if (flow == NULL) {
                    PT_LOG(DEBUG, "Unknown flow, dropping: ");
                    TCP_LOG_PKT(DEBUG, m, false);
                    rte_pktmbuf_free(m);
                    pm->stats_pktdropped++;
                    /* Process next packet */
                    continue;
                }

                // Known flow => check if we have just seen the first data
                // packet from the originator
                else if (is_first_data_packet(flow, &hdrs, originator)) {
                    flow->data = true;

                    /* Run our regexp over the data in the first data pkt */
                    if (match_packet(pm, &hdrs)) {
                        PT_LOG(DEBUG, "REGEXP MATCHED: ");
                        TCP_LOG_PKT(DEBUG, m, true);
                        out_pkts[out++] = m;
                        pm->stats_regmatch++;
                        // touch the flow
                        protomatch_touch_flow(pm, flow, m->udata64);
                    }

                    /* data packet failed to match regexp => drop flow */
                    else {
                        PT_LOG(DEBUG, "Failed to match: ");
                        TCP_LOG_PKT(DEBUG, m, true);
                        protomatch_remove_flow(pm, flow);
                        rte_pktmbuf_free(m);
                        pm->stats_pktdropped++;
                        pm->stats_regnomatch++;
                        /* Halt processing on this pkt, cont to next pkt */
                        continue;
                    }
                }

                /* otherwise, flow is known and either have not seen data yet */
                /* or we have and it matched, in which case, forward the */
                /* packet */
                else {
                    PT_LOG(DEBUG, "Matched a flow: ");
                    TCP_LOG_PKT(DEBUG, m, false);
                    out_pkts[out++] = m;
                    // touch the flow to keep it active, update timestamp
                    protomatch_touch_flow(pm, flow, m->udata64);
                }
            }
        } else {
            /* automatically forward all non-TCP/IPv4 packets */
            out_pkts[out++] = m;
            pm->stats_nontcpipv4++;
        }
    }

    return out;
}

void protomatch_get_stats(protomatch *pm, protomatch_stats *s) {
    s->size = pm->len;
    s->capacity = FLOW_TABLE_SIZE;
    s->flow_drop_cnt = pm->stats_flowdropped;
    s->pkt_discard_cnt = pm->stats_pktdropped;
    if (pm->tail != NULL)
        s->oldest_ts = pm->tail->timestamp;
    else
        s->oldest_ts = 0;
    if (pm->head != NULL)
        s->newest_ts = pm->head->timestamp;
    else
        s->newest_ts = 0;
    s->regexp_match_cnt = pm->stats_regmatch;
    s->regexp_nonmatch_cnt = pm->stats_regnomatch;
    s->syndata_cnt = pm->stats_syndata;
    s->nontcpipv4_cnt = pm->stats_nontcpipv4;
}
