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
#include <algorithm>

#include <ctype.h>
#include <inttypes.h>
#include <assert.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <string.h>

#include <rte_eal.h>
#include <rte_errno.h>
#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_mbuf.h>
#include <rte_mbuf_ptype.h>
#include <rte_hash.h>
#include <rte_timer.h>
#include <rte_thash.h>
#include <rte_malloc.h>

#include <config.h>
#include <debug.h>
#include <port.h>
#include <burst.h>
#include <tcp.h>
#include <offload.h>
#include <cspi_crc.h>
#include <rte_backports.h>

// pointer to our mbuf pool
static rte_mempool *mbuf_pool = NULL;

volatile bool quit_signal = false;

// Track stats per worker/RX thread
typedef struct lcore_stats {
    unsigned long long discarded_packets;
    struct offload_printstats offload_printstats;
} lcore_stats;

typedef struct lcore_ctx {
    uint8_t lcore_id = 0;
    union {
        // for offload/worker lcores:
        uint8_t worker_id = 0;
        // for RX/distributor lcores:
        uint8_t queue_id;
    };
    struct rte_mempool* mempool = NULL;
    struct rte_ring* ring = NULL;
    volatile struct config* cfg = {0};
    volatile struct lcore_stats stats = {0};
} lcore_ctx;

typedef struct config {
    uint8_t nb_workers = 0;
    struct rte_ring* distributor_ring = NULL;
    struct lcore_ctx workers[RTE_MAX_LCORE];
} config;

// Global app configuration
static volatile struct config cfg;

static void print_stats() {
    // Print NIC port stats
    uint16_t i;
    RTE_ETH_FOREACH_DEV(i) {
        port_stats_print(i);
    }

    // Compute global stats state from worker states
    struct lcore_stats globalstats = {0};

    for (i = 0; i < cfg.nb_workers; ++i) {
        volatile lcore_stats *s = &cfg.workers[i].stats;
        globalstats.discarded_packets += s->discarded_packets;
        // compute global offload stats:
        globalstats.offload_printstats.drop_cnt += s->offload_printstats.drop_cnt;
        if (globalstats.offload_printstats.oldest_ts == 0)
            globalstats.offload_printstats.oldest_ts = s->offload_printstats.oldest_ts;
        else
            globalstats.offload_printstats.oldest_ts =
                RTE_MIN(globalstats.offload_printstats.oldest_ts,
                        s->offload_printstats.oldest_ts);
        globalstats.offload_printstats.newest_ts =
            RTE_MAX(globalstats.offload_printstats.newest_ts,
                    s->offload_printstats.newest_ts);
        globalstats.offload_printstats.size += s->offload_printstats.size;
        globalstats.offload_printstats.capacity += s->offload_printstats.capacity;
    }

    // Print global stats
    setlocale(LC_NUMERIC, "");
    printf("DROPPED SYNs: %'llu\n", globalstats.offload_printstats.drop_cnt);
    printf("DISCARDED PACKETS: %'llu\n", globalstats.discarded_packets);
    printf("MBUF MEMPOOL = %i used / %i avail\n",
            rte_mempool_in_use_count(mbuf_pool),
            rte_mempool_avail_count(mbuf_pool));
    printf("OFFLOAD TABLE SIZE = %u / %u\n", globalstats.offload_printstats.size,
            globalstats.offload_printstats.capacity);
    if (globalstats.offload_printstats.oldest_ts > 0)
        printf("OLDEST OFFLOAD PACKET = %.4f seconds\n", 
                (rte_rdtsc() - globalstats.offload_printstats.oldest_ts) /
                (double)rte_get_tsc_hz());
}

static void sigusr_handler(int sig_num) {
    print_stats();
}

static void sigint_handler(int sig_num) {
    printf("Quitting on signal %d\n", sig_num);
    // TODO: flush TX buffer
    quit_signal = true;
}

static void lcore_worker(void *arg) {
    lcore_ctx *ctx = (lcore_ctx *)arg;

    offload *offld = offload_create(mbuf_pool);

    struct burst wk_burst;
    struct burst tx_burst = {{0}, 0};

    while (!quit_signal) {
        // Unload a burst from the worker's ring
        wk_burst.count = rte_ring_dequeue_burst(ctx->ring, 
                (void**)wk_burst.bufs, BURST_SIZE, NULL);

        if (wk_burst.count == 0)
            continue;

        // inspect some packet data
        for (size_t i = 0; i < wk_burst.count; ++i) {
            rte_mbuf *m = wk_burst.bufs[i];

            // Filter out just TCP/IPv4 packets
            if (RTE_ETH_IS_IPV4_HDR(m->packet_type) && 
               (m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {

                struct tcp_ip_hdrs hdrs;
                tcp_get_ipv4_headers(m, &hdrs);

                tcp_socket src_sock = {
                    // use these values in raw network endianness because
                    // it doesn't matter for our hashing purposes
                    .ip = hdrs.ipv4_hdr->src_addr,
                    .port = hdrs.tcp_hdr->src_port,
                };

                tcp_socket dst_sock = {
                    // use these values in raw network endianness because
                    // it doesn't matter for our hashing purposes
                    .ip = hdrs.ipv4_hdr->dst_addr,
                    .port = hdrs.tcp_hdr->dst_port,
                };

                /* printf("lcore %u: ", ctx->lcore_id); */
                /* tcp_print_tcpipv4_pkt_info(m, false); */

                /* rte_pktmbuf_free(m); */
                /* continue; */

                /* burst_add(&tx_burst, m); */
                /* continue; */

                // if we have found a SYN packet, add it to our SYN table
                // and do not yet retransmit it
                if ((hdrs.tcp_hdr->tcp_flags & TCP_SYN_FLAG) != 0 &&
                        (hdrs.tcp_hdr->tcp_flags & TCP_ACK_FLAG) == 0) {

                    /* Pre-offload sanity checks: */
                    // (1) Packet must fit into an offload buffer
                    if (rte_pktmbuf_data_len(m) > sizeof(struct offload_pkt_data_inner)) {
                        // packet is larger than a SYN should be (malformed)
                        // => forward it as-is
                        burst_add(&tx_burst, m);
                        DEBUG("\nFORWARDING MALFORMED SYN (too large)\n");
                    }
                    // (2) Packet must be contiguous (i.e. NOT segmented)
                    else if (!rte_pktmbuf_is_contiguous(m)) {
                        // can't deal with segmented packets => forward as-is
                        burst_add(&tx_burst, m);
                        DEBUG("\nFORWARDING SEGMENTED SYN (probably malformed)\n");
                    }
                    // Otherwise, the SYN packet is OK to offload
                    else {
                        DEBUG("\nINSERTING NEW SYN\n");
                        tcp_conn conn = {
                            .orig = src_sock,
                            .dest = dst_sock
                        };
                        offload_insert(offld, &conn, m);
#ifdef DEBUG_ENABLE
                        tcp_print_tcpipv4_pkt_info(m, false);
                        printf("mbuf_data_len=%u\n", rte_pktmbuf_data_len(m));
                        printf("checksum_be=0x%04x\n", hdrs.tcp_hdr->cksum);
                        printf("checksum_le=0x%04x\n", rte_be_to_cpu_16(hdrs.tcp_hdr->cksum));
#endif
                        // once inserted into our offload table, we can free
                        // the original mbuf to be used again, since
                        // offload_insert clones the header data from the mbuf
                        rte_pktmbuf_free(m);
                    }
                }

                // if we have found an ACK (or SYN/ACK) packet:
                else if ((hdrs.tcp_hdr->tcp_flags & TCP_ACK_FLAG) != 0) {
                    /*
                     * For offloading, whenever we see an ACK packet from
                     * either side, we can look up orig=dst,dest=src in the
                     * offload table to see if there was a SYN for this
                     * connection.
                     */
                    tcp_conn conn = {
                        .orig = dst_sock,
                        .dest = src_sock
                    };

                    // (1) Check for corresponding SYN in our table
                    offload_pkt * syn_offload = offload_lookup(offld, &conn);

                    DEBUG("\nRECEIVED AN ACK...LOOKING FOR SYN\n");

                    if (syn_offload != NULL) {
                        // (2) If we found one, send it and clear it
                        DEBUG("FOUND SYN for ACK... SENDING SYN:\n");

                        // allocate a new mbuf for TX'ing the SYN
                        rte_mbuf *syn_mbuf = offload_make_mbuf(offld, syn_offload);

#ifdef DEBUG_ENABLE
                        tcp_print_tcpipv4_pkt_info(syn_mbuf, false);
#endif
                        // enqueue the SYN for transmitting
                        burst_add(&tx_burst, syn_mbuf);

                        // free and remove it from our offload table
                        offload_remove(offld, syn_offload, true);
                    } else {
                        DEBUG("NO SYN FOUND\n");
                    }

                    DEBUG(".....................SENDING ACK\n");
#ifdef DEBUG_ENABLE
                    tcp_print_tcpipv4_pkt_info(m, false);
#endif
                    burst_add(&tx_burst, m);
                } else {
                    burst_add(&tx_burst, m);
                }
            } else {
                // transparently forward all other packets onward
                burst_add(&tx_burst, m);
            }
        }

        /* Transmit the TX burst */
        burst_send(&tx_burst, INPUT_PORT^1);

        /* Update lcore offload stats */
        offload_get_stats(offld, (offload_printstats*)&ctx->stats.offload_printstats);
    }
}

/* Put the given packet into the given burst for the given SW ring */
/* Fills each burst to BURST_SIZE and then pushes it to the ring */
static inline void distribute(burst *b, rte_mbuf *m, rte_ring *r) {
    burst_add(b, m);
    if (b->count == BURST_SIZE) {
        const uint16_t nb_failed = burst_enqueue(b, r);
        if (nb_failed > 0)
            printf("Distributor missed %u packets\n", nb_failed);
    }
}

static void lcore_rx_distributor(void *arg) {
    struct lcore_ctx *ctx = (struct lcore_ctx *)arg;
    uint8_t num_workers = ctx->cfg->nb_workers;

    /*
     * Check that the port is on the same NUMA node as the polling thread
     * for best performance.
     */
    if (rte_eth_dev_socket_id(INPUT_PORT) > 0 &&
            rte_eth_dev_socket_id(INPUT_PORT) !=
                    (int)rte_socket_id())
        printf("WARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.\n", INPUT_PORT);

    printf("\nCore %u forwarding packets. [Ctrl+C to quit]\n",
            rte_lcore_id());

    // packet burst buffers
    struct burst rx_burst;
    struct burst ring_bursts[num_workers];
    // initialize the bursts with all 0 values for now
    memset(&ring_bursts, 0, sizeof(ring_bursts));

    /* Run until the application is quit or killed. */
    while (!quit_signal) {
        /*
         * Receive packets on INPUT_PORT and place them onto the appropriate
         * SRRS ring.
         */
        rx_burst.count = rte_eth_rx_burst(INPUT_PORT, ctx->queue_id,
                rx_burst.bufs, BURST_SIZE);

        // NOTE: unlikely() is a function that tells the
        // compiler this branch is unlikely to be taken
        if (unlikely(rx_burst.count == 0))
            continue;

        // distribute packets across software rings based on RSS software and
        // hardware hashing
        for (size_t i = 0; i < rx_burst.count; ++i) {
            rte_mbuf *m = rx_burst.bufs[i];

            // distribute each packet onto a worker queue based on raw RSS hash value
            uint32_t rss_queue = (uint32_t)(
                    ((uint64_t)m->hash.rss * (uint64_t)num_workers) >> 32);

            distribute(&ring_bursts[rss_queue], m, ctx->cfg->workers[rss_queue].ring);
        }
    }
}

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int main(int argc, char *argv[]) {
    signal(SIGINT, sigint_handler);
    signal(SIGUSR1, sigusr_handler);

    // number of ports
    unsigned nb_ports;

    /* Initialize the Environment Abstraction Layer (EAL). */
    // NOTE: return value of rte_eal_init is number of consumed args
    int ret = rte_eal_init(argc, argv);
    if (ret < 0)
        rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");

    // subtract consumed args from our arg count, and advance argv array
    // pointer accordingly
    argc -= ret;
    argv += ret;

    /* Check that there is an even number of ports to send/receive on. */
    nb_ports = rte_eth_dev_count();
    if (nb_ports != 2)
        rte_exit(EXIT_FAILURE, "Error: number of ports must be 2\n");

    /* Check that a valid input port is configured */
    if (INPUT_PORT < 0 || INPUT_PORT >= nb_ports)
        rte_exit(EXIT_FAILURE, "Error: input port out of range\n");


    /* Creates a new mempool in memory to hold the mbufs. */
    // returns pointer to newly allocated mempool, or NULL on error
    mbuf_pool = rte_pktmbuf_pool_create(
        "MBUF_POOL",            // name our mbuf pool "MBUF_POOL"
        NUM_MBUFS,              // capacity of mbuf pool (num elements)
        MBUF_CACHE_SIZE,        // size of per-core object cache 

        0,                      // size of private data area between 
                                //   rte_mbuf struct and data buffer

        /* RTE_ALIGN(sizeof(bool), RTE_MBUF_PRIV_ALIGN), // size of private data area between */ 
        /*                         //   rte_mbuf struct and data buffer */

        MBUF_SIZE,              // size of data buffer in each mbuf,
                                //   including RTE_PKTMBUF_HEADROOM
        rte_socket_id()         // CPU socket identifier for mem alloc
    );

    if (mbuf_pool == NULL)
        // immediately terminate the application with given exit code
        // and error message to be printed to the shell
        rte_exit(EXIT_FAILURE, "Cannot create mbuf pool (%s)\n",
                rte_strerror(rte_errno));

    /* Initialize all ports. */
    for (uint16_t portid = 0; portid < nb_ports; portid++)
        if (port_init(portid, mbuf_pool) != 0)
            rte_exit(EXIT_FAILURE, "Cannot init port %" PRIu16 " (%s)\n",
                    portid, rte_strerror(rte_errno));

    uint8_t lcore_id = 0, worker_id = 0, recv_q_id = 0;
    char ring_name[64];

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        // Launch the rx/distributor lcore
        if (lcore_id >= rte_lcore_count()-NB_RX_CORES) {
            printf("lcore %u: starting lcore_rx_distributor q=%u\n",
                    lcore_id, recv_q_id);
            
            snprintf(ring_name, sizeof(ring_name), "distributor_ring_%u", recv_q_id);

            rte_ring *ring = rte_ring_create(ring_name, 
                    rte_align32pow2(BURST_SIZE)*2,
                    rte_socket_id(), 
                    RING_F_SC_DEQ | RING_F_SP_ENQ);
                    /* RING_F_SC_DEQ); //| RING_F_SP_ENQ); */

            if (ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create distributor ring for q=%u "
                         "on lcore %u (%s)\n", recv_q_id, lcore_id,
                         rte_strerror(rte_errno));

            cfg.distributor_ring = ring;

            lcore_ctx *ctx = (lcore_ctx *)rte_malloc(NULL, 
                    sizeof(struct lcore_ctx), 0);
            ctx->lcore_id = lcore_id;
            // for the rx cores, use queue_id instead of worker_id
            ctx->queue_id = recv_q_id;
            ctx->mempool = mbuf_pool;
            ctx->ring = NULL;
            ctx->cfg = &cfg;

            rte_eal_remote_launch((lcore_function_t *)lcore_rx_distributor,
                    ctx, lcore_id);

            recv_q_id++;
        }
        // Launch all the other worker lcores
        else if (cfg.nb_workers < MAX_NB_WORKERS){
    
            printf("lcore %u: starting lcore_worker %u\n", lcore_id, worker_id);

            snprintf(ring_name, sizeof(ring_name), "worker_ring_%u", worker_id);

            rte_ring *ring = rte_ring_create(ring_name, 
                    rte_align32pow2(NUM_MBUFS)*2,
                    rte_socket_id(), 
                    RING_F_SC_DEQ); //| RING_F_SP_ENQ);

            if (ring == NULL)
                rte_exit(EXIT_FAILURE, "Cannot create ring for worker "
                         "%u on lcore %u (%s)\n", worker_id, lcore_id,
                         rte_strerror(rte_errno));

            lcore_ctx *ctx = (lcore_ctx *)&cfg.workers[worker_id];
            ctx->lcore_id = lcore_id;
            ctx->worker_id = worker_id;
            ctx->mempool = mbuf_pool;
            ctx->ring = ring;
            ctx->cfg = &cfg;

            rte_eal_remote_launch((lcore_function_t *)lcore_worker,
                    ctx, lcore_id);

            worker_id++;
            cfg.nb_workers++;
        }
    }

    while (!quit_signal) {
        sleep(1);
        print_stats();
    }

    RTE_LCORE_FOREACH_SLAVE(lcore_id) {
        if (rte_eal_wait_lcore(lcore_id) < 0)
            return -1;
    }
    
    rte_exit(EXIT_SUCCESS, "Received Ctrl-C... exiting\n");

    return 0;
}
