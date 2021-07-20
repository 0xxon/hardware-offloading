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
#include <protomatch.h>
#include <cspi_crc.h>
#include <rte_backports.h>

// RTE logtype for rte_log functions
// see prototype_init_log()
int pt_logtype;
int pt_stats_logtype;

// pointer to our mbuf pool
static rte_mempool *mbuf_pool = NULL;

static volatile bool quit_signal = false;

// Track stats per worker/RX thread
typedef struct lcore_stats {
    unsigned long long discarded_packets;
    struct protomatch_stats protomatch_stats;
} lcore_stats;

typedef struct lcore_ctx {
    uint8_t lcore_id = 0;
    union {
        // for worker lcores:
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

        // compute global protocol matching stats
        globalstats.protomatch_stats.flow_drop_cnt +=
            s->protomatch_stats.flow_drop_cnt;
        globalstats.protomatch_stats.pkt_discard_cnt +=
            s->protomatch_stats.pkt_discard_cnt;
        if (globalstats.protomatch_stats.oldest_ts == 0)
            globalstats.protomatch_stats.oldest_ts =
                s->protomatch_stats.oldest_ts;
        else
            globalstats.protomatch_stats.oldest_ts =
                RTE_MIN(globalstats.protomatch_stats.oldest_ts,
                        s->protomatch_stats.oldest_ts);
        globalstats.protomatch_stats.size +=
            s->protomatch_stats.size;
        globalstats.protomatch_stats.capacity +=
            s->protomatch_stats.capacity;
        globalstats.protomatch_stats.nontcpipv4_cnt +=
            s->protomatch_stats.nontcpipv4_cnt;
        globalstats.protomatch_stats.regexp_match_cnt +=
            s->protomatch_stats.regexp_match_cnt;
        globalstats.protomatch_stats.regexp_nonmatch_cnt +=
            s->protomatch_stats.regexp_nonmatch_cnt;
        globalstats.protomatch_stats.syndata_cnt +=
            s->protomatch_stats.syndata_cnt;
    }

    /* NOTE: this locale hack gives nice comma thousands separators */
    setlocale(LC_NUMERIC, "");

    /* Print global stats */
    PT_STATS_LOG(INFO, "---");
    PT_STATS_LOG(INFO, "MBUF MEMPOOL = %i used / %i avail",
            rte_mempool_in_use_count(mbuf_pool),
            rte_mempool_avail_count(mbuf_pool));
    PT_STATS_LOG(INFO, "DISCARDED PACKETS: %'llu",
            globalstats.discarded_packets);

    /* Print protocol matching stats */
    PT_STATS_LOG(INFO, "---");
    PT_STATS_LOG(INFO, "[PROTO] DROPPED FLOWS: %'llu",
            globalstats.protomatch_stats.flow_drop_cnt);
    PT_STATS_LOG(INFO, "[PROTO] REGEXP MATCHES: %'llu",
            globalstats.protomatch_stats.regexp_match_cnt);
    PT_STATS_LOG(INFO, "[PROTO] REGEXP NON-MATCHES: %'llu",
            globalstats.protomatch_stats.regexp_nonmatch_cnt);
    PT_STATS_LOG(INFO, "[PROTO] SYNs WITH DATA: %'llu",
            globalstats.protomatch_stats.syndata_cnt);
    PT_STATS_LOG(INFO, "[PROTO] NON-TCP-IP PKTS: %'llu",
            globalstats.protomatch_stats.nontcpipv4_cnt);
    PT_STATS_LOG(INFO, "[PROTO] TABLE SIZE = %u / %u",
            globalstats.protomatch_stats.size,
            globalstats.protomatch_stats.capacity);
    if (globalstats.protomatch_stats.oldest_ts > 0)
        PT_STATS_LOG(INFO, "[PROTO] OLDEST FLOW = %.4f seconds",
                (rte_rdtsc() - globalstats.protomatch_stats.oldest_ts) /
                (double)rte_get_tsc_hz());
}

static void sigusr_handler(int sig_num) {
    print_stats();
}

static void sigint_handler(int sig_num) {
    PT_LOG(WARNING, "Quitting on signal %d", sig_num);
    // TODO: flush TX buffer
    quit_signal = true;
}

static void lcore_worker(void *arg) {
    lcore_ctx *ctx = (lcore_ctx *)arg;

    protomatch *pmatch = protomatch_init("pm");

    struct burst wk_burst;
    struct burst tx_burst = {{0}, 0};

    while (!quit_signal) {
        /* Unload a burst from the worker's ring */
        wk_burst.count = rte_ring_dequeue_burst(ctx->ring, 
                (void**)wk_burst.bufs, BURST_SIZE, NULL);

        if (wk_burst.count == 0)
            continue;

        /* Run flow/proto classification */
        tx_burst.count = protomatch_burst(pmatch, wk_burst.bufs,
                wk_burst.count, tx_burst.bufs);

        /* Transmit the TX burst */
        burst_send(&tx_burst, INPUT_PORT^1);

        /* Update lcore worker stats after each burst */
        protomatch_get_stats(pmatch, (protomatch_stats*)&ctx->stats.protomatch_stats);
        ctx->stats.discarded_packets = ctx->stats.protomatch_stats.pkt_discard_cnt;
    }
}

/* Put the given packet into the given burst for the given SW ring */
/* Fills each burst to BURST_SIZE and then pushes it to the ring */
static inline void distribute(burst *b, rte_mbuf *m, rte_ring *r) {
    burst_add(b, m);
    if (b->count == BURST_SIZE) {
        const uint16_t nb_failed = burst_enqueue(b, r);
        if (unlikely(nb_failed > 0))
            PT_LOG(WARNING, "Distributor missed %u packets", nb_failed);
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
        PT_LOG(WARNING, "WARNING, port %u is on remote NUMA node to "
                "polling thread.\n\tPerformance will "
                "not be optimal.", INPUT_PORT);

    PT_LOG(NOTICE, "\nCore %u forwarding packets. [Ctrl+C to quit]\n",
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
            PT_LOG(INFO, "lcore %u: starting lcore_rx_distributor q=%u",
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
    
            PT_LOG(INFO, "lcore %u: starting lcore_worker %u", lcore_id, worker_id);

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

RTE_INIT(prototype_init_log);

static void prototype_init_log(void) {
    // prototype logtype
	pt_logtype = rte_log_register(PT_LOGTYPE_STR);
	if (pt_logtype >= 0)
		rte_log_set_level(pt_logtype, RTE_LOG_DEBUG);

    // prototype.stats logtype
    pt_stats_logtype = rte_log_register(PT_STATS_LOGTYPE_STR);
    if (pt_stats_logtype >= 0)
        rte_log_set_level(pt_stats_logtype, RTE_LOG_DEBUG);
}
