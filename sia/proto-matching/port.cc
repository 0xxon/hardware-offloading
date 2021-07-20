#include <rte_ethdev.h>
#include <rte_cycles.h>
#include <rte_thash.h>

#include <config.h>
#include <tcp.h>
#include <port.h>
#include <cspi_crc.h>
#include <debug.h>

/*
 * Callback that adds timestamps and RSS hashes to packets as they're received.
 */
static uint16_t preprocess_burst(uint16_t port __rte_unused, 
                               uint16_t qidx __rte_unused, 
                               struct rte_mbuf **pkts, 
                               uint16_t nb_pkts, 
                               uint16_t max_pkts __rte_unused, 
                               void *_ __rte_unused) {
    struct tcp_ip_hdrs hdrs;
	for (uint16_t i = 0; i < nb_pkts; i++)  {
        rte_mbuf *m = pkts[i];
		m->udata64 = rte_rdtsc();

        const uint32_t hw_rss = m->hash.rss;

        // Compute software RSS hash for TCP/IPv4 packets
        // TODO: move this software hashing implementation into another file
        // once it becomes more complex  and needs to handle e.g. UDP, IPv6.
        if (RTE_ETH_IS_IPV4_HDR(m->packet_type) && 
            (m->packet_type & RTE_PTYPE_L4_MASK) == RTE_PTYPE_L4_TCP) {

            // Get TCP/IPv4 packet headers
            tcp_get_ipv4_headers(m, &hdrs);

            // Compute SW RSS hash
            m->hash.rss = cspi_crc_hash_packet(hdrs.ipv4_hdr->src_addr,
                    hdrs.ipv4_hdr->dst_addr, hdrs.tcp_hdr->src_port,
                    hdrs.tcp_hdr->dst_port);

            PT_LOG(DEBUG, "HW_RSS = %u | SW_RSS %u: ", hw_rss, m->hash.rss);
            TCP_LOG_PKT(DEBUG, m, false);
        }
    }
	return nb_pkts;
}

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */
int port_init(uint16_t port, struct rte_mempool *mbuf_pool) {
    struct rte_eth_conf port_conf = {0};

    // Enable jumbo frames
    port_conf.rxmode.max_rx_pkt_len = ETHER_MAX_JUMBO_FRAME_LEN;
    port_conf.rxmode.jumbo_frame = 1;

    // Set other hardware flags
    port_conf.rxmode.header_split = 0;
    port_conf.rxmode.hw_ip_checksum = 0;
    port_conf.rxmode.hw_vlan_filter = 0;
    port_conf.rxmode.hw_vlan_strip = 0;
    port_conf.rxmode.hw_vlan_extend = 0;
    port_conf.rxmode.hw_strip_crc = 0;
    port_conf.txmode.mq_mode = ETH_MQ_TX_NONE;

    // Disable checksum offloads
    port_conf.txmode.offloads &= ~DEV_TX_OFFLOAD_TCP_CKSUM;
    port_conf.txmode.offloads &= ~DEV_TX_OFFLOAD_IPV4_CKSUM;
    /* port_conf.txmode.offloads |= DEV_TX_OFFLOAD_TCP_CKSUM; */
    /* port_conf.txmode.offloads |= DEV_TX_OFFLOAD_IPV4_CKSUM; */

    // Enable generation of hardware RSS hashes
    // NOTE: we use only one rx ring, so all hash values go to the same RX
    // lcore, and we then distribute non-TCP packets to SW rings based on
    // those hardware-computed RSS hashes, since we don't currently care where
    // non-TCP streams end up
    port_conf.rxmode.mq_mode = ETH_MQ_RX_RSS;
    port_conf.rx_adv_conf.rss_conf.rss_key = NULL;
    port_conf.rx_adv_conf.rss_conf.rss_hf = ETH_RSS_IP | ETH_RSS_UDP |
        ETH_RSS_TCP | ETH_RSS_SCTP;

    const uint16_t rx_rings = NB_RX_CORES, tx_rings = rte_lcore_count();
    uint16_t nb_rxd = RX_RING_SIZE;
    uint16_t nb_txd = TX_RING_SIZE;
    int retval;
    uint16_t q;
    struct rte_eth_dev_info dev_info;

    // check that we don't try to init a non-existent port
    if (port >= rte_eth_dev_count())
        return -1;

    rte_eth_dev_info_get(port, &dev_info);

    // Limit max packet length to maximum supported by the port
    port_conf.rxmode.max_rx_pkt_len = dev_info.max_rx_pktlen;

    // Print maximum supported packet length for user's reference
    PT_LOG(NOTICE, "Port %u max_rx_pktlen=%u", port,
            port_conf.rxmode.max_rx_pkt_len);

    /* Configure the Ethernet device. */
    // use 1 RX hardware ring, and 1 TX hardware ring
    // initialize Ethernet port with default port config
    retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
    if (retval != 0)
        return retval;

    // Check that number of RX and TX ring descriptors we've specified
    // doesn't exceed the hardware limitations, and if they do, adjust the
    // numbers to be within the hardware's limits
    retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
    if (retval != 0)
        return retval;
    
    /* Allocate and set up TX queues for the Ethernet port. */
    for (q = 0; q < tx_rings; q++) {
        retval = rte_eth_tx_queue_setup(
            port,                // port ID
            q,                 // index of TX queue to set up
            nb_txd,                // number of TX descriptors to allocate for TX ring
            rte_eth_dev_socket_id(port),     // CPU socket ID (for NUMA)
            &(dev_info.default_txconf)
        );
        if (retval < 0)
            return retval;
    }

    /* Allocate and set up RX queues for the Ethernet port. */
    for (q = 0; q < rx_rings; q++) {
        retval = rte_eth_rx_queue_setup(
            port,                // port ID
            q,                 // index of RX queue to set up
            nb_rxd,                // number of RX descriptors to allocate for receive ring
            rte_eth_dev_socket_id(port),     // CPU socket ID (for NUMA)
            &(dev_info.default_rxconf),
            mbuf_pool            // memory pool in which to allocate rte_mbuf buffers for the RX ring
        );
        if (retval < 0)
            return retval;
    }

    /* Zero the port stats */
    port_stats_reset(port);

    /* Start the Ethernet port. */
    retval = rte_eth_dev_start(port);
    if (retval < 0)
        return retval;

    /* Display the port MAC address. */
    struct ether_addr addr;
    rte_eth_macaddr_get(port, &addr);
    PT_LOG(NOTICE, "Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
               " %02" PRIx8 " %02" PRIx8 " %02" PRIx8,
            port,
            addr.addr_bytes[0], addr.addr_bytes[1],
            addr.addr_bytes[2], addr.addr_bytes[3],
            addr.addr_bytes[4], addr.addr_bytes[5]);

    // Automatically add timestamps and SW RSS hashes to received mbufs
    rte_eth_add_rx_callback(port, 0, preprocess_burst, NULL);

    /* Enable RX in promiscuous mode for the Ethernet device. */
    rte_eth_promiscuous_enable(port);

    return 0;
}
