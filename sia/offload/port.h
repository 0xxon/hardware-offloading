#pragma once

#include <iostream>

#include <rte_ethdev.h>

int port_init(uint16_t port, struct rte_mempool *mbuf_pool);
inline void port_stats_reset(uint16_t port);
inline void port_stats_print(uint16_t port);

inline void port_stats_reset(uint16_t port) {
    rte_eth_stats_reset(port);
}

inline void port_stats_print(uint16_t port) {
    static struct rte_eth_stats last_stats[64] = {{0}};
    struct rte_eth_stats stats;
    struct rte_eth_stats *last = &last_stats[port];
    rte_eth_stats_get(port, &stats);
    setlocale(LC_NUMERIC, "");
    printf(
        "IF %u: "
        "ipkts %lu (%'lu/sec) "
        "ibyts %lu (%'lu/sec) "
        "ierrs %lu (%'lu/sec) "
        "imiss %lu (%'lu/sec) "
        "nobuf %lu (%'lu/sec) "
        "opkts %lu (%'lu/sec) "
        "obyts %lu (%'lu/sec) "
        "oerrs %lu (%'lu/sec) "
        "\n",
        port, 
        stats.ipackets,  (stats.ipackets - last->ipackets), 
        stats.ibytes,    (stats.ibytes - last->ibytes), 
        stats.ierrors,   (stats.ierrors - last->ierrors), 
        stats.imissed,   (stats.imissed - last->imissed), 
        stats.rx_nombuf, (stats.rx_nombuf - last->rx_nombuf), 
        stats.opackets,  (stats.opackets - last->opackets), 
        stats.obytes,    (stats.obytes - last->obytes), 
        stats.oerrors,   (stats.oerrors - last->oerrors));
    *last = stats;
}
