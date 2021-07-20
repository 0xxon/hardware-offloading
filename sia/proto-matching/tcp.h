#pragma once

#include <stdio.h>

#include <arpa/inet.h>

#include <rte_ether.h>
#include <rte_ip.h>
#include <rte_tcp.h>

#include <debug.h>

// TCP header flags
#define TCP_CWR_FLAG 0x80 
#define TCP_ECE_FLAG 0x40 
#define TCP_URG_FLAG 0x20 
#define TCP_ACK_FLAG 0x10 
#define TCP_PSH_FLAG 0x08 
#define TCP_RST_FLAG 0x04 
#define TCP_SYN_FLAG 0x02 
#define TCP_FIN_FLAG 0x01 

#define TCP_LOG_PKT(level, mbuf, data) \
        tcp_log_tcpipv4_pkt_info(RTE_LOG_ ## level, __func__, mbuf, data);

/*
 * Struct representing a TCP socket.
 */
typedef struct tcp_socket tcp_socket;
struct tcp_socket {
    uint32_t ip;   // IPv4 address
    uint32_t port; // TCP port
}; // note struct size must be multiple of 4 octs for rte_hash-ing

typedef struct tcp_conn tcp_conn;
struct tcp_conn {
    // originator socket
    struct tcp_socket orig;
    // destination socket
    struct tcp_socket dest;
};

/*
 * Structure for storing pointers to headers and TCP data section for a
 * TCP/IPv4 packet.
 */
typedef struct tcp_ip_hdrs tcp_ip_hdrs;
struct tcp_ip_hdrs {
    struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ipv4_hdr;
    struct tcp_hdr *tcp_hdr;
    char *tcp_data;
    uint16_t tcp_datalen;
};

/*
 * Given an mbuf containing a TCP/IPv4 packet, fills in the given tcp_ip_hdrs
 * struct with pointers to the L2, L3, and L4 headers, and L4 data section.
 */
inline void tcp_get_ipv4_headers(struct rte_mbuf *m, 
                                        struct tcp_ip_hdrs *hdrs) {
    // extract Ethernet header
    hdrs->eth_hdr = rte_pktmbuf_mtod(m, struct ether_hdr *);

    // extract IPv4 header
    hdrs->ipv4_hdr = rte_pktmbuf_mtod_offset(m, struct ipv4_hdr *, 
            sizeof(struct ether_hdr));

    // extract TCP header
    hdrs->tcp_hdr = rte_pktmbuf_mtod_offset(m, struct tcp_hdr *, 
            sizeof(struct ether_hdr) + 
            sizeof(struct ipv4_hdr));

    // extract TCP data section as char array
    hdrs->tcp_data = rte_pktmbuf_mtod_offset(m, char *, 
            sizeof(struct ether_hdr) +
            sizeof(struct ipv4_hdr) + 
            ((hdrs->tcp_hdr->data_off & 0xf0) >> 2));

    // compute length of TCP packet data section, in bytes
    hdrs->tcp_datalen = 
        // total size of IPv4 packet
        rte_be_to_cpu_16(hdrs->ipv4_hdr->total_length)
        // minus length of IPv4 header
        - sizeof(struct ipv4_hdr)
        // minus length of TCP header (TCP offset)
        // NOTE: this is an endianness conversion and *4 to convert to bytes
        - ((hdrs->tcp_hdr->data_off & 0xf0) >> 2);
}

/*
 * Converts a raw IPv4 address value from the IP packet header into a
 * human-readable string in the standard NNN.NNN.NNN.NNN form.
 * The strbuf must be an allocated array of type char[INET_ADDRSTRLEN].
 */
inline void tcp_ipv4_pkt_addr_to_str(uint32_t addr, char *strbuf) {
    // sockaddr struct needed for ARPA func inet_ntop
    struct sockaddr_in sa = {0};
    
    // convert IP from network bit order to CPU bit order
    uint32_t ip = rte_be_to_cpu_32(addr);
    
    // initialize sockaddr struct fields
    sa.sin_family = AF_INET;
    /* sa.sin_addr = {0}; */
    memset(&sa.sin_addr, 0, sizeof(sa.sin_addr));

    // convert addr to string
    sa.sin_addr.s_addr = htonl(ip);
    inet_ntop(AF_INET, &(sa.sin_addr), strbuf, INET_ADDRSTRLEN);
}

/*
 * Prints information about a TCP/IPv4 packet stored in the given mbuf.
 */
inline void tcp_log_tcpipv4_pkt_info(int loglevel, char const * caller, struct rte_mbuf *m, bool data) {
    // Do nothing if log level isn't set high enough
    if (!(loglevel <= rte_log_get_level(pt_logtype)))
        return;

    // stores header info for the TCP/IPv4 packet
    struct tcp_ip_hdrs hdrs;

    // strings to store src addr and dst addr in human form
    char ip_src_str[INET_ADDRSTRLEN];
    char ip_dst_str[INET_ADDRSTRLEN];
    
    // load header information
    tcp_get_ipv4_headers(m, &hdrs);

    // convert IPv4 addresses to their human-friendly strings
    tcp_ipv4_pkt_addr_to_str(hdrs.ipv4_hdr->src_addr, ip_src_str);
    tcp_ipv4_pkt_addr_to_str(hdrs.ipv4_hdr->dst_addr, ip_dst_str);

    // print stuff about the packet
    PT_LOG_INTLVL(loglevel, caller, "Packet %s: %s:%u -> %s:%u",
           /* "Data: \n", */ 
        rte_get_ptype_l4_name(m->packet_type),
        ip_src_str,
        rte_be_to_cpu_16(hdrs.tcp_hdr->src_port),
        ip_dst_str,
        rte_be_to_cpu_16(hdrs.tcp_hdr->dst_port)
    );

    // Print any printable TCP data to stdout followed by a newline
    if (data) {
        printf("TCP_DATALEN=%u\n", hdrs.tcp_datalen);
        for (uint16_t i = 0; i < hdrs.tcp_datalen; ++i) {
            if (isalnum(hdrs.tcp_data[i]) || ispunct(hdrs.tcp_data[i])) {
                putchar(hdrs.tcp_data[i]);
            } else {
                printf("\\x%02X", hdrs.tcp_data[i]);
            }
        }
        printf("\n");
    }
}

/*
 * Returns true if two tcp_sockets are identical.
 */
inline bool tcp_socket_eq(tcp_socket *s1, tcp_socket *s2) {
    return (s1->ip == s2->ip && s1->port == s2->port);
}

/*
 * Returns true if two tcp_conns are identical.
 */
inline bool tcp_conn_eq(tcp_conn *c1, tcp_conn *c2) {
    return tcp_socket_eq(&c1->orig, &c2->orig) &&
           tcp_socket_eq(&c1->dest, &c2->dest);
}
