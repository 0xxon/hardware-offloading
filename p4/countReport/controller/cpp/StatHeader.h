#ifndef STATHEADER_H
#define STATHEADER_H

#include <stdint.h>

#define ETH_P_STAT 0x8900

#define P_SRC_V6 "src_v6"
#define P_SRC_V4 "src_v4"
#define P_SRC_PREFIX_LEN "srcPrefixLen"
#define P_DST_V6 "dst_v6"
#define P_DST_V4 "dst_v4"
#define P_DST_PREFIX_LEN "dstPrefixLen"
#define P_SRC_PORT "srcPort"
#define P_DST_PORT "dstPort"
#define P_TCP "tcp_proto"
#define P_UDP "udp_proto"

#define M_SRC_V6 "ipv6.src"
#define M_SRC_V4 "ipv4.src"
/* FIXME Masks are exception in P4 */
#define M6_SRC_PREFIX_LEN "ipv6.srcPrefixLen"
#define M4_SRC_PREFIX_LEN "ipv4.srcPrefixLen"
#define M_DST_V6 "ipv6.dst"
#define M_DST_V4 "ipv4.dst"
#define M6_DST_PREFIX_LEN "ipv6.dstPrefixLen"
#define M4_DST_PREFIX_LEN "ipv4.dstPrefixLen"
#define MT_SRC_PORT "tcp.srcPort"
#define MU_SRC_PORT "udp.srcPort"
#define MT_DST_PORT "tcp.dstPort"
#define MU_DST_PORT "udp.dstPort"
#define M_TCP "tcp"
#define M_UDP "udp"

#define NONE_STNXT		0x0000
#define SHORTCUT_STNXT	0x0001
#define FLV6_SPEC_STNXT 0x0002
#define FLV4_SPEC_STNXT 0x0003
#define FL_PKTCNT_STNXT 0x0004

struct stat_tlv {
	uint16_t nexthdr;
	uint16_t len;
} __attribute__((packed));

struct stat_shortcut {
	struct stat_tlv tlv;
	uint16_t len_short;
	uint16_t nexthdr_short;
} __attribute__((packed));

struct stat_flow_ipv4 {
	struct stat_tlv tlv;
	uint32_t src;
	uint32_t dst;
	uint8_t src_prefixlen;
	uint8_t dst_prefixlen;
	uint8_t res_1:6,
		udp:1,
		tcp:1;
	uint8_t	res_2;
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((packed));

struct stat_flow_ipv6 {
	struct stat_tlv tlv;
	uint32_t src [4];
	uint32_t dst [4];
	uint8_t src_prefixlen;
	uint8_t dst_prefixlen;
	uint8_t res_1:6,
		udp:1,
		tcp:1;
	uint8_t	res_2;
	uint16_t src_port;
	uint16_t dst_port;
} __attribute__((packed));

struct stat_fl_pktcnt {
	struct stat_tlv tlv;
	uint64_t fl_pktcnt;
} __attribute__((packed));

#endif

