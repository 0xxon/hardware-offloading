#include "statParse.p4"
#include "checksum.p4"

/* Header definitions */
header_type eth_hdr {
	fields {
		dst: 48;
		src: 48;
		etype: 16;
	}
}

#define IPV4_ETYPE 0x0800
#define IPV6_ETYPE 0x86DD
#define STAT_ETYPE 0x8900
#define CMD_ETYPE 0x8901

header_type ipv4_hdr {
	fields {
		ver: 4;
		ihl: 4;
		tos: 8;
		len: 16;
		id: 16;
		frag: 16;
		ttl: 8;
		proto: 8;
		csum: 16;
		src: 32;
		dst: 32;
	}
}

header_type ipv6_hdr {
	fields {
		ver: 4;
		tc: 8;
		flow: 20;
		len: 16;
		nxt: 8;
		hoplimit: 8;
		src: 128;
		dst: 128;
	}
}

#define TCP_IPTYPE 0x06
#define UDP_IPTYPE 0x11

/* TODO No tcp options handled here ! */
header_type tcp_hdr {
	fields {
		srcPort: 16;
		dstPort: 16;
		seq: 32;
		ack: 32;
		offset: 4;
		res: 3;
		nonce: 1;
		CWR: 1;
		ECE: 1;
		URG: 1;
		ACK: 1;
		PUSH: 1;
		RST: 1;
		SYN: 1;
		FIN: 1;
		window: 16;
		checksum: 16;
		urgPtr: 16;
	}
}

header_type udp_hdr {
	fields {
		srcPort: 16;
		dstPort: 16;
		len: 16;
		checksum: 16;
	}
}

header_type parse_metadata {
	fields {
		tcpLength: 16; // Checksum computation
	}
}

/* XXX IPv6 not supported */
header_type flow_info {
	fields {
		addr1_v4: 32;
		addr2_v4: 32;
		port1: 16;
		port2: 16;
		ecmp_hash_value: 16;
	}
}

/* Header instances */

header eth_hdr eth;
header ipv4_hdr ipv4;
header ipv6_hdr ipv6;
header tcp_hdr tcp;
header udp_hdr udp;

metadata parse_metadata parse_meta;
metadata flow_info flow_meta;

/* Parser */
parser start
{
	return eth_parse;
}

parser eth_parse
{
	extract(eth);
	return select(eth.etype) {
		IPV4_ETYPE : ipv4_parse;
		IPV6_ETYPE : ipv6_parse;
		STAT_ETYPE : stat_parse;
		CMD_ETYPE : ingress;
	}
}

parser ipv4_parse
{
	extract(ipv4);
	set_metadata(parse_meta.tcpLength, ipv4.len - 20);
	return select(ipv4.proto) {
		UDP_IPTYPE : udp_parse;
		TCP_IPTYPE : tcp_parse;
	}
}

parser ipv6_parse
{
	extract(ipv6);
	set_metadata(parse_meta.tcpLength, ipv6.len - 20);
	return select(ipv6.nxt) {
		UDP_IPTYPE : udp_parse;
		TCP_IPTYPE : tcp_parse;
	}
}

parser tcp_parse
{
	extract(tcp);
	return ingress;
}

parser udp_parse
{
	extract(udp);
	return ingress;
}

