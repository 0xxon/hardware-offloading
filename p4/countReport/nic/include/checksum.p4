#define tcp_check_fields \
		tcp.srcPort; \
		tcp.dstPort; \
		tcp.seq; \
		tcp.ack; \
		tcp.offset; \
		tcp.res; \
		tcp.nonce; \
		tcp.CWR; \
		tcp.ECE; \
		tcp.URG; \
		tcp.ACK; \
		tcp.PUSH; \
		tcp.RST; \
		tcp.SYN; \
		tcp.FIN; \
		tcp.window; \
		tcp.checksum; \
		tcp.urgPtr; \
		payload;

field_list ip4_tcp_checksum_list {
	ipv4.src;
	ipv4.dst;
	8'0;
	ipv4.proto;
	parse_meta.tcpLength; /* ipv4.len - 20 */
	tcp_check_fields
}

field_list ip6_tcp_checksum_list {
	ipv6.src;
	ipv6.dst;
	16'0;
	/* FIXME This does not remove the extension header length */
	parse_meta.tcpLength; /* ipv6.len - 20 */
	24'0;
	ipv6.nxt;
	tcp_check_fields
}

field_list_calculation ip4_tcp_checksum {
	input {
		ip4_tcp_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

field_list_calculation ip6_tcp_checksum {
	input {
		ip6_tcp_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

/* P4 is supposed to allow conditions on field values
 * but they are ignored by Netronome.
 * (and will event make it bug if the field is in the metadata)
 * Nevertheless, if the header is modified by the P4 code, it will recompute it.
 */
calculated_field tcp.checksum {
	update ip4_tcp_checksum if(valid(ipv4));
	update ip6_tcp_checksum if(valid(ipv6));
}

/* ECMP */
/* XXX IPv6 not supported */
field_list ecmp_hash_fields {
	flow_meta.addr1_v4;
	flow_meta.addr2_v4;
	flow_meta.port1;
	flow_meta.port2;
}

field_list_calculation ecmp_hash {
	input {
		ecmp_hash_fields;
	}
	algorithm : crc16; /* Hashes functions are defined in SDK_FOLDER/p4/components/flowenv/me/lib/std/hash.h */
	output_width : 16;
}

