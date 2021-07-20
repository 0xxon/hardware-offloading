
/* Header definitions */
header_type eth_hdr {
	fields {
		dst: 48;
		src: 48;
		etype: 16;
	}
}

#define IPV4_ETYPE 0x0800

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

#define TCP_IPTYPE 0x06
#define UDP_IPTYPE 0x11

header_type tcp_hdr {
	fields {
		sport: 16;
		dport: 16;
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
		sport: 16;
		dport: 16;
		len: 16;
		checksum: 16;
	}
}

header_type parse_metadata {
	fields {
		tcpLength: 16; // Checksum computation
	}
}

/* Header instances */

header eth_hdr eth;
header ipv4_hdr ipv4;
header tcp_hdr tcp;
header udp_hdr udp;

metadata parse_metadata parse_meta;

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
	}
}

parser ipv4_parse
{
	extract(ipv4);
	return select(ipv4.proto) {
		UDP_IPTYPE : udp_parse;
		TCP_IPTYPE : tcp_parse;
	}
}

parser tcp_parse
{
	extract(tcp);
	set_metadata(parse_meta.tcpLength, ipv4.len - 20);
	return ingress;
}

parser udp_parse
{
	extract(udp);
	return ingress;
}

/* Checksum */

field_list ip4_tcp_checksum_list {
	ipv4.src;
	ipv4.dst;
	8'0;
	ipv4.proto;
	parse_meta.tcpLength; /* ipv4.len - 20 */
	tcp.sport;
	tcp.dport;
	tcp.seq;
	tcp.ack;
	tcp.offset;
	tcp.res;
	tcp.nonce;
	tcp.CWR;
	tcp.ECE;
	tcp.URG;
	tcp.ACK;
	tcp.PUSH;
	tcp.RST;
	tcp.SYN;
	tcp.FIN;
	tcp.window;
	tcp.checksum; // TODO Remove as in the example ?
	tcp.urgPtr;
	payload;
}

field_list_calculation ip4_tcp_checksum {
	input {
		ip4_tcp_checksum_list;
	}
	algorithm : csum16;
	output_width : 16;
}

calculated_field tcp.checksum {
	update ip4_tcp_checksum if(tcp.SYN == 0);
}

/* Actions */

action fwd_act(port, idx)
{
	modify_field(standard_metadata.egress_spec, port);
	modify_field(tcp.res, 1);

	count(fl_count, idx);
}

action drop_act()
{
	drop();
}


/* Tables */

#define MAX_COUNTERS 50

counter fl_count {
	type: packets;
	instance_count: MAX_COUNTERS;
}

table flow_ip4_tcp_tbl {
	reads {
		ipv4.dst: ternary;
		ipv4.src: ternary;
		tcp.sport: ternary;
		tcp.dport: ternary;
	}
	actions {
		fwd_act;
		drop_act;
	}
}

table flow_ip4_udp_tbl {
	reads {
		ipv4.dst: ternary;
		ipv4.src: ternary;
		udp.sport: ternary;
		udp.dport: ternary;
	}
	actions {
		fwd_act;
		drop_act;
	}
}


/* Ingress */

control ingress
{
	if (valid(tcp))
		apply(flow_ip4_tcp_tbl);
	else
		apply(flow_ip4_udp_tbl);
}

/* No egress */

