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

/* Header instances */

header eth_hdr eth;
header ipv4_hdr ipv4;
header ipv6_hdr ipv6;

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
		default : eth_ingress;
	}
}

parser ipv4_parse
{
	extract(ipv4);
	return eth_ingress; //ipv4_ingress;
}

parser ipv6_parse
{
	extract(ipv6);
	return eth_ingress; //ipv6_ingress;
}

/* Ingress */
action fwd_act(port)
{
	modify_field(standard_metadata.egress_spec, port);
}

action drop_act()
{
	drop();
}

table fwd_tbl {
	reads {
		eth.dst: exact;
	}
	actions {
		fwd_act;
		drop_act;
	}
}

counter eth_count {
	type : packets;
	direct : fwd_tbl;
	//min_width : 32;
}

control eth_ingress
{
	apply(fwd_tbl);
}

//control ipv4_ingress
//{
	// TODO Add different counts here
	//apply(fwd_tbl);
//}

//control ipv6_ingress
//{
	// TODO Add different counts here
	//apply(fwd_tbl);
//}

/* No egress */
