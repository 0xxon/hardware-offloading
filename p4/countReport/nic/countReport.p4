#include "parse.p4"
#include "tables.p4"


header_type local_metadata {
	fields {
		idx: 32;
		src_v4: 32;
		dst_v4: 32;
		src_v6: 128;
		dst_v6: 128;
		srcPort: 16;
		dstPort: 16;
		srcPrefixLen: 8;
		dstPrefixLen: 8;
		tcp: 1;
		udp: 1;
	}
}

metadata local_metadata local;


/* Ingress */

control ingress
{
	if (valid(tcp) and tcp.SYN == 1 and tcp.ACK == 1)
		apply(checksum_recompute);

	if (valid(shortcut) and shortcut.nxtShortcut == NONE_STNXT)
		apply(mac_tbl);
	else if (valid(ipv6) and valid(tcp))
		apply(flow_ip6_tcp_tbl);
	else if (valid(ipv6) and valid(udp))
		apply(flow_ip6_udp_tbl);
	else if (valid(ipv4) and valid(tcp))
		apply(flow_ip4_tcp_tbl);
	else if (valid(ipv4) and valid(udp))
		apply(flow_ip4_udp_tbl);
	else
		apply(controller_cmd_tbl);

	/* FIXME not IPv6-compatible */
	if (valid(ipv4) and (valid(tcp) or valid(udp)))
		apply(ecmp_tbl);
}

/* No egress */

