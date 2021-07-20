/* For the moment, we limit ourselves to stats above IP traffic */

/* XXX This could be a undefined macro for compilation time such
 * as the maximum number of stat headers
 */

#define STAT_COMMON_HEADER \
	nxt: 16; \
	len: 16;

header_type stat_shortcut_hdr {
	fields {
		STAT_COMMON_HEADER
		/* The next two fields can be used
		 * to bypass (at least partially)
		 * the stat headers.
		 */
		lenShortcut: 16;
		nxtShortcut: 16;
	}
}

header_type stat_flowspec_v4_hdr {
	fields {
		STAT_COMMON_HEADER

		src: 32;
		dst: 32;
		srcPrefixLen: 8;
		dstPrefixLen: 8;

		/* TCP and/or UDP */
		tcp: 1;
		udp: 1;
		reserved: 14;

		/* 0 as port means a wildcard */
		srcPort: 16;
		dstPort: 16;
	}
}

header_type stat_flowspec_v6_hdr {
	fields {
		STAT_COMMON_HEADER

		src: 128;
		dst: 128;
		srcPrefixLen: 8;
		dstPrefixLen: 8;

		/* TCP and/or UDP */
		tcp: 1;
		udp: 1;
		reserved: 14;

		/* 0 as port means a wildcard */
		srcPort: 16;
		dstPort: 16;
	}
}

header_type stat_flow_pktcnt_hdr {
	fields {
		STAT_COMMON_HEADER
		cnt: 64;
	}
}

header stat_flowspec_v4_hdr flv4_spec;
header stat_flowspec_v6_hdr flv6_spec;
header stat_shortcut_hdr shortcut;
header stat_flow_pktcnt_hdr fl_pktcnt;

#define NONE_STNXT	0x0000
#define SHORTCUT_STNXT	0x0001
#define FLV6_SPEC_STNXT	0x0002
#define FLV4_SPEC_STNXT 0x0003
#define FL_PKTCNT_STNXT	0x0004
#define IPV4_STNXT	0x0800
#define IPV6_STNXT	0x86DD

/* Netronome doesn't allow variable length fields in staked header
 * => We are forced to impose an order (but this doesn't really matter
 * since it is only forsending purpose)
 */

parser stat_parse
{
	extract(shortcut);
	return select(latest.nxtShortcut) {
		NONE_STNXT : ingress;
		default : shortcut_parse;
	}
}

parser shortcut_parse
{
	return select(shortcut.nxt) {
		IPV4_STNXT : ipv4_parse;
		IPV6_STNXT : ipv6_parse;
		FLV6_SPEC_STNXT : flv6_spec_parse;
		FLV4_SPEC_STNXT : flv4_spec_parse;
	}
}

parser flv6_spec_parse
{
	extract(flv6_spec);
	return select(latest.nxt) {
		IPV4_STNXT : ipv4_parse;
		IPV6_STNXT : ipv6_parse;
		FL_PKTCNT_STNXT : fl_pktcnt_parse;
	}
}

parser flv4_spec_parse
{
	extract(flv4_spec);
	return select(latest.nxt) {
		IPV4_STNXT : ipv4_parse;
		IPV6_STNXT : ipv6_parse;
		FL_PKTCNT_STNXT : fl_pktcnt_parse;
	}
}

parser fl_pktcnt_parse
{
	extract(fl_pktcnt);
	return select(latest.nxt) {
		IPV4_STNXT : ipv4_parse;
		IPV6_STNXT : ipv6_parse;
	}
}

