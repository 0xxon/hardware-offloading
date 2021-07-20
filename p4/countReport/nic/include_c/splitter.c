
/* This code fills in the flow_meta values
 * (and provides the same fields for the two directions of a connection)
 */

static void ecmp_splitter(EXTRACTED_HEADERS_T *headers)
{
	/* XXX IPv6 not supported (use memcmp ?) */
	PIF_PLUGIN_ipv4_T *ipv4;
	PIF_PLUGIN_tcp_T *tcp;
	PIF_PLUGIN_udp_T *udp;

	uint16_t srcPort;
	uint16_t dstPort;

	ipv4 = pif_plugin_hdr_get_ipv4(headers);

	if (pif_plugin_hdr_tcp_present(headers)) {
		tcp = pif_plugin_hdr_get_tcp(headers);
		srcPort = tcp->srcPort;
		dstPort = tcp->dstPort;
	} else {
		udp = pif_plugin_hdr_get_udp(headers);
		srcPort = udp->srcPort;
		dstPort = udp->dstPort;
	}

	if (ipv4->src > ipv4->dst ||
	    ipv4->src == ipv4->dst && srcPort >= dstPort) {
		pif_plugin_meta_set__flow_meta__addr1_v4(headers, ipv4->src);
		pif_plugin_meta_set__flow_meta__addr2_v4(headers, ipv4->dst);
		pif_plugin_meta_set__flow_meta__port1(headers, srcPort);
		pif_plugin_meta_set__flow_meta__port2(headers, dstPort);
	} else {
		pif_plugin_meta_set__flow_meta__addr1_v4(headers, ipv4->dst);
		pif_plugin_meta_set__flow_meta__addr2_v4(headers, ipv4->src);
		pif_plugin_meta_set__flow_meta__port1(headers, dstPort);
		pif_plugin_meta_set__flow_meta__port2(headers, srcPort);
	}
}

