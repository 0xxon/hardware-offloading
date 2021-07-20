
/*
 * Registers shortcuts
 */
#define FL_COUNT pif_register_fl_count
#define FL_COUNT_MOD pif_register_fl_count_mod
#define TH_COUNT pif_register_th_fl_count

/* Adds to the packet a statistic header
 *
 * @param idx: The index inside the counter tables fl_count and fl_count_mod.
 * This parameter is retrieved from the "local" metadata since Netronome does
 * not support yet arguments in primitive actions.
 */
static int advertise_stats(EXTRACTED_HEADERS_T *headers,
			   ACTION_DATA_T *action_data)
{
	PIF_PLUGIN_shortcut_T *shortcut;
	PIF_PLUGIN_flv4_spec_T *flv4_spec;
	PIF_PLUGIN_flv6_spec_T *flv6_spec;
	PIF_PLUGIN_fl_pktcnt_T *fl_pktcnt;
	PIF_PLUGIN_eth_T *eth;
	uint32_t idx;

	uint32_t cnt_0;
	uint32_t cnt_1;
	uint32_t cnt_mod_0;
	uint32_t cnt_mod_1;
	uint32_t cnt_th_0;
	uint32_t cnt_th_1;

	uint16_t etype;

	idx = pif_plugin_meta_get__local__idx(headers);

	/* Counters's words are inverted for some reason in netronome */
	cnt_1 = PIF_HEADER_GET_fl_count___value_packets___0(&FL_COUNT[idx]);
	cnt_0 = PIF_HEADER_GET_fl_count___value_packets___1(&FL_COUNT[idx]);
	cnt_mod_1 = PIF_HEADER_GET_fl_count_mod___value_packets___0(\
							&FL_COUNT_MOD[idx]);
	cnt_mod_0 = PIF_HEADER_GET_fl_count_mod___value_packets___1(\
							&FL_COUNT_MOD[idx]);

	cnt_th_0 = PIF_HEADER_GET_th_fl_count___value___0(TH_COUNT);
	cnt_th_1 = PIF_HEADER_GET_th_fl_count___value___1(TH_COUNT);

	if ((cnt_mod_0 >= cnt_th_0 ||
	     (cnt_mod_0 == cnt_th_0 && cnt_mod_1 >= cnt_th_1))
	    && !pif_plugin_hdr_shortcut_add(headers)) {

		shortcut = pif_plugin_hdr_get_shortcut(headers);

		if (pif_plugin_hdr_ipv6_present(headers)) {
			pif_plugin_hdr_flv6_spec_add(headers);
			flv6_spec = pif_plugin_hdr_get_flv6_spec(headers);
			if (!flv6_spec)
				goto remove_shortcut;

			PIF_HEADER_SET_shortcut___nxt(shortcut,
						      FLV6_SPEC_STNXT);
			PIF_HEADER_SET_shortcut___len(shortcut, 4);
			PIF_HEADER_SET_shortcut___lenShortcut(shortcut, 52); /* FIXME Should not be hardcoded */

			PIF_HEADER_SET_flv6_spec___nxt(flv6_spec,
						       FL_PKTCNT_STNXT);
			PIF_HEADER_SET_flv6_spec___len(flv6_spec, 40);

			PIF_HEADER_SET_flv6_spec___src___0(flv6_spec, pif_plugin_meta_get__local__src_v6__0(headers));
			PIF_HEADER_SET_flv6_spec___src___1(flv6_spec, pif_plugin_meta_get__local__src_v6__1(headers));
			PIF_HEADER_SET_flv6_spec___src___2(flv6_spec, pif_plugin_meta_get__local__src_v6__2(headers));
			PIF_HEADER_SET_flv6_spec___src___3(flv6_spec, pif_plugin_meta_get__local__src_v6__3(headers));

			PIF_HEADER_SET_flv6_spec___dst___0(flv6_spec, pif_plugin_meta_get__local__dst_v6__0(headers));
			PIF_HEADER_SET_flv6_spec___dst___1(flv6_spec, pif_plugin_meta_get__local__dst_v6__1(headers));
			PIF_HEADER_SET_flv6_spec___dst___2(flv6_spec, pif_plugin_meta_get__local__dst_v6__2(headers));
			PIF_HEADER_SET_flv6_spec___dst___3(flv6_spec, pif_plugin_meta_get__local__dst_v6__3(headers));

			PIF_HEADER_SET_flv6_spec___srcPrefixLen(flv6_spec, pif_plugin_meta_get__local__srcPrefixLen(headers));
			PIF_HEADER_SET_flv6_spec___dstPrefixLen(flv6_spec, pif_plugin_meta_get__local__dstPrefixLen(headers));
			PIF_HEADER_SET_flv6_spec___tcp(flv6_spec, pif_plugin_meta_get__local__tcp(headers));
			PIF_HEADER_SET_flv6_spec___udp(flv6_spec, pif_plugin_meta_get__local__udp(headers));
			PIF_HEADER_SET_flv6_spec___reserved(flv6_spec, 0);
			PIF_HEADER_SET_flv6_spec___srcPort(flv6_spec, pif_plugin_meta_get__local__srcPort(headers));
			PIF_HEADER_SET_flv6_spec___dstPort(flv6_spec, pif_plugin_meta_get__local__dstPort(headers));
		} else {
			pif_plugin_hdr_flv4_spec_add(headers);
			flv4_spec = pif_plugin_hdr_get_flv4_spec(headers);
			if (!flv4_spec)
				goto remove_shortcut;

			PIF_HEADER_SET_shortcut___nxt(shortcut,
						      FLV4_SPEC_STNXT);
			PIF_HEADER_SET_shortcut___len(shortcut, 4);
			PIF_HEADER_SET_shortcut___lenShortcut(shortcut, 28); /* FIXME Should not be hardcoded */

			PIF_HEADER_SET_flv4_spec___nxt(flv4_spec,
						       FL_PKTCNT_STNXT);
			PIF_HEADER_SET_flv4_spec___len(flv4_spec, 16);

			PIF_HEADER_SET_flv4_spec___src(flv4_spec, pif_plugin_meta_get__local__src_v4(headers));
			PIF_HEADER_SET_flv4_spec___dst(flv4_spec, pif_plugin_meta_get__local__dst_v4(headers));

			PIF_HEADER_SET_flv4_spec___srcPrefixLen(flv4_spec, pif_plugin_meta_get__local__srcPrefixLen(headers));
			PIF_HEADER_SET_flv4_spec___dstPrefixLen(flv4_spec, pif_plugin_meta_get__local__dstPrefixLen(headers));
			PIF_HEADER_SET_flv4_spec___tcp(flv4_spec, pif_plugin_meta_get__local__tcp(headers));
			PIF_HEADER_SET_flv4_spec___udp(flv4_spec, pif_plugin_meta_get__local__udp(headers));
			PIF_HEADER_SET_flv4_spec___reserved(flv4_spec, 0);
			PIF_HEADER_SET_flv4_spec___srcPort(flv4_spec, pif_plugin_meta_get__local__srcPort(headers));
			PIF_HEADER_SET_flv4_spec___dstPort(flv4_spec, pif_plugin_meta_get__local__dstPort(headers));
		}

		pif_plugin_hdr_fl_pktcnt_add(headers);
		fl_pktcnt = pif_plugin_hdr_get_fl_pktcnt(headers);
		if (!fl_pktcnt)
			goto remove_fl_spec;

		/* Even if there is no locking, the preclassifier of netronome
		 * prevents concurrent access to the counter slots. Only flows
		 * with different 5-tuples can go to a different thread. Such
		 * flows match different rules.
		 */
		PIF_HEADER_SET_fl_count_mod___value_packets___0(\
							&FL_COUNT_MOD[idx], 0);
		PIF_HEADER_SET_fl_count_mod___value_packets___1(\
							&FL_COUNT_MOD[idx], 0);

		eth = pif_plugin_hdr_get_eth(headers);

		/* Note : The counter's words are inverted to appear in the header
		 * in the correct order
		 */
		PIF_HEADER_SET_fl_pktcnt___cnt___1(fl_pktcnt, cnt_1);
		PIF_HEADER_SET_fl_pktcnt___cnt___0(fl_pktcnt, cnt_0);

		etype = PIF_HEADER_GET_eth___etype(eth);
		/* FIXME This assumes that Ethernet type has the same value as
		 * its Next Stat equivalent
		 */
		PIF_HEADER_SET_fl_pktcnt___nxt(fl_pktcnt, etype);
		PIF_HEADER_SET_shortcut___nxtShortcut(shortcut, etype);
		PIF_HEADER_SET_fl_pktcnt___len(fl_pktcnt, 8);
		PIF_HEADER_SET_eth___etype(eth, STAT_ETYPE);

		return ATTACHED_STATISTICS;
	}

out:
	return NO_ATTACHED_STATISTICS;

remove_fl_spec:
	if (pif_plugin_hdr_ipv6_present(headers))
		pif_plugin_hdr_flv6_spec_remove(headers);
	else
		pif_plugin_hdr_flv4_spec_remove(headers);
remove_shortcut:
	pif_plugin_hdr_shortcut_remove(headers);
	goto out;
}

