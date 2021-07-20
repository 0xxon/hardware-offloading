
primitive_action pipeline_process();
primitive_action clock_syn_offloading();

action fwd_act(idx, src_v4, src_v6, srcPrefixLen, dst_v4, dst_v6,
	       dstPrefixLen, srcPort, dstPort, tcp_proto, udp_proto)
{
	/* This metadata field is useful for the C action
	 * because netronome does not allow to pass arguments for the moment
	 */
	modify_field(local.idx, idx);
	modify_field(local.src_v4, src_v4);
	modify_field(local.src_v6, src_v6);
	modify_field(local.srcPrefixLen, srcPrefixLen);
	modify_field(local.dst_v4, dst_v4);
	modify_field(local.dst_v6, dst_v6);
	modify_field(local.dstPrefixLen, dstPrefixLen);
	modify_field(local.srcPort, srcPort);
	modify_field(local.dstPort, dstPort);
	modify_field(local.tcp, tcp_proto);
	modify_field(local.udp, udp_proto);

	/* Counting */
	count(fl_count, idx);
	count(fl_count_mod, idx);

	/* In netronome every action executes its instructions sequentially,
	 * though this is not what the P4 specifications state
	 */
	pipeline_process();

	/* Select the egress rule */
	modify_field_with_hash_based_offset(flow_meta.ecmp_hash_value, 0, ecmp_hash, MAX_VFS); /* MAX_VFS is defined in the Makefile */
}

action drop_act()
{
	drop();
}

action reset_th()
{
	/**
	 * This action is useless. But P4 compiler will remove the register
	 * if it is not "used" somewhere. Indeed, P4 compiler does not
	 * consider C files.
	 */
	register_write(th_fl_count, 0, 0);
}

action controller_clock(port)
{
	/* Forwarded to measure processing cost and the number of entries removed */
	modify_field(standard_metadata.egress_spec, port);

	count(ctrl_clock, 0);
	clock_syn_offloading();
}

/* Action is here for the sole purpose of referencing debug_counter */
action db_act()
{
	register_write(debug_counter, 0, 0);
}

action trigger_checksum_update()
{
	/* Changing this field in C does not trigger checksum update */
	modify_field(tcp.res, 1);
}

action set_nexthop(port)
{
	modify_field(standard_metadata.egress_spec, port);
}

