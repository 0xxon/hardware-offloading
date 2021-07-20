#include "actions.p4"

#define MAX_COUNTERS 50

/* Netronome max number of VFs and 2 physical ones (+ 1 for default rule) */
#define MAX_SPLITTER_RULES 35

#define NBR_CTRL_COMMANDS 1

/* One counter for all the tables -> simpler */
counter fl_count_mod {
	type: packets;
	instance_count: MAX_COUNTERS;
}

counter fl_count {
	type: packets;
	instance_count: MAX_COUNTERS;
}

register th_fl_count {
	width: 64;
	instance_count: 1;
}

/* Incremented by each clock packet from the controller */
counter ctrl_clock {
	type: packets;
	instance_count: 1;
}

register debug_counter {
	width: 32;
	instance_count: 20;
}

table flow_ip6_tcp_tbl {
	reads {
		ipv6.dst: ternary;
		ipv6.src: ternary;
		tcp.srcPort: ternary;
		tcp.dstPort: ternary;
	}
	actions {
		fwd_act;
		drop_act;
		reset_th; /* Never actually called but to prevent the register to be dropped in compile time */
	}
}

table flow_ip6_udp_tbl {
	reads {
		ipv6.dst: ternary;
		ipv6.src: ternary;
		udp.srcPort: ternary;
		udp.dstPort: ternary;
	}
	actions {
		fwd_act;
		drop_act;
		reset_th;
	}
}

table flow_ip4_tcp_tbl {
	reads {
		ipv4.dst: ternary;
		ipv4.src: ternary;
		tcp.srcPort: ternary;
		tcp.dstPort: ternary;
	}
	actions {
		fwd_act;
		drop_act;
		reset_th;
	}
}

table flow_ip4_udp_tbl {
	reads {
		ipv4.dst: ternary;
		ipv4.src: ternary;
		udp.srcPort: ternary;
		udp.dstPort: ternary;
	}
	actions {
		fwd_act;
		drop_act;
		reset_th;
	}
}

/* Used only for statistics only frames */
table mac_tbl {
	reads {
		eth.src: ternary;
		eth.dst: ternary;
	}
	actions {
		set_nexthop;
		db_act;
	}
	size : 1;
}

/* heartbeats */
table controller_cmd_tbl {
	reads {
		eth.src: ternary;
		eth.dst: ternary;
	}
	actions {
		controller_clock;
	}
	/* XXX Change if additional commands are used */
	size : NBR_CTRL_COMMANDS;
}

table checksum_recompute {
	reads {
		tcp.SYN: exact;
	}
	actions {
		trigger_checksum_update;
	}
	/* Only applied for SYN+ACK */
	size : 1;
}

table ecmp_tbl {
	reads {
		flow_meta.ecmp_hash_value: exact;
	}
	actions {
		set_nexthop;
	}
	size : MAX_SPLITTER_RULES;
}

