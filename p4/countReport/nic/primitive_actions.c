#include <nfp/mem_atomic.h>
#include <pkt_ops.h>
#include <pif_headers.h>
#include <nfp_override.h>
#include <pif_common.h>
#include <std/hash.h>
#include <nfp/me.h>
#include <memory.h>

#include "pif_plugin.h"


/**
 * Debug code
 */
#define DB_COUNT pif_register_debug_counter

static uint32_t debug_get(uint32_t index)
{
	return PIF_HEADER_GET_debug_counter___value(&DB_COUNT[index]);
}

static void debug_incr(uint32_t index)
{
	uint32_t cnt;
	cnt = PIF_HEADER_GET_debug_counter___value(&DB_COUNT[index]);
	PIF_HEADER_SET_debug_counter___value(&DB_COUNT[index], cnt + 1);
}

static void debug_set(uint32_t index, uint32_t value)
{
	PIF_HEADER_SET_debug_counter___value(&DB_COUNT[index], value);
}


/**
 * Statistic headers
 */
#define STAT_ETYPE 0x8900

#define NONE_STNXT	0x0000
#define SHORTCUT_STNXT  0x0001
#define FLV6_SPEC_STNXT 0x0002
#define FLV4_SPEC_STNXT 0x0003
#define FL_PKTCNT_STNXT 0x0004

#define NO_ATTACHED_STATISTICS 0x0
#define ATTACHED_STATISTICS 0x1

/**
 * Primitive actions
 */

#include <stat_advertise.c>
#include <syn_offloading.c>
#include <splitter.c>

/**
 * Main pipeline
 */

/* Removes the payload of the packet by settings the next header field of the
 * last statistics header to NONE_STNXT
 */
static int remove_payload(EXTRACTED_HEADERS_T *headers,
			  ACTION_DATA_T *action_data)
{
	PIF_PLUGIN_fl_pktcnt_T *fl_pktcnt;
	PIF_PLUGIN_shortcut_T *shortcut;

	/* Last statistic header was defined here as the counting header.
	 * XXX This could change in the future
	 */
	fl_pktcnt = pif_plugin_hdr_get_fl_pktcnt(headers);
	if (!fl_pktcnt)
		return PIF_PLUGIN_RETURN_DROP;
	PIF_HEADER_SET_fl_pktcnt___nxt(fl_pktcnt, NONE_STNXT);

	/* The shortcut has to be changed too */
	shortcut = pif_plugin_hdr_get_shortcut(headers);
	if (!shortcut)
		return PIF_PLUGIN_RETURN_DROP;
	PIF_HEADER_SET_shortcut___nxtShortcut(shortcut, NONE_STNXT);

	return PIF_PLUGIN_RETURN_FORWARD;
}

int pif_plugin_pipeline_process(EXTRACTED_HEADERS_T *headers,
				ACTION_DATA_T *action_data)
{
	int stats = advertise_stats(headers, action_data);
	int filter = port_scanning_filter(headers, action_data);

	/* Statistics must be sent no matter what !
	 * Therefore, the payload will be removed to only keep the stats.
	 */
	if (stats == ATTACHED_STATISTICS && filter == PIF_PLUGIN_RETURN_DROP)
		filter = remove_payload(headers, action_data);

	if (filter != PIF_PLUGIN_RETURN_DROP)
		ecmp_splitter(headers);

	return filter;
}

