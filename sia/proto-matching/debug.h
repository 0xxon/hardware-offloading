#pragma once

#include <stdio.h>
#include <rte_log.h>

#ifdef DEBUG_ENABLE
#define DEBUG(...) fprintf(stderr, __VA_ARGS__);
#else
#define DEBUG(...) do{ } while (0)
#endif 

// Enable DPDK debug options
#ifdef DEBUG_ENABLE
#define CONFIG_RTE_MBUF_DEBUG
#define CONFIG_RTE_LIBRTE_MEMPOOL_DEBUG
#define CONFIG_RTE_MALLOC_DEBUG
#endif

/* Logging Macros */
extern int pt_logtype;
extern int pt_stats_logtype;

#define PT_LOGTYPE_STR "prototype"
#define PT_STATS_LOGTYPE_STR "prototype.stats"

#define PT_STATS_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, pt_stats_logtype, \
		PT_STATS_LOGTYPE_STR ": " fmt "\n", ## args)

#define PT_LOG(level, fmt, args...) \
	PT_LOG_INTLVL(RTE_LOG_ ## level, __func__, fmt, ## args)

// Special version that takes precise caller and log level int values
#define PT_LOG_INTLVL(level, caller, fmt, args...) \
	rte_log(level, pt_logtype, PT_LOGTYPE_STR ": %s(): " fmt "\n", \
		caller, ## args)
