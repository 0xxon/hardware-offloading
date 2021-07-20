#pragma once

#include <stdio.h>

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
