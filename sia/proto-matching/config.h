#pragma once

// how many ports the device has
#define NB_PORTS 2

// The port where input traffic is read from
// The other port will be the output port
#define INPUT_PORT (0)

// How many RX distributor threads to use (must be even number if using HW RSS)
// NOTE: set to 1 to preserve per-stream packet ordering
//
// All other available non-RX lcores will automatically become worker
// threads, up until MAX_NB_WORKERS is reached
#define NB_RX_CORES 1

// maximum number of worker threads to create
// usually this is constrained due to memory limits
#define MAX_NB_WORKERS 9

#define RX_RING_SIZE 256
#define TX_RING_SIZE 256

// number of mbufs to allocate
#define NUM_MBUFS ((1 << 16) - 1)

// size of data cache for mempool
#define MBUF_CACHE_SIZE 100

// size of each mbuf
#define MBUF_SIZE RTE_MBUF_DEFAULT_BUF_SIZE

// size of flow table
#define FLOW_TABLE_SIZE ((1 << 21) - 1)

// maximum number of packets to read in each burst
#define BURST_SIZE 32

// length in bytes of the Ethernet trailer at the end of every packet
// NOTE: trailers are preserved, not stripped
// (e.g. in cases where network hardware adds a trailer)
// (e.g. in our configuration, the CVU adds a 16-byte trailer)
#define ETHER_TRAILER_LENGTH 0

// enable debug print statements
/* #define DEBUG_ENABLE */
