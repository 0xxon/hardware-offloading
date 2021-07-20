
/* This code filters out SYNs  issued from port scanning
 * -> SYNs are dropped and add state to the hashtable
 * -> SYN+ACKs remove the state in the hashtable and are forwarded
 *
 * This code is inspired from https://github.com/open-nfpsw/p4c_firewall
 * The heap implementation is inspired from https://gist.github.com/aatishnn/8265656
 */

#define SPIN_LOCK_SLEEP 2000 /* cycles TODO Change */

#define BUCKET_SIZE 16
#define HASHTABLE_SIZE 0x0FFFFF /* 16777200 state table entries available */
#define QUEUE_SIZE 0x00FFFF /* FIXME Get a real relation between hashtable size and queue size */

/* This value represents how many ticks (of the controller clock) we wait before cleaning a connection.
 * For the algebra of the unsigned integers to work, this tolerance must never exceed the half of the maximum clock value
 */
#define TOLERANCE 5
#define CTRL_CLOCK pif_register_ctrl_clock

/* TODO Handle IPv6 with another bucket */
typedef struct bucket_entry {
	/* We want to get the same keys for both directions of the flow
	 * The is composed of 2 IPs and 2 ports. The "biggest" IP/port first.
	 * The "biggest" host has the biggest IP address
	 * (if both are equal, it has the largest port number)
	 */
	uint32_t key[3];
	/* No protocol field needed since only TCP SYNs are kept */

	uint32_t active;

	/* Index inside the heap */
	uint32_t heap_index;
} bucket_entry;

typedef struct bucket_list {
	bucket_entry list[BUCKET_SIZE];
} bucket_list;

__shared __export __addr40 __emem bucket_list syn_tbl[HASHTABLE_SIZE];

typedef struct prio_node {
	uint32_t hashtable_index;
	/* Index in the bucket list of the hashtable */
	uint32_t collision_index;
	uint32_t timestamp;
} prio_node;

__shared __export __addr40 __emem prio_node heap[QUEUE_SIZE];
// The index + 1 of the last element in the priority queue
__shared __export __addr40 __emem uint32_t conn_number[1];

__shared __export __emem volatile uint32_t syn_lock = 0;


#define find_key(ipv4, tcp, hash_key) \
	if (ipv4->src > ipv4->dst || \
	    ipv4->src == ipv4->dst && tcp->srcPort >= tcp->dstPort) { \
		hash_key[0] = ipv4->src; \
		hash_key[1] = ipv4->dst; \
		hash_key[2] = (tcp->srcPort << 16) | tcp->dstPort; \
	} else { \
		hash_key[0] = ipv4->dst; \
		hash_key[1] = ipv4->src; \
		hash_key[2] = (tcp->dstPort << 16) | tcp->srcPort; \
	}

static void lock_syn_cache()
{
	__xrw uint32_t xfer = 1;
	mem_test_set(&xfer, &syn_lock, sizeof(uint32_t));
	while(xfer == 1) {
		sleep(SPIN_LOCK_SLEEP);
		mem_test_set(&xfer, &syn_lock, sizeof(uint32_t));
	}
}

static void unlock_syn_cache()
{
	__xwrite uint32_t xfer_out = 0;
	mem_write32(&xfer_out, &syn_lock, sizeof(uint32_t));
}

/* Connection addition */

static uint32_t insert_prio_entry(uint32_t count, uint32_t hashtable_index,
				  int32_t collision_index)
{
	uint32_t prio_index;
	uint32_t parent_index;

	uint32_t current_clock;

	__xread prio_node parent_node_r;
	__xwrite prio_node node_w;

	prio_index = count;
	current_clock = PIF_HEADER_GET_ctrl_clock___value_packets___1(CTRL_CLOCK);

	for(; prio_index; prio_index = parent_index) {
		parent_index = (prio_index - 1) >> 1; // Integer division by 2

		mem_read32(&parent_node_r, heap + parent_index, sizeof(parent_node_r));
		if (parent_node_r.timestamp <= current_clock)
			break;

		node_w = parent_node_r;
		mem_write32(&node_w, heap + prio_index, sizeof(node_w));
	}

	node_w.hashtable_index = hashtable_index;
	node_w.collision_index = collision_index;
	node_w.timestamp = current_clock;
	mem_write32(&node_w, heap + prio_index, sizeof(node_w));

	return prio_index;
}

static int add_connection(EXTRACTED_HEADERS_T *headers, PIF_PLUGIN_ipv4_T *ipv4,
			  PIF_PLUGIN_tcp_T *tcp)
{
	uint32_t hash_key[3];
	volatile uint32_t hash_value;

	__addr40 bucket_entry *entry;
	__xwrite bucket_entry tmp_entry;

	uint32_t i;
	uint32_t heap_index;

	__xread uint32_t conn_number_r;
	__xwrite uint32_t conn_number_w;

	find_key(ipv4, tcp, hash_key);

	/* TODO Change has value by looking at which functions are available on
	 * the lib (hash_toeplitz ? cphash ?)
	 */
	hash_value = hash_me_crc32((void *) hash_key, sizeof(hash_key), 1);
	hash_value &= (HASHTABLE_SIZE);

	lock_syn_cache();

	for (i = 0; i < BUCKET_SIZE; i += 1) {
		if (!syn_tbl[hash_value].list[i].active) {
			entry = &syn_tbl[hash_value].list[i];
			break;
		}
	}

	mem_read32(&conn_number_r, conn_number, sizeof(conn_number_r));

	/* Full bucket or full queue -> must send the SYN anyway */
	if (i == BUCKET_SIZE || conn_number_r == QUEUE_SIZE) {
		unlock_syn_cache();
		return PIF_PLUGIN_RETURN_FORWARD;
	}

	heap_index = insert_prio_entry(conn_number_r, hash_value, i);

	conn_number_w = conn_number_r + 1;
	mem_write32(&conn_number_w, conn_number, sizeof(conn_number_w));

	tmp_entry.key[0] = hash_key[0];
	tmp_entry.key[1] = hash_key[1];
	tmp_entry.key[2] = hash_key[2];
	tmp_entry.active = 1;
	tmp_entry.heap_index = heap_index;

	mem_write32(&tmp_entry, entry, sizeof(tmp_entry));

	unlock_syn_cache();

	return PIF_PLUGIN_RETURN_DROP;
}

/* Removal of connections */

/**
 * Restore the heap ordering after removing an element
 */
static void min_heapify(uint32_t count, uint32_t index)
{
	uint32_t loc;
	uint32_t oldest;
	uint32_t left;
	uint32_t right;

	__xread prio_node loc_node_r;
	__xread prio_node oldest_node_r;
	__xread prio_node left_node_r;
	__xread prio_node right_node_r;

	__xwrite prio_node swap_node_loc_w;
	__xwrite prio_node swap_node_old_w;

	loc = index;
	oldest = loc;
	do {
		loc = oldest;
		left = 2*(loc) + 1;
		right = left + 1;

		mem_read32(&oldest_node_r, heap + oldest, sizeof(oldest_node_r));

		if (left <= count) {
			mem_read32(&left_node_r, heap + left, sizeof(left_node_r));
			if (left_node_r.timestamp < oldest_node_r.timestamp) {
				oldest = left;
				swap_node_loc_w = left_node_r;
			}
		}

		if (right <= count) {
			mem_read32(&right_node_r, heap + right, sizeof(right_node_r));
			if (right_node_r.timestamp < oldest_node_r.timestamp) {
				oldest = right;
				swap_node_loc_w = right_node_r;
			}
		}

		if (loc != oldest) {
			/* Swap heap[loc] and heap[oldest] */
			mem_read32(&loc_node_r, heap + loc, sizeof(loc_node_r));
			mem_write32(&swap_node_loc_w, heap + loc, sizeof(swap_node_loc_w));
			swap_node_old_w = loc_node_r;
			mem_write32(&swap_node_old_w, heap + oldest, sizeof(swap_node_old_w));
		}
	} while (loc != oldest);
	debug_set(15, oldest); // TODO final index of the last element
}

static void remove_prio_entry(uint32_t count, uint32_t index)
{
	__xread prio_node node_r;
	__xwrite prio_node node_w;

	int lastindex = count - 1;

	mem_read32(&node_r, heap + lastindex, sizeof(node_r));

	node_w = node_r;
	mem_write32(&node_w, heap + index, sizeof(node_w));

	/* "Re-heapify" everything */
	min_heapify(lastindex + 1, index);
}

static void remove_connection(EXTRACTED_HEADERS_T *headers,
			      PIF_PLUGIN_ipv4_T *ipv4, PIF_PLUGIN_tcp_T *tcp)
{
	__addr40 bucket_entry *entry;
	uint32_t hash_key[3];
	__xread bucket_entry entry_r;
	__xwrite bucket_entry entry_w;

	volatile uint32_t hash_value;
	uint32_t i = 0;
	int found = 0;

	__xread uint32_t conn_number_r;
	__xwrite uint32_t conn_number_w;

	find_key(ipv4, tcp, hash_key);

	/* TODO Change has value by looking at which functions are available on
	 * the lib (hash_toeplitz ? cphash ?)
	 */
	hash_value = hash_me_crc32((void *) hash_key, sizeof(hash_key), 1);
	hash_value &= (HASHTABLE_SIZE);

	lock_syn_cache();

	mem_read32(&conn_number_r, conn_number, sizeof(conn_number_r));

	for (; i < BUCKET_SIZE; i++) {
		entry = &syn_tbl[hash_value].list[i];
		mem_read32(&entry_r, entry, sizeof(entry_r));

		if (!entry_r.active)
			continue;

		if (hash_key[0] == entry_r.key[0]
		    && hash_key[1] == entry_r.key[1]
		    && hash_key[2] == entry_r.key[2]) {

			remove_prio_entry(conn_number_r, entry_r.heap_index);
			conn_number_w = conn_number_r - 1;
			mem_write32(&conn_number_w, conn_number, sizeof(conn_number_w));

			entry_w.key[0] = 0;
			entry_w.key[1] = 0;
			entry_w.key[2] = 0;
			entry_w.active = 0;
			entry_w.heap_index = 0;

			mem_write32(&entry_w, entry, sizeof(entry_w));
			found = 1;
			break;
		}
	}

	unlock_syn_cache();

	if (!found) {
		/* Unmark SYN+ACK as established connection
		 *
		 * The cleanest way to do that would be to define a new TCP
		 * option but the TCP option space is limited to 40 bytes due to
		 * bad design choices (i.e., 4 bits for the data offset).
		 *
		 * Therefore we use the 3 reserved bits of the TCP header.
		 */
		PIF_HEADER_SET_tcp___res(tcp, 0);
	}
}

/* Main logic */
static int port_scanning_filter(EXTRACTED_HEADERS_T *headers,
				ACTION_DATA_T *action_data)
{
	PIF_PLUGIN_ipv4_T *ipv4;
	PIF_PLUGIN_tcp_T *tcp;

	/* XXX IPv6 not supported (use memcmp ?) */
	if (pif_plugin_hdr_ipv4_present(headers)
	    && pif_plugin_hdr_tcp_present(headers)) {

		ipv4 = pif_plugin_hdr_get_ipv4(headers);
		tcp = pif_plugin_hdr_get_tcp(headers);

		if (PIF_HEADER_GET_tcp___SYN(tcp)
		    && !PIF_HEADER_GET_tcp___ACK(tcp)) {
			return add_connection(headers, ipv4, tcp);

		} else if (PIF_HEADER_GET_tcp___SYN(tcp)
			   && PIF_HEADER_GET_tcp___ACK(tcp)) {
			remove_connection(headers, ipv4, tcp);
		}
	}

	return PIF_PLUGIN_RETURN_FORWARD;
}

/* Cleanup due to heartbeat */
int pif_plugin_clock_syn_offloading(EXTRACTED_HEADERS_T *headers,
				    ACTION_DATA_T *action_data)
{
	uint32_t conn_number_tmp;
	__xread uint32_t conn_number_r;
	__xwrite uint32_t conn_number_w;

	uint32_t current_clock;

	__xread prio_node oldest_node_r;

	__xwrite uint32_t hash_active;

	lock_syn_cache();

	mem_read32(&conn_number_r, conn_number, sizeof(conn_number_r));
	conn_number_tmp = conn_number_r;

	hash_active = 0;

	if (conn_number_tmp) {

		/* Cap the first 32 bits of the clock */
		current_clock = PIF_HEADER_GET_ctrl_clock___value_packets___1(CTRL_CLOCK);

		mem_read32(&oldest_node_r, heap, sizeof(oldest_node_r));
		while (conn_number_tmp && oldest_node_r.timestamp + TOLERANCE < current_clock) {

			/* Disable hashmap entry to oldest entry */
			mem_write32(&hash_active, &(syn_tbl[oldest_node_r.hashtable_index].list[oldest_node_r.collision_index].active), sizeof(hash_active));

			remove_prio_entry(conn_number_tmp, 0);
			conn_number_tmp = conn_number_tmp - 1;

			mem_read32(&oldest_node_r, heap, sizeof(oldest_node_r));
		}

		conn_number_w = conn_number_tmp;
		mem_write32(&conn_number_w, conn_number, sizeof(conn_number_w));
	}

	unlock_syn_cache();

	/* To measure latency */
	return PIF_PLUGIN_RETURN_FORWARD;
}

