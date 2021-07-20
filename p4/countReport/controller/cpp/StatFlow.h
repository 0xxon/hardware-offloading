#ifndef STATFLOW_H
#define STATFLOW_H

#include "lib/json.hpp"

#include "StatFrame.h"

class StatFlow
{
public:
	int init(nlohmann::json &params, int ipv4, int ipv6, int tcp, int udp);
	int produce_stat_headers(StatFrame &frame) const;

	uint64_t fl_pktcnt;
	uint32_t idx;
private:
	/* All the following fields are stored
	 * in network byte-order
	 */
	uint32_t src_v4;
	uint8_t src_v6 [16];
	uint8_t src_prefixlen;
	uint32_t dst_v4;
	uint8_t dst_v6 [16];
	uint8_t dst_prefixlen;
	uint16_t src_port;
	uint16_t dst_port;
	bool ipv6;
	bool ipv4;
	bool tcp;
	bool udp;
};

#endif

