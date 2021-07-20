#include <arpa/inet.h>
#include <regex>

#include "StatFlow.h"
#include "StatHeader.h"

using namespace std;
using namespace nlohmann;


class ParsingException: public runtime_error {
public:
	ParsingException(const char *str) : runtime_error(str) {}
};


static void parse_addr(string addr, void *ptr, int af_type)
{
	int s = inet_pton(af_type, addr.data(), ptr);
	if (s <= 0) {
		if (s == 0)
			fprintf(stderr, "Not in presentation format");
		else
			perror("inet_pton");
		throw ParsingException(addr.data());
	}
}

static uint32_t parse_int(string param)
{
	uint32_t val;
	smatch matches;
	regex p4_integer("^(?:([1-9]?[0-9]*)')?(.+)$");
	if (regex_search(param, matches, p4_integer)) {
		string str = matches.str(2);
		size_t pos = 0;

		val = (uint32_t) stoul(str, &pos, 0);
		if (pos < str.length())
			throw ParsingException(param.data());
	} else {
		throw ParsingException(param.data());
	}

	return val;
}

int StatFlow::init(json &params, int p_ipv4, int p_ipv6, int p_tcp, int p_udp)
{
	try {
		if (p_ipv6) {
			parse_addr(params[P_SRC_V6]["value"].get<string>(),
				   this->src_v6, AF_INET6);
			parse_addr(params[P_DST_V6]["value"].get<string>(),
				   this->dst_v6, AF_INET6);
		}
		if (p_ipv4) {
			parse_addr(params[P_SRC_V4]["value"].get<string>(),
				   &this->src_v4, AF_INET);
			parse_addr(params[P_DST_V4]["value"].get<string>(),
				   &this->dst_v4, AF_INET);
		}

		this->src_prefixlen = \
			(uint8_t) parse_int(params[P_SRC_PREFIX_LEN]["value"] \
						.get<string>());
		this->dst_prefixlen = \
			(uint8_t) parse_int(params[P_DST_PREFIX_LEN]["value"] \
						.get<string>());

		this->src_port = \
			htons((uint16_t) parse_int(params[P_SRC_PORT]["value"] \
						.get<string>()));
		this->dst_port = \
			htons((uint16_t) parse_int(params[P_DST_PORT]["value"] \
						.get<string>()));

		this->ipv4 = p_ipv4;
		this->ipv6 = p_ipv6;
		this->tcp = p_tcp;
		this->udp = p_udp;

		this->idx = params["idx"]["value"].get<int>();
	} catch (ParsingException &e) {
		cerr << "Cannot parse a string supplied: "
			<< e.what() << endl;
		return -1;
	}
	return 0;
}

int StatFlow::produce_stat_headers(StatFrame &frame) const
{
	/* FIXME No IPv6 */

	if (frame.get_size_free() < sizeof(struct stat_flow_ipv4)
				    + sizeof(struct stat_fl_pktcnt)) {
		return -1;
	}

	struct stat_flow_ipv4 flv4;
	uint16_t len = sizeof(flv4) - sizeof(flv4.tlv);
	flv4.tlv.len = htons(len);
	memcpy(&flv4.src, &this->src_v4, 4);
	memcpy(&flv4.dst, &this->dst_v4, 4);
	flv4.src_prefixlen = this->src_prefixlen;
	flv4.dst_prefixlen = this->dst_prefixlen;
	flv4.tcp = this->tcp;
	flv4.udp = this->udp;
	flv4.res_1 = 0;
	flv4.res_2 = 0;
	memcpy(&flv4.src_port, &this->src_port, 2);
	memcpy(&flv4.dst_port, &this->dst_port, 2);

	frame.append_stat_header((unsigned char *) &flv4, len,
				 htons(FLV4_SPEC_STNXT));

	struct stat_fl_pktcnt pktcnt;
	len = sizeof(pktcnt) - sizeof(pktcnt.tlv);
	pktcnt.tlv.len = htons(len);
	pktcnt.fl_pktcnt = htonl(this->fl_pktcnt);

	frame.append_stat_header((unsigned char *) &pktcnt, len,
				 htons(FL_PKTCNT_STNXT));

	return 0;
}

