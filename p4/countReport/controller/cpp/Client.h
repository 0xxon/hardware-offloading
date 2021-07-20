#ifndef CLIENT_H
#define CLIENT_H

#include "gen-cpp/RunTimeEnvironment.h"
#include "lib/json.hpp"

#include "StatFlow.h"

class Client: public RunTimeEnvironmentClient
{
public:
	Client(boost::shared_ptr< ::apache::thrift::protocol::TProtocol> prot):
		RunTimeEnvironmentClient(prot) { }

	void design_reconfig(RteReturn& _return,
			     const std::string& pif_config_json) {
		RunTimeEnvironmentClient::design_reconfig(_return,
							  pif_config_json);
	}
	int design_reconfig(const std::string &pif_config_json_path,
			    std::vector<StatFlow> &flows,
			    uint32_t max_vfs);

	/* TODO Add separate removal and addition of rule */

	int retrieve_stats(std::vector<StatFlow> &flows);
	int info_fetching();

private:
	uint32_t pktcnt_index = 0;
};

#endif

