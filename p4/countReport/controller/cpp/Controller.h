#ifndef CONTROLLER_H
#define CONTROLLER_H

#include <thrift/protocol/TBinaryProtocol.h>
#include <thrift/transport/TSocket.h>
#include <thrift/transport/TTransportUtils.h>
#include <thrift/transport/TZlibTransport.h>

#include "Client.h"
#include "StatFlow.h"
#include "StatFrame.h"
#include "CleanFrame.h"


class Controller {

public:
	Controller(int rpc_port, unsigned int stat_time,
		   unsigned int nic_clock);
	~Controller();
	int setup(const char *start_config_path);
	int run();
private:
	Client *client = nullptr;
	boost::shared_ptr<apache::thrift::transport::TZlibTransport> transport;

	unsigned int stat_sleep_time;
	unsigned int nic_clock_frequence;
	std::vector<StatFlow> flows = std::vector<StatFlow>();
	int sfd = -1;
	int clean_sfd = -1;

	uint8_t ether_shost[6];
	struct sockaddr_ll socket_dst_address;

	StatFrame stat_frame;
	CleanFrame clean_frame;

	int report_stats();
	int cleanup_syn_offloading();
};

#endif

