#include <net/if.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <string.h>
#include <chrono>
#include <thread>
#include <cerrno>
#include <future>
#include <net/ethernet.h>
#include <iostream>
#include <signal.h>
#include <string.h>
#include <sys/socket.h>
#include <linux/if_packet.h>

#include "gen-cpp/RunTimeEnvironment.h"

#include "Controller.h"
#include "utils.h"

using namespace std;
using namespace apache::thrift;
using namespace apache::thrift::protocol;
using namespace apache::thrift::transport;

#define RPCPORT 20206
#define STAT_SLEEP_TIME 3000 // ms
#define NIC_CLOCK_FREQUENCE 1000 // ms
#define MTU 1500

static volatile sig_atomic_t interrupted;


static void handle_sigint(int signum)
{
	if (signum == SIGINT)
		interrupted = 1;
}

Controller::Controller(int rpc_port, unsigned int stat_time,
		       unsigned int nic_clock)
{
	boost::shared_ptr<TTransport> socket(new TSocket("127.0.0.1", rpc_port));
	boost::shared_ptr<TBufferedTransport> buf(new TBufferedTransport(socket));
	this->transport = boost::shared_ptr<TZlibTransport>(new TZlibTransport(buf));
	boost::shared_ptr<TProtocol> protocol(new TBinaryProtocol(transport));

	this->client = new Client(protocol);

	this->stat_sleep_time = stat_time;
	this->nic_clock_frequence = nic_clock;
}

Controller::~Controller()
{
	if (this->sfd >= 0)
		close(this->sfd);
	if (this->clean_sfd >= 0)
		close(this->clean_sfd);
	delete this->client;
}

int Controller::setup(const char *start_config_path)
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = handle_sigint;
	if (sigaction(SIGINT, &sa, NULL) == -1) {
		cerr << "ERROR: Cannot change handling of SIGINT signal"
			<< endl;
		return -1;
	}

	/* Socket for dataplane communication */

	this->sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (this->sfd < 0) {
		cerr << "ERROR: Cannot create socket."
			<< " Please execute this program as root" << endl;
		return -1;
	}

	this->clean_sfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
	if (this->clean_sfd < 0) {
		cerr << "ERROR: Cannot create socket."
			<< " Please execute this program as root" << endl;
		return -1;
	}

	memset(&this->socket_dst_address, 0, sizeof(this->socket_dst_address));

	/* Get the index of the interface to send on */
	string ifname;
	if (vfname_check(this->sfd, 1, ifname)) {
		cerr << "Is the rte server up ? "
			<< "If it is, check that there is at least two active VFs. "
			<< "Check NUM_VFS in the config file." << endl;
		return -1;
	}
	struct ifreq if_req;
	memset(&if_req, 0, sizeof(if_req));
	strncpy(if_req.ifr_name, ifname.data(), IFNAMSIZ-1);
	if (ioctl(this->sfd, SIOCGIFINDEX, &if_req) < 0) {
	    perror("SIOCGIFINDEX");
	    return -1;
	}

	this->socket_dst_address.sll_ifindex = if_req.ifr_ifindex;
	this->socket_dst_address.sll_family = AF_PACKET;
	this->socket_dst_address.sll_protocol = htons(ETH_P_ALL);

	/* Get the MAC address of the interface to send on */
	memset(&if_req, 0, sizeof(if_req));
	strncpy(if_req.ifr_name, ifname.data(), IFNAMSIZ-1);
	if (ioctl(this->sfd, SIOCGIFHWADDR, &if_req) < 0) {
		perror("SIOCGIFHWADDR");
		return -1;
	}

	memcpy(this->ether_shost, if_req.ifr_hwaddr.sa_data, 6);

	this->socket_dst_address.sll_halen = ETH_ALEN;
	/* Destination broadcast MAC */
	this->socket_dst_address.sll_addr[0] = 0x00;
	this->socket_dst_address.sll_addr[1] = 0x00;
	this->socket_dst_address.sll_addr[2] = 0x00;
	this->socket_dst_address.sll_addr[3] = 0x00;
	this->socket_dst_address.sll_addr[4] = 0x00;
	this->socket_dst_address.sll_addr[5] = 0x00;


	/* RTE server connection */

	this->transport->open();
	try {
		string ret;
		this->client->sys_ping(ret);
	} catch (TException& tx) {
		this->transport->close();
		cerr << "ERROR: Basic communication with RPC server failed"
			<< endl;
		return -1;
	}

	try {
		// TODO Additional rules can be added afterwards
		if (start_config_path != nullptr) {
			uint32_t max_vfs = vfnumber(this->sfd);
			if (max_vfs < 3) {
				cerr << "Not enough VFs available (less than 3)!" << endl;
				cerr << "Please change RTE server the configuration" << endl;
				return -1;
			}
			if (this->client->design_reconfig(string(start_config_path),
							  this->flows, max_vfs)) {
				cerr << "Cannot load config "
					<< "(see RTE server logs for more details)"
					<< endl;
				return -1;
			}
		}
		if (this->client->info_fetching()) {
			cout << "Cannot find the P4 counters."
				<< " Did you load the right design ?" << endl;
			return -1;
		}
	} catch (TException& tx) {
		this->transport->close();
		cerr << "ERROR: Cannot load configuration rules" << endl;
		return -1;
	}

	return 0;
}

int Controller::run()
{
	int err = 0;

	try {
		auto fut = std::async(std::launch::async,
				      &Controller::cleanup_syn_offloading,
				      this);
		while (!interrupted && !err) {
			this_thread::sleep_for(std::chrono::milliseconds(\
							this->stat_sleep_time));
			if (!this->client->retrieve_stats(this->flows)) {
				if ((err = this->report_stats()))
					cerr << "Cannot report statistics to Bro" << endl;
			} else {
				cerr << "Cannot retrieve flows statistics from NIC" << endl;
			}
		}
		this->transport->close();
	} catch (TException& tx) {
		this->transport->close();
		cerr << "ERROR: " << tx.what() << endl;
		return -1;
	}
	return err;
}

int Controller::report_stats()
{
	if (this->stat_frame.start_frame(this->ether_shost,
					 this->socket_dst_address.sll_addr))
		return -1;

	for (uint64_t i = 0; !interrupted && i < this->flows.size(); i++) {
		if (this->flows[i].produce_stat_headers(this->stat_frame)) {

			this->stat_frame.finish_frame();
			if (this->stat_frame.send_frame(this->sfd,
						&this->socket_dst_address))
				perror("Couldn't send a statistic frame !");

			/* Always succeeds here */
			this->stat_frame.start_frame(this->ether_shost,
					this->socket_dst_address.sll_addr);
			if (this->flows[i].produce_stat_headers(this->stat_frame)) {
				cerr << "MTU is too short even for a single flow !"
					<< endl;
				return -1; /* FIXME Splitting the statistics is a solution */
			}
		}
	}

	this->stat_frame.finish_frame();
	if (this->stat_frame.send_frame(this->sfd, &this->socket_dst_address)) {
		perror("Couldn't send a statistic frame !");
	}


	return 0;
}

int Controller::cleanup_syn_offloading()
{
	int err = 0;
	while (!err && !interrupted) {
		this_thread::sleep_for(std::chrono::milliseconds(this->nic_clock_frequence));
		err = this->clean_frame.send_frame(this->clean_sfd,
						   this->ether_shost,
						   &this->socket_dst_address);
	}
	return err;
}

int main(int argc, char *argv [])
{
	/* TODO  Do real argument parsing */
	Controller ctrl(RPCPORT, STAT_SLEEP_TIME, NIC_CLOCK_FREQUENCE);
	if (ctrl.setup(argc >= 2 ? argv[1] : nullptr)) {
		cerr << "ERROR" << endl;
		return -1;
	}
	int i = ctrl.run();
	return i;
}

