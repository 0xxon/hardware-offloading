#ifndef CLEANFRAME_H
#define CLEANFRAME_H

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define CLEAN_CMD_LEN 26 // Just a ethernet frame
#define CLEAN_CMD 0x8901


class CleanFrame
{
public:
	CleanFrame()
	{
		this->size = CLEAN_CMD_LEN;
		this->sendbuf = new unsigned char [this->size];

		struct ether_header *et = (struct ether_header *) this->sendbuf;
		et->ether_type = htons(CLEAN_CMD);
	}
	~CleanFrame()
	{
		delete[] this->sendbuf;
	}
	int send_frame(int sfd, void *src_mac,
		       struct sockaddr_ll *socket_address);
private:
	size_t size;
	unsigned char *sendbuf;
};

#endif

