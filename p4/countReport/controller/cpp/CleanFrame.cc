#include <arpa/inet.h>
#include <cstring>

#include "CleanFrame.h"

int CleanFrame::send_frame(int sfd, void *src_mac,
			   struct sockaddr_ll *socket_address)
{
	struct ether_header *eth = (struct ether_header *) this->sendbuf;
	memcpy(eth->ether_shost, src_mac, 6);
	memcpy(eth->ether_dhost, socket_address->sll_addr, 6);

	return sendto(sfd, this->sendbuf, this->size, 0,
		      (struct sockaddr*) socket_address,
		      sizeof(struct sockaddr_ll)) < 0;
}

