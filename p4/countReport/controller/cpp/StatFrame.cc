#include <arpa/inet.h>
#include <iostream>
#include <string.h>

#include "StatHeader.h"
#include "StatFrame.h"

using namespace std;


int StatFrame::start_frame(void *src_mac, void *dst_mac)
{
	this->len = 0;
	this->ptr = this->sendbuf;

	if (((int) this->get_size_free()) - ((int) sizeof(struct ether_header))
			    - ((int) sizeof(struct stat_shortcut)) < 0) {
		cerr << "Not enough room for a single statistic header" << endl;
		return -1;
	}

	/* Ethernet header */
	struct ether_header *eth = (struct ether_header *) this->ptr;
	memcpy(eth->ether_shost, src_mac, 6);
	memcpy(eth->ether_dhost, dst_mac, 6);
	eth->ether_type = htons(ETH_P_STAT);
	this->len = sizeof(*eth);
	this->ptr = this->sendbuf + this->len;

	/* Statistics shortcut header */
	this->shortcut = (struct stat_shortcut *) this->ptr;
	this->nexthdr = &this->shortcut->tlv.nexthdr;
	this->shortcut->tlv.len = htons(sizeof(struct stat_shortcut)
					- sizeof(struct stat_tlv));
	this->len += sizeof(*shortcut);
	this->ptr = this->sendbuf + this->len;

	return 0;
}

int StatFrame::append_stat_header(unsigned char *header, uint16_t header_len,
				  uint16_t header_type)
{
	if (header_len + sizeof(struct stat_tlv) > this->get_size_free())
		return -1;

	*(this->nexthdr) = header_type;

	memcpy(this->ptr, header, header_len + sizeof(struct stat_tlv));

	this->nexthdr = (uint16_t *) this->ptr;
	this->len += header_len + sizeof(struct stat_tlv);
	this->ptr = this->sendbuf + this->len;

	return 0;
}

void StatFrame::finish_frame()
{
	/* 0x0000 means end of the frame! */
	*(this->nexthdr) = 0;
	/* FIXME Assumption: the MTU is always below 2^16
	 * => No need for more than one shortcut inside a single frame.
	 */
	this->shortcut->len_short = htons(this->len - sizeof(struct stat_tlv)
						- sizeof(struct ether_header));
	this->shortcut->nexthdr_short = htons(NONE_STNXT);
}

int StatFrame::send_frame(int sfd, struct sockaddr_ll *socket_address) const
{
	return sendto(sfd, this->sendbuf, this->len, 0,
		      (struct sockaddr*) socket_address,
		      sizeof(struct sockaddr_ll)) < 0;
}

