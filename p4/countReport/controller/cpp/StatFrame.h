#ifndef STATFRAME_H
#define STATFRAME_H

#include <sys/socket.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

#define MTU 1500


class StatFrame
{
public:
	StatFrame()
	{
		this->len = 0;
		this->size = MTU;
		this->sendbuf = new unsigned char [this->size];
		this->ptr = this->sendbuf;
		this->nexthdr = nullptr;
		this->shortcut = nullptr;
	}
	~StatFrame()
	{
		delete[] this->sendbuf;
	}
	int start_frame(void *src_mac, void *dst_mac);
	/* header_len is the length of the value of the statistic header
	 * (i.e., nxthdr and length fields excluded)
	 */
	int append_stat_header(unsigned char *header, uint16_t header_len,
			       uint16_t header_type);
	void finish_frame();
	int send_frame(int sfd, struct sockaddr_ll *socket_address) const;
	size_t get_size_free() const
	{
		if (this->len > this->size)
			return 0;
		return this->size - this->len;
	}
private:
	size_t len;
	size_t size;
	unsigned char *sendbuf;
	unsigned char *ptr;
	uint16_t *nexthdr;
	struct stat_shortcut *shortcut;
};

#endif

