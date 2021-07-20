#include <net/if.h>
#include <sys/ioctl.h>
#include <cstring>

#include "utils.h"

using namespace std;

#define IFNAME_ROOT string("vf0_")
#define NIC_IFNAME_ROOT string("v0.")


void vfname(uint32_t vfindex, std::string &ifname)
{
	ifname += IFNAME_ROOT;
	ifname += to_string(vfindex);
}

void nic_vfname(uint32_t vfindex, string &nic_ifname)
{
	nic_ifname += NIC_IFNAME_ROOT;
	nic_ifname += to_string(vfindex);
}

int vfname_check(int sfd, uint32_t vfindex, string &ifname)
{
	vfname(vfindex, ifname);

	struct ifreq if_req;
	memset(&if_req, 0, sizeof(if_req));
	strncpy(if_req.ifr_name, ifname.data(), IFNAMSIZ-1);
	if (ioctl(sfd, SIOCGIFINDEX, &if_req) < 0)
		return -1;

	return 0;
}

uint32_t vfnumber(int sfd)
{

	uint32_t i = 0;
	for (;; i++) {
		struct ifreq if_req;
		memset(&if_req, 0, sizeof(if_req));

		string s;
		if (vfname_check(sfd, i, s))
			break;
	}
	return i;
}

/* Compute the negation of the mask that match all numbers below the argument */
uint32_t neg_mask_16(uint32_t value)
{
	uint32_t mask = 1;
	while (value >>= 1) {
		mask = (mask << 1) | 1;
	}
	/* Only on 16 bits */
	return mask & 0x0000FFFF;
}

