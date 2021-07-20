#ifndef COUNT_REPORT_UTILS_H
#define COUNT_REPORT_UTILS_H

#include <cstdint>
#include <string>


void vfname(uint32_t vfindex, std::string &ifname);
void nic_vfname(uint32_t vfindex, std::string &nic_ifname);

int vfname_check(int sfd, uint32_t vfindex, std::string &ifname);

uint32_t vfnumber(int sfd);

/* Compute the negation of the mask that match all numbers below the argument */
uint32_t neg_mask_16(uint32_t value);

#endif

