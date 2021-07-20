#!/bin/python

import time
from scapy.all import *


pktcnt = 0

while pktcnt < 6:
    if pktcnt == 0 or pktcnt == 1:
        pkt = Ether()/IP()/TCP(sport=532, dport=80)
    elif pktcnt >= 2 and pktcnt <= 4:
        pkt = Ether()/IP()/TCP(sport=80, dport=256)
    else:
        pkt = Ether()/IP()/TCP(sport=1, dport=443)

    sendp(pkt, iface="vf0_0")

    pktcnt += 1
    time.sleep(1)

