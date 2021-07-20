#!/bin/python

from scapy.all import *
import sys
import time


IFACE = "vf0_0"
pktcnt = 0

if len(sys.argv) < 2 or "stats" in sys.argv:
    while pktcnt < 5:
        pktcnt += 1
        if pktcnt == 0:
            pkt = Ether()/IP()/TCP(sport=1025, dport=80, flags='A')
        elif pktcnt == 1:
            pkt = Ether()/IP()/TCP(sport=80, dport=1024, flags='A')
        elif pktcnt == 2:
            pkt = Ether()/IP()/TCP(sport=1025, dport=22, flags='A')
        elif pktcnt == 3:
            pkt = Ether()/IP()/TCP(sport=22, dport=1024, flags='A')
        else:
            pkt = Ether()/IP()/TCP(sport=1025, dport=1024, flags='A')
        sendp(pkt, iface=IFACE)
        time.sleep(3)

if len(sys.argv) < 2 or "syn_offloading" in sys.argv:
    c_seq = 1000
    s_seq = 2000
    msg = "TEST"

    # 2 handshakes at the same time
    sendp(Ether()/IP()/TCP(sport=6020, dport=443, flags='S', seq=c_seq), iface=IFACE)
    time.sleep(1)

    # Interleaved handshake
    sendp(Ether()/IP()/TCP(sport=1040, dport=443, flags='S', seq=c_seq), iface=IFACE)
    time.sleep(1)
    sendp(Ether()/IP()/TCP(sport=443, dport=1040, flags='SA', seq=s_seq), iface=IFACE)
    time.sleep(1)

    # Remaining of the first handshake
    sendp(Ether()/IP()/TCP(sport=443, dport=6020, flags='SA', seq=s_seq), iface=IFACE)
    time.sleep(1)
    sendp(Ether()/IP()/TCP(sport=6020, dport=443, flags='A', seq=c_seq + 1, ack=s_seq + 1), iface=IFACE)

    # Data exchange for the first connection
    sendp(Ether()/IP()/TCP(sport=6020, dport=443, flags='A', seq=c_seq + 1, ack=s_seq + 1)/msg, iface=IFACE)
    sendp(Ether()/IP()/TCP(sport=6020, dport=443, flags='RA', seq=c_seq + 1 + len(msg), ack=s_seq + 1), iface=IFACE)

    # Third handshake with a too long RTT => state should be cleaned and SYN+ACK without Reserved bit set
    sendp(Ether()/IP()/TCP(sport=6050, dport=443, flags='S', seq=c_seq), iface=IFACE)
    time.sleep(7)
    sendp(Ether()/IP()/TCP(sport=443, dport=6050, flags='SA', seq=s_seq), iface=IFACE)

