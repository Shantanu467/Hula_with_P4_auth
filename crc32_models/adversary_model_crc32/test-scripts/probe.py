#!/usr/bin/env python3
import argparse
import sys
import socket
import random
import struct
import time

from scapy.all import sendp, send, get_if_list, get_if_hwaddr, bind_layers
from scapy.all import Packet, BitField, Raw
from scapy.all import Ether, IP, UDP, TCP

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

class Hula(Packet):
    fields_desc = [ BitField("dst_tor", 0x00, 24),
                   BitField("path_util", 0x00, 8),
                   BitField("digest",0,32)]

bind_layers(IP, Hula, proto=0x42)

def main():

    iface = get_if()
    hw_if = get_if_hwaddr(iface)

    print("sending probe on interface %s." % (iface))
    pkt =  Ether(src=hw_if, dst='ff:ff:ff:ff:ff:ff')
    pkt = pkt / IP(dst="224.0.0.1", proto=66)

    dt = int(pkt[IP].src.split(".")[2])
    print("dt : ",dt)
    print("packet ip source : ", pkt[IP].src)
    pkt = pkt / Hula(dst_tor=dt, path_util=255,digest=0)
    pkt = pkt / Raw("probe packet")

    # Keep sending probes
    while True:
        print(pkt.show(dump=True))
        sendp(pkt, iface=iface, verbose=False)
        time.sleep(0.05)


if __name__ == '__main__':
    main()
