#!/usr/bin/env python3

import scapy.all as scapy

def arp_sweep(IP):
	scapy.arping(IP)
	
arp_sweep("192.168.1.0/24")
