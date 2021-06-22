#!/usr/bin/env python3

import scapy.all as scapy
import argparse

def argument_parser():
	parser = argparse.ArgumentParser(prog="netdiscover", description='Host Discovering tool. its use ARP')
	parser.add_argument('-t', '--target', dest='IP', help='Enter IP or Range of IP using /8 /16 /24')
	args = parser.parse_args()
	if not args.IP:
		parser.error("[-] No IP or IP Range Provided\nuse -h for more Information")
	return args
	
def arp_scanner(IP):
	# scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=IP ARP_REQUEST
	ans, unans = scapy.srp(scapy.Ether(dst="ff:ff:ff:ff:ff:ff")/scapy.ARP(pdst=IP), verbose=False, timeout=5)
	if not ans:
		print("\nAll Host are close from IP", IP,"\n")
		exit()
	result_list = []
	for element in ans:
		result_dict = {"ip":element[1].psrc, "mac":element[1].hwsrc}
		result_list.append(result_dict)

	return result_list
		
def result_printer(scanner_result):	
	print("-----------------------------------------\n    IP\t\tMAC Address\n-----------------------------------------")
	for print_result in scanner_result:
		print(print_result["ip"]," | ",print_result["mac"])
	print("-----------------------------------------\n")
		
		
target = argument_parser()
arp_scanner_result = arp_scanner(target.IP)
result_printer(arp_scanner_result)

