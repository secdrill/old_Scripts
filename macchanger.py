#!/usr/bin/env python3

import subprocess
import argparse
import re

def get_argument():
	parser = argparse.ArgumentParser(prog='machanger.py', description='This program is used to spoof MAC Address')
	parser.add_argument('-i', '--interface', dest='interface', help='Interface Name to change MAC')
	parser.add_argument('-m', '--mac', dest='mac_address', help='New Fake MAC Address')
	args = parser.parse_args()
	if not args.interface:
		parser.error("[-] Please Specify a Interface. use --help for more info")
	elif not args.mac_address:
		parser.error("[-] Please Specify a Mac Address. use --help for more info")
	elif not re.match("(([0-9a-fA-F_]{2})[:-]){5}([0-9a-fA-F_]{2})", args.mac_address):
		parser.error("[-] Please enter correct Mac Address Syntax")
	
	return args
	
def mac_changer(interface, mac_address):
	print("[+] Changing",interface,"Mac Address with", mac_address)
	current_mac = mac_checker(interface)
	subprocess.run(["ifconfig", interface, "down"])
	subprocess.run(["ifconfig", interface, "hw", "ether", mac_address])
	subprocess.run(["ifconfig", interface, "up"])
	
	new_mac = mac_checker(interface)
	if mac_address == new_mac:
		print("[+] Mac Address Changed successfully from ",current_mac,"to",new_mac)
	else:
		print("[-] Failed Please check all parameters")
	
def mac_checker(interface):
	raw_output = subprocess.run(["ifconfig", interface], capture_output=True)
	output = raw_output.stdout.decode('utf-8')
	mac = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", output)
	return mac.group(0)

parse_arg = get_argument()
mac_changer(parse_arg.interface, parse_arg.mac_address)
