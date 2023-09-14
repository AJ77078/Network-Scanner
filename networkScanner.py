#!/usr/bin/python3

import scapy.all as scapy
import argparse

def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t","--target", dest="target",help="Target IP/ IP range")
    options = parser.parse_args()
    return options

def scan(ip):
    # Below function is used to list all the parameters for ARP() object
    # scapy.ls(scapy.ARP())
    # scapy.arping(ip) scans the network and returns the MAC address mapped with ip address
    # arp_request.summary() returns the summary of ARP request
    # scapy.ls(scapy.ARP()) returns the fields we can set of ARP object

    arp_request = scapy.ARP(pdst=ip)
    #arp_request.show()
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for element in answered_list:
        clients_dict = {"ip":element[1].psrc,"mac":element[1].hwsrc}
        clients_list.append(clients_dict)
        #print(element[1].psrc+"\t\t"+element[1].hwsrc)
    return clients_list

def print_result(results_list):
    print("IP\t\t\tMAC Address\n-------------------------------------------")
    for client in results_list:
        print(client["ip"]+"\t\t"+client["mac"])

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)