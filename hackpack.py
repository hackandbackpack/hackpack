#!/usr/bin/env python3

import sys
from scapy.all import *
from scapy.contrib.ospf import OSPF_Hdr as OSPF

def main(pcap_file):
    protocols_found = {}
    pcap = rdpcap(pcap_file)

    for packet_num, packet in enumerate(pcap, start=1):
        # Check for CDP (Cisco Discovery Protocol) and STP (Spanning Tree Protocol)
        if packet.haslayer(SNAP):
            if packet[SNAP].OUI == 0x00000c:
                # Check for CDP
                if packet[SNAP].code == 0x2000:
                    protocols_found.setdefault("CDP", []).append(packet_num)
                # Check for STP
                elif packet[SNAP].code == 0x010b:
                    protocols_found.setdefault("STP", []).append(packet_num)

        # Check for HSRP (Hot Standby Router Protocol)
        if packet.haslayer(UDP) and packet[UDP].sport == 1985:
            protocols_found.setdefault("HSRP", []).append(packet_num)

        # Check for EIGRP (Enhanced Interior Gateway Routing Protocol)
        if packet.haslayer(IP) and packet[IP].proto == 88:
            protocols_found.setdefault("EIGRP", []).append(packet_num)

        # Check for OSPF (Open Shortest Path First)
        if packet.haslayer(OSPF):
            protocols_found.setdefault("OSPF", []).append(packet_num)

    if protocols_found:
        print("The following protocols were found in the pcap file:")
        for protocol, packet_nums in protocols_found.items():
            packet_nums_str = ", ".join(map(str, packet_nums[:3]))
            print(f"{protocol}: Found in Packet # - {packet_nums_str}")
    else:
        print("No CDP, HSRP, EIGRP, OSPF, or STP packets were found in the pcap file.")

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <pcap_file>")
        sys.exit(1)

    pcap_file = sys.argv[1]
    main(pcap_file)
