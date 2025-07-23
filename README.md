# Task_1_network_sniffer

## Description
This project is part of CodeAlpha Cybersecurity Internship(July 2025)
I built a "network packet sniffer" using python's 'socket' module with raw sockets.

The sniffer capture and parses "Ethernet", "IPv4", "ICMP", "TCP" and "UDP" packets from the network interface in real time, displaying structured details and payloads.

## Features
-Raw socket programming in python
-Real-time packet sniffing
-protocol filtering(ICMP, TCP, UDP, ALL)
-Header parsing for IP, TCP, UDP, and ICMP packets
-Custom consol output formatting

## How to Run 
Must ru with "sudo" (admin access required for raw sockets)

''' bash

sudo python3 packet_sniffer_raw_socket.py

##Author
Ledet Tamiru
