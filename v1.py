import socket
import struct

# Create a raw socket
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

# Bind the socket to the WiFi interface
raw_socket.bind(("wlan0", 0))

# Set the socket to promiscuous mode
raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)

# Loop indefinitely and capture packets
while True:
    # Receive a packet
    packet = raw_socket.recvfrom(65565)

    # Unpack the packet header
    ethernet_header = packet[0][0:14]
    ethernet_header = struct.unpack("!6s6s2s", ethernet_header)
    eth_protocol = socket.ntohs(ethernet_header[2])
    
    # Extract the source and destination MAC addresses
    source_mac = ethernet_header[0]
    dest_mac = ethernet_header[1]
    
    # Print the packet information
    print("\nSource MAC: {}\tDestination MAC: {}".format(source_mac, dest_mac))
    
    # Extract the payload data based on the protocol
    if eth_protocol == 8:
        # IPv4 packet
        ip_header = packet[14:34]
        ip_header = struct.unpack("!12s4s4s", ip_header)
        ip_protocol = ip_header[2]

        if ip_protocol == 6:
            # TCP packet
            tcp_header = packet[34:54]
            tcp_header = struct.unpack("!2s2s16s", tcp_header)
            tcp_data = packet[54:]

            # Print the payload data
            print("TCP payload data:", tcp_data)
        elif ip_protocol == 17:
            # UDP packet
            udp_header = packet[34:42]
            udp_header = struct.unpack("!4s4s", udp_header)
            udp_data = packet[42:]

            # Print the payload data
            print("UDP payload data:", udp_data)
