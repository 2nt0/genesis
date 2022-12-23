import socket
import struct

#define <take the last two chars> function
def tltc(string):
        return string[-2:]

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
    
    #extract, format and print source and header macs
    source_mac = ":".join(map(tltc, map(hex, map(int, ethernet_header[0])))).upper()
    dest_mac = ":".join(map(tltc, map(hex, map(int, ethernet_header[1])))).upper() 
    print("\nSource MAC: {}\tDestination MAC: {}".format(source_mac, dest_mac))
    
    print("eth_proto", ethernet_header[2])
    if ethernet_header[2] == b'\x08\x00':
        #ipv4 packet
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[0][14:34])
        ip_protocol = ip_header[6]
        print("ip_proto", ip_protocol)
        print("IP header data:  ", ip_header)
        
        #extract, format and print src and dst ip addresses
        ip_src = '.'.join(map(str, ip_header[8]))
        ip_dst = '.'.join(map(str, ip_header[9]))
        print("\nSource IP: {}\tDestination IP: {}".format(ip_src, ip_dst))
        
        if ip_protocol == 6:
            # TCP packet
            tcp_header = struct.unpack("!2s2s16s", packet[34:54])
            tcp_data = packet[54:]

            # Print the payload data
            print("TCP header data: ", tcp_header)
            print("TCP payload data:", tcp_data)
        elif ip_protocol == 17:
            # UDP packet
            udp_header = struct.unpack("!4s4s", packet[34:42])
            udp_data = packet[42:]

            # Print the payload data
            print("UDP header data: ", udp_header)
            print("UDP payload data:", udp_data)
    print(packet)
