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
    source_mac = ":".join(map(tltc, map(hex, map(int, ethernet_header[1])))).upper()
    dest_mac = ":".join(map(tltc, map(hex, map(int, ethernet_header[0])))).upper() 
    print("\nSrc MAC:\t{}\nDst MAC:\t{}".format(source_mac, dest_mac))
    print("Length:\t", ethernet_header[2])
    
    #print("eth_proto", ethernet_header[2])
    if ethernet_header[2] == b'\x08\x00':
        #ipv4 packet
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[0][14:34])
        ip_protocol = ip_header[6]
        #print("ip_proto", ip_protocol)
        print("IP Header:\t", ip_header)
        
        #extract, format and print src and dst ip addresses
        ip_src = '.'.join(map(str, ip_header[8]))
        ip_dst = '.'.join(map(str, ip_header[9]))
        print("Src IP:\t{}\nDst IP:\t{}".format(ip_src, ip_dst))
        
        if ip_protocol == 6:
            # TCP packet
            print("TCP PACKET")
            tcp_header = struct.unpack("!HHIIBBHHH", packet[0][34:54])
            print("Src Port:\t", tcp_header[0])
            print("Dst Port:\t", tcp_header[1])
            print("Seq Num:\t", tcp_header[2])
            print("ACK Num:\t", tcp_header[3])
            print("DOs Rsv NS:\t", tcp_header[4])
            print("Oth. Flags:\t", tcp_header[5])
            print("Win Size:\t", tcp_header[6])
            print("TCP Hash:\t", tcp_header[7])
            print("URG pnt:\t", tcp_header[8])
            tcp_data = packet[0][54:]

            # Print the payload data
            print("TCP Payload:", tcp_data)
        elif ip_protocol == 17:
            # UDP packet
            print("UDP PACKET")
            udp_header = struct.unpack("!HHHH", packet[0][34:42])
            print("Src Port:\t", udp_header[0])
            print("Dst Port:\t", udp_header[1])
            print("UDP Length:\t", udp_header[2])
            print("UDP Hash:\t", udp_header[3])
            udp_data = packet[0][42:]

            # Print the payload data
            print("UDP Payload:\t", udp_data)
        print("Extra Data:\t", packet[1]) 
