import socket
import struct

debug = int(input("Debug Mode? (0/1)"))

#define <remove (the) first two chars> function
def rftc(string):
    return string[2:]

def pad_mac(mystr):
    return mystr.rjust(2, "0")

# Create a raw socket
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

# Bind the socket to the WiFi interface
raw_socket.bind(("wlan0", 0))

# Set the socket to promiscuous mode
raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)

if debug:
    print("Socket in promiscuous mode created")

# Loop indefinitely and capture packets
while True:
    # Receive a packet
    packet = raw_socket.recvfrom(65565)
    
    # Unpack the packet header
    eth_header = struct.unpack("!6s6s2s", packet[0][0:14])
    if debug:
        print("eth_header", eth_header)
    
    #extract, format and print source and header macs
    src_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[1])))))
    dst_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[0])))))
    print("Src MAC:\t", src_mac)
    print("Dst MAC:\t", dst_mac)
    print("Eth Len:\t", eth_header[2])
    
    #print("eth_proto", ethernet_header[2])
    if eth_header[2] == b'\x08\x00':
        #ipv4 packet
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[0][14:34])
        ip_protocol = ip_header[6]
        #print("ip_proto", ip_protocol)
        print("IP Header:\t", ip_header)
        
        #extract, format and print src and dst ip addresses
        src_ip = '.'.join(map(str, ip_header[8]))
        dst_ip = '.'.join(map(str, ip_header[9]))
        print("Src IP:\t", src_ip)
        print("Dst IP:\t", dst_ip)
        
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
        
        #line break between packets
        print("")
        
        if debug:
            print(packet)
