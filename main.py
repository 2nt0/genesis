import socket
import struct

debug = int(input("Debug mode? (0/1)"))
logging = int(input("Log output? (0/1)"))

if logging:
    log_blank = int(input("Log blank payloads? (0/1)"))
    print_verbose = int(input("Print all details? (0/1)"))
else:
    log_blank = 0
    print_verbose = 1
    if debug:
        print("Assuming print_verbose = 1 and log_blank = 0")

def rftc(string): #define <remove first two chars> function
    return string[2:]

def pad_mac(mystr): # define <pad mac address to 2 hex chars per section> function
    return mystr.rjust(2, "0")

raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) # Create a raw socket
raw_socket.bind(("wlan0", 0)) # Bind the socket to the WiFi interface
raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30) # Set the socket to promiscuous mode

if debug:
    print("Socket in promiscuous mode created")

while True: # Loop indefinitely and capture packets
    packet = raw_socket.recvfrom(65535) # Receive a packet
    
    eth_header = struct.unpack("!6s6s2s", packet[0][0:14]) # Unpack the packet header
    if debug:
        print("eth_header", eth_header)
    
    #extract, format and print source and header macs
    src_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[1])))))
    dst_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[0])))))
    print("Src MAC:\t", src_mac)
    print("Dst MAC:\t", dst_mac)
    print("Eth Len:\t", eth_header[2])
    
    if debug:
        print("eth_proto", eth_header[2])
    
    if eth_header[2] == b'\x08\x00': #ipv4 packet
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[0][14:34])
        ip_protocol = ip_header[6]
        
        if debug:
            print("ip_proto", ip_protocol)
        
        print("IP Header:\t", ip_header)
        
        #extract, format and print src and dst ip addresses
        src_ip = '.'.join(map(str, ip_header[8]))
        dst_ip = '.'.join(map(str, ip_header[9]))
        print("Src IP:\t\t", src_ip)
        print("Dst IP:\t\t", dst_ip)
        
        tcp_data = b''
        udp_data = b''
        
        if ip_protocol == 6: # TCP packet
            print("TCP PACKET")
            tcp_header = struct.unpack("!HHIIBBHHH", packet[0][34:54])
            tcp_data = packet[0][54:]
            
            def tcp_log(): # probably a better way to do this, including the <print_verbose> part with lists but cba
                open("genesis.log", "w").write("\nSrc Port:\t" + str(tcp_header[0]))
                open("genesis.log", "w").write("\nDst Port:\t" + str(tcp_header[1]))
                open("genesis.log", "w").write("\nSeq Num:\t" + str(tcp_header[2]))
                open("genesis.log", "w").write("\nACK Num:\t" + str(tcp_header[3]))
                open("genesis.log", "w").write("\nDOs Rsv NS:\t" + str(tcp_header[4]))
                open("genesis.log", "w").write("\nOth. Flags:\t" + str(tcp_header[5]))
                open("genesis.log", "w").write("\nWin Size:\t" + str(tcp_header[6]))
                open("genesis.log", "w").write("\nTCP Hash:\t" + str(tcp_header[7]))
                open("genesis.log", "w").write("\nURG pnt:\t" + str(tcp_header[8]))
                open("genesis.log", "w").write("\nTCP Payload:\t" + str(tcp_data))
            
            if logging:
                if log_blank:
                    tcp_log()
                elif tcp_data != b'':
                    tcp_log()
            
            if print_verbose:
                print("Src Port:\t", tcp_header[0])
                print("Dst Port:\t", tcp_header[1])
                print("Seq Num:\t", tcp_header[2]) # sequence number (dual role, check wikipedia)
                print("ACK Num:\t", tcp_header[3]) # acknowledgement number (if ACK set)
                print("DOs Rsv NS:\t", tcp_header[4]) # (bits) Data offset (3), <reserved 000> (3), NS flag (1)
                print("Oth. Flags:\t", tcp_header[5]) # bitwise: CWR, ECE (SYN-dependant), URG, ACK, PSH, RST, SYN, FIN
                print("Win Size:\t", tcp_header[6]) # window size
                print("TCP Hash:\t", tcp_header[7]) # checksum
                print("URG Pnt:\t", tcp_header[8]) # URGENT pointer (if URG set)
                print("TCP Payload:\t", tcp_data) # Print the payload data
            
        elif ip_protocol == 17: # UDP packet
            print("UDP PACKET")
            udp_header = struct.unpack("!HHHH", packet[0][34:42])
            udp_data = packet[0][42:]
            
            def udp_log(): # probably a better way to do this, including the <print_verbose> part with lists but cba
                open("genesis.log", "wb").write("\nSrc Port:\t" + str(udp_header[0]))
                open("genesis.log", "wb").write("\nDst Port:\t" + str(udp_header[1]))
                open("genesis.log", "wb").write("\nUDP Length:\t" + str(udp_header[2]))
                open("genesis.log", "wb").write("\nUDP Hash:\t" + str(udp_header[3]))
                open("genesis.log", "wb").write("\nUDP Payload:\t" + str(udp_data))
            
            if logging:
                if log_blank:
                    udp_log()
                elif udp_data != b'':
                    udp_log()
            
            if print_verbose:
                print("Src Port:\t", udp_header[0])
                print("Dst Port:\t", udp_header[1])
                print("UDP Length:\t", udp_header[2])
                print("UDP Hash:\t", udp_header[3]) # checksum
                print("UDP Payload:\t", udp_data) # Print the payload data
        
        if logging:
            if log_blank:
                    open("genesis.log", "wb").write("\nExtra Data:\t", packet[1])
            elif tdp_data != b'' or tcp_data != b'':
                    open("genesis.log", "wb").write("\nExtra Data:\t", packet[1])
        if print_verbose:
            print("Extra Data:\t", packet[1])
        
        if logging:
            open("genesis.log", "w").write("\n") #write blank line to log file between packets
        
        if debug:
            print(packet)
        
        print("") #line break between packets
