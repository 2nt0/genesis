# TODO:
# add ARP parsing (if eth_proto == 2054)
# add system launch options (eg main.py -d 3 -l 0 -p 1)

import socket
import struct

def rftc(string): #define <remove first two chars> function
    return string[2:]

def pad_mac(string): # define <pad mac address to 2 hex chars per section> function
    return string.rjust(2, "0")

def parse_ip_data(ip_data, ip_proto, logging, print_verbose):
    if ip_proto == 6: # TCP packet
        tcp_header = struct.unpack("!HHIIBBHHH", ip_data[:20])
        tcp_data = ip_data[20:]

        #set lists to print and/or log
        log_list = [] # legacy tcp_log_def
        if debug >= 1:
            log_list += ["Src Port:\t"+str(tcp_header[0]), "Dst Port:\t"+str(tcp_header[1])] # legacy tcp_log_main
        if debug >= 2:
            log_list += ["TCP Payload:\t"+str(tcp_data), "Seq Num:\t"+str(tcp_header[2])] # legacy tcp_log_debug
        if debug >= 3:
            log_list += ["TCP Header:\t"+str(tcp_header)] # legacy tcp_log_dev
        # seq num: sequence number (dual role, check wikipedia)

        #print/log what the user wants to be printed/logged
        if logging:
            for i in log_list:
                open("genesis.log",  "a").write("\n"+i)
        if print_verbose:
            for i in log_list:
                print(i)

    elif ip_proto == 17: # UDP packet
        udp_header = struct.unpack("!HHHH", ip_data[:8])
        udp_data = ip_data[8:]

        #set lists to print and/or log
        log_list = [] # legacy udp_log_def
        if debug >= 1:
            log_list += ["Src Port:\t"+str(udp_header[0]), "Dst Port:\t" + str(udp_header[1])] # legacy udp_log_main
        if debug >= 2:
            log_list += ["UDP Payload:\t" + str(udp_data)] # legacy udp_log_debug
        if debug >= 3:
            log_list += ["UDP Header:\t"+str(udp_header)] # legacy udp_log_dev

        #print/log udp log lists
        if logging:
            for i in log_list:
                open("genesis.log",  "a").write("\n"+i)
        if print_verbose:
            for i in log_list:
                print(i)

    else:
        open("genesis_ip_proto.log",  "a").write(str(ip_proto)+"\n")

debug = input("How much detail to output? (0/1/2/3)")
while not(debug in ["0", "1", "2", "3"]):
    print("Please enter a number: 0, 1, 2 or 3")
    debug = input("How much detail to output? (0/1/2/3)")
debug = int(debug)

logging = input("Log output? (0/1)")
while not(logging in ["0", "1"]):
    print("Please enter a number: 0, 1")
    logging = input("Log output? (0/1)")
logging = int(logging)

print_verbose = input("Print output? (0/1)")
while not(print_verbose in ["0", "1"]):
      print("Please enter a number: 0, 1")
      print_verbose = input("Print output? (0/1)")
print_verbose = int(print_verbose)

raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003)) # Create a raw socket
raw_socket.bind(("wlan0", 0)) # Bind the socket to the WiFi interface
raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30) # Set the socket to promiscuous mode

if debug:
    print("Socket in promiscuous mode created")

while True: # Loop indefinitely and capture packets
    packet = raw_socket.recvfrom(65535) # Receive a packet
    
    eth_header = struct.unpack("!6s6sH", packet[0][:14]) # format the packet header into a tuple
    eth_data = packet[0][14:]
    
    #extract, format and print source and header macs
    src_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[1])))))
    dst_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[0])))))
    
    #determine whether 2s from eth_header is length or protocol; set each variable accordingly
    #NOTE: IF 1500 < eth_header[2] < 1536, LEN OR PROTO IS UNDEFINED (AS DEFINED BY IEEE Std 802.3-2005, 3.2.6) AND BOTH RETURN None
    eth_len = None
    eth_proto = None
    
    lop = eth_header[2] #stands for "length or protocol"
    if lop <= 1500:
        eth_len = lop
    elif lop >= 1536:
        eth_proto = lop
    
    #set lists to print and/or log
    log_list = ["", "Src MAC:\t"+src_mac, "Dst MAC:\t"+dst_mac] # legacy gen_log_def
    if debug >= 1:
        log_list += ["Eth Protocol:\t"+str(eth_proto)] # legacy gen_log_main
    if debug >= 2:
        log_list += ["Extra Data:\t"+str(packet[1])] # eth protocol 2048 is ipv4; 34525 is ipv6, legacy gen_log_debug
    if debug >= 3:
        log_list += ["Eth Header:\t"+str(eth_header)] # legacy gen_log_dev
    
    #print/log what the user wants to be printed/logged
    if logging:
        for i in log_list:
            open("genesis.log",  "a").write("\n"+i)
    if print_verbose:
        for i in log_list:
            print(i)
    
    
    if eth_proto == 2048: #ipv4 packet
        ihl = int.from_bytes(eth_data[0], "big") - 64 # ipv4 header length in number of quad-octets
        ip_header = struct.unpack('!BBHHHBBH4s4s'+str(ihl-5)+"s", eth_data[:4*ihl])
        ip_data = eth_data[4*ihl:]
        ip_proto = ip_header[6]
        
        #extract, format and print src and dst ip addresses
        src_ip = '.'.join(map(str, ip_header[8]))
        dst_ip = '.'.join(map(str, ip_header[9]))
        
        #set lists to print and/or log
        log_list = ["Src IPv4:\t\t"+src_ip, "Dst IPv4:\t\t"+dst_ip] # legacy ipv4_log_def
        if debug >= 1:
            log_list += ["IPv4 Protocol:\t"+str(ip_proto)] # legacy ipv4_log_main
        if debug >= 2:
            log_list += [] # ip protocol 6 is tcp, 17 is udp, legacy ipv4_log_debug
        if debug >= 3:
            log_list += ["IPv4 Header:\t"+str(ip_header)] # legacy ipv4_log_dev
        
        #print/log what the user wants to be printed/logged
        if logging:
            for i in log_list:
                open("genesis.log",  "a").write("\n"+i)
        if print_verbose:
            for i in log_list:
                print(i)
        
        parse_ip_data(ip_data, ip_proto, logging, print_verbose)
        
        
    elif eth_proto == 34525: #ipv6 packet
        ip_header = struct.unpack('!IHBB16s16s', eth_data[:40])
        ip_data = eth_data[40:]
        ip_proto = ip_header[2]
        
        #extract, format and print src and dst ip addresses
        src_ip = ':'.join(map(str, ip_header[4]))
        dst_ip = ':'.join(map(str, ip_header[5]))
        
        #set lists to print and/or log
        log_list = ["Src IPv6:\t\t"+src_ip, "Dst IPv6:\t\t"+dst_ip] # legacy ipv4_log_def
        if debug >= 1:
            log_list += ["IPv6 Protocol:\t"+str(ip_proto)] # legacy ipv4_log_main
        if debug >= 2:
            log_list += [] # ip protocol 6 is tcp, 17 is udp, legacy ipv4_log_debug
        if debug >= 3:
            log_list += ["IPv6 Header:\t"+str(ip_header)] # legacy ipv4_log_dev
        
        #print/log what the user wants to be printed/logged
        if logging:
            for i in log_list:
                open("genesis.log",  "a").write("\n"+i)
        if print_verbose:
            for i in log_list:
                print(i)
        
        parse_ip_data(ip_data, ip_proto, logging, print_verbose)
        
    elif eth_proto == 2054: # ARP packet
        pass
    
    else:
        if debug >= 3:
            open("genesis_eth_proto.log",  "a").write(str(lop)+"\n")
