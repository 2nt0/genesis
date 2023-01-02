import socket
import struct

def rftc(string): #define <remove first two chars> function
    return string[2:]

def pad_mac(mystr): # define <pad mac address to 2 hex chars per section> function
    return mystr.rjust(2, "0")

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
    
    eth_header = struct.unpack("!6s6s2s", packet[0][0:14]) # format the packet header into a tuple
    
    #extract, format and print source and header macs
    src_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[1])))))
    dst_mac = ":".join(map(pad_mac, map(rftc, map(hex, map(int, eth_header[0])))))
    
    #determine whether 2s from eth_header is length or protocol; set each variable accordingly
    #NOTE: IF 1500 < eth_header[2] < 1536, LEN OR PROTO IS UNDEFINED (AS DEFINED BY IEEE Std 802.3-2005, 3.2.6) AND BOTH RETURN None
    eth_len = None
    eth_proto = None
    
    lop = int.from_bytes(eth_header[2], "big") #stands for "length or protocol"
    if lop <= 1500:
        eth_len = lop
    elif lop >= 1536:
        eth_proto = lop
    
    #set lists to print and/or log
    log_list = ["", "Src MAC:\t"+src_mac, "Dst MAC:\t"+dst_mac] # legacy gen_log_def
    if debug >= 1:
        log_list += [] # legacy gen_log_main
    if debug >= 2:
        log_list += ["Eth Length:\t"+str(eth_len), "Eth Protocol:\t"+str(eth_proto), "Extra Data:\t"+str(packet[1])] # eth protocol 2048 is ipv4; 34525 is ipv6, legacy gen_log_debug
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
        ip_header = struct.unpack('!BBHHHBBH4s4s', packet[0][14:34])
        ip_proto = ip_header[6]
        
        #extract, format and print src and dst ip addresses
        src_ip = '.'.join(map(str, ip_header[8]))
        dst_ip = '.'.join(map(str, ip_header[9]))
        
        #set lists to print and/or log
        log_list = ["Src IP:\t\t"+src_ip, "Dst IP:\t\t"+dst_ip] # legacy ipv4_log_def
        if debug >= 1:
            log_list += [] # legacy ipv4_log_main
        if debug >= 2:
            log_list += ["IP Protocol:\t"+str(ip_proto)] # ip protocol 6 is tcp, 17 is udp, legacy ipv4_log_debug
        if debug >= 3:
            log_list += ["IP Header:\t"+str(ip_header)] # legacy ipv4_log_dev
        
        #print/log what the user wants to be printed/logged
        if logging:
            for i in log_list:
                open("genesis.log",  "a").write("\n"+i)
        if print_verbose:
            for i in log_list:
                print(i)
        
        tcp_data = b''
        udp_data = b''
        
        if ip_header[6] == 6: # TCP packet
            tcp_header = struct.unpack("!HHIIBBHHH", packet[0][34:54])
            tcp_data = packet[0][54:]
            
            #set lists to print and/or log
            log_list = [] # legacy tcp_log_def
            if debug >= 1:
                log_list += ["Src Port:\t"+str(tcp_header[0]), "Dst Port:\t"+str(tcp_header[1]), "Seq Num:\t"+str(tcp_header[2]), "TCP Payload:\t"+str(tcp_data)] # legacy tcp_log_main
            if debug >= 2:
                log_list += ["TCP PACKET", "ACK Num:\t"+str(tcp_header[3]), "DOs Rsv NS:\t"+str(tcp_header[4]), "Oth. Flags:\t"+str(tcp_header[5]), "Win Size:\t"+str(tcp_header[6]), "TCP Hash:\t"+str(tcp_header[7]), "URG pnt:\t"+str(tcp_header[8])] # legacy tcp_log_debug
            if debug >= 3:
                log_list += ["TCP Packet:\t"+str(packet[0][34:])] # legacy tcp_log_debug
            # seq num: sequence number (dual role, check wikipedia); ACK Num: acknowledgement number (if ACK set); DOs Rsv NS: # (bits) Data offset (3), <reserved 000> (3), NS flag (1); Oth. Flags (bitwise): CWR, ECE (SYN-dependant), URG, ACK, PSH, RST, SYN, FIN; Win Size: Window size; TCP Hash: checksum; URG Pnt: URGENT pointer (if URG set)
    
            #print/log what the user wants to be printed/logged
            if logging:
                for i in log_list:
                    open("genesis.log",  "a").write("\n"+i)
            if print_verbose:
                for i in log_list:
                    print(i)
            
        elif ip_header[6] == 17: # UDP packet
            udp_header = struct.unpack("!HHHH", packet[0][34:42])
            udp_data = packet[0][42:]
            
            #set lists to print and/or log
            log_list = [] # User Datagram Protocol does not provide IP addresses, legacy udp_log_def
            if debug >= 1:
                log_list += ["Src Port:\t"+str(udp_header[0]), "Dst Port:\t" + str(udp_header[1]), "UDP Payload:\t" + str(udp_data)] # legacy udp_log_main
            if debug >= 2:
                log_list += ["UDP PACKET", "UDP Hash:\t" + str(udp_header[3]), "UDP Length:\t" + str(udp_header[2])] # legacy udp_log_debug
            if debug >= 3:
                log_list += ["UDP Packet:\t"+str(packet[0][42:])] # legacy udp_log_dev
            
            #print/log udp log lists
            if logging:
                for i in log_list:
                    open("genesis.log",  "a").write("\n"+i)
            if print_verbose:
                for i in log_list:
                    print(i)
    
    elif eth_proto == 34525: #ipv6 packet
        pass
