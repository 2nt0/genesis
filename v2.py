import socket
import struct

# Create a raw socket
sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

# Bind the socket to the wireless interface
sock.bind(("wlan0", 0))

# Set the socket to promiscuous mode
sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)

# Start sniffing packets
while True:
    # Receive a packet
    packet, addr = sock.recvfrom(65565)

    # Parse the packet
    eth_header = packet[:14]
    eth_header = struct.unpack("!6s6s2s", eth_header)
    eth_protocol = socket.ntohs(eth_header[2])

    # Print the packet
    print("Packet:", packet)
    print("Protocol:", eth_protocol)
