import socket
import struct

# Create a raw socket
raw_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0003))

# Bind the socket to the WiFi interface
raw_socket.bind(("wlan0", 0))

# Set the socket to promiscuous mode
raw_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 2**30)

# Enable promiscuous mode
raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

# Loop indefinitely and capture packets
while True:
    # Receive a packet
    packet = raw_socket.recvfrom(65565)

    # Unpack the packet header
    ethernet_header = packet[0][0:14]
    ethernet_header = struct.unpack("!6s6s2s", ethernet_header)

    # Extract the source and destination MAC addresses
    source_mac = ethernet_header[0]
    dest_mac = ethernet_header[1]
    source_mac = ":".join(["{:02x}".format(ord(ch)) for ch in source_mac])
    dest_mac = ":".join(["{:02x}".format(ord(ch)) for ch in dest_mac])

    # Print the packet information
    print("Source MAC: {}\tDestination MAC: {}".format(source_mac, dest_mac))

# Disable promiscuous mode
raw_socket.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
