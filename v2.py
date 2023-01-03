from scapy.all import sniff
from scapy.layers.l2 import Ether

def packet_callback(packet):
  src_mac = packet[Ether].src
  dst_mac = packet[Ether].dst
  print("Source MAC:", src_mac)
  print("Destination MAC:", dst_mac)

sniff(iface="wlan0", filter="ip", promisc=True, prn=packet_callback)
