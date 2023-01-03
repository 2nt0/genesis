from scapy.all import sniff
from scapy.layers.l2 import Ether

def packet_callback(packet):
  src_mac = packet[Ether].src
  dst_mac = packet[Ether].dst
  print("Src MAC:\t", src_mac)
  print("Dst MAC:\t", dst_mac)
  print("")

sniff(iface="wlan0", filter="ip", promisc=True, prn=packet_callback)
