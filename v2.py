from scapy.all import sniff
print("imported scapy")

def packet_callback(packet):
  src_mac = packet[Ether].src
  dst_mac = packet[Ether].dst
  print("Source MAC:", src_mac)
  print("Destination MAC:", dst_mac)

print("defined pack cb")

sniff(iface="wlan0", filter="ip", promisc=True, prn=packet_callback)
