from scapy.all import sniff
print("imported scapy")

def packet_callback(packet):
  print(packet.show())

print("defined pack cb")

sniff(iface="wlan0", filter="ip", promisc=True, prn=packet_callback)
