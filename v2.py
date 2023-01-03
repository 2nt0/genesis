from scapy.all import sniff

def packet_callback(packet):
  print(packet.show())

sniff(iface="eth0", filter="ip", promisc=True, prn=packet_callback)
