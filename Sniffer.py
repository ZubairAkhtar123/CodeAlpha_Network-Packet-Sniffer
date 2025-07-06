from scapy.all import *
from scapy.layers.inet import IP 

def process_packet(packet):
    if packet.haslayer(IP):
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        proto = packet[IP].proto

        print("\n[+] Packet Captured:")
        print("Source IP:", src_ip)
        print("Destination IP:", dst_ip)
        print("Protocol:", proto)

        if packet.haslayer(Raw):
            try:
                payload = packet[Raw].load.decode(errors='ignore')
                print("Payload:\n", payload)
            except:
                print("Payload could not be decoded.")

#Interace name
iface_name = "\\Device\\NPF_{A8B16C33-7E8E-4EBA-8C4D-3FE995669AA3}"  

sniff(filter="ip", iface=iface_name, prn=process_packet, store=0)
