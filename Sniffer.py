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

                # Host header dhoondhna (HTTP request ka)
                if "Host:" in payload:
                    host_line = [line for line in payload.split('\r\n') if "Host:" in line]
                    if host_line:
                        website = host_line[0].split("Host: ")[1]
                        print("[*] Website Visited:", website)
            except:
                print("Payload could not be decoded.")

# Replace this with your own interface
iface_name = "\\Device\\NPF_{A8B16C33-7E8E-4EBA-8C4D-3FE995669AA3}"

# Only capture 10 packets
sniff(filter="tcp", iface=iface_name, prn=process_packet, store=0, count=10)

