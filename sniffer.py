from scapy.all import sniff, IP

def packet_callback(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst

        print("\n--- Packet Captured ---")
        print("Source IP:", src)
        print("Destination IP:", dst)

        with open("log.txt", "a") as f:
            f.write(f"Source: {src} -> Destination: {dst}\n")

print("Starting Network Sniffer... Running...")

sniff(prn=packet_callback, filter="tcp", store=False, count=20)