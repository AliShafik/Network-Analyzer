import scapy.all as scapy
from scapy.layers.http import HTTPRequest
from collections import Counter
import time

# Dictionary to track bandwidth (Bytes per IP)
stats = Counter()

def process_packet(packet):
    # Bandwidth Stats
    if packet.haslayer(scapy.IP):
        ip_layer = packet.getlayer(scapy.IP)
        stats[ip_layer.src] += len(packet)

    # ARP Spoofing Detection
    if packet.haslayer(scapy.ARP) and packet.getlayer(scapy.ARP).op == 2:
        try:
            # Check the real MAC of the sender
            real_mac = scapy.getmacbyip(packet.getlayer(scapy.ARP).psrc)
            response_mac = packet.getlayer(scapy.ARP).hwsrc
            if real_mac != response_mac:
                print(f"[!] SECURITY ALERT: Possible ARP Spoofing from {packet.getlayer(scapy.ARP).psrc}")
        except:
            pass # Handle cases where lookup fails

    # Credential Exposure=
    if packet.haslayer(HTTPRequest):
        if packet.haslayer(scapy.Raw):
            load = str(packet.getlayer(scapy.Raw).load)
            keywords = ["username", "user", "password", "pass", "login"]
            if any(key in load.lower() for key in keywords):
                print(f"\n[!] ALERT: Sensitive Data in Cleartext: {load}\n")

def print_stats():
    """Periodically prints the top bandwidth consumers."""
    print("\n--- Network Traffic Stats ---")
    for ip, vol in stats.most_common(5):
        print(f"IP: {ip} | Data: {vol} bytes")
    print("-----------------------------\n")

def main():
    print("Sniffer active... Press Ctrl+C to stop.")
    try:
        # Filter captures only IP-based traffic to save CPU
        scapy.sniff(iface=None, store=False, prn=process_packet, filter="ip or arp")
    except KeyboardInterrupt:
        print_stats()

if __name__ == "__main__":
    main()