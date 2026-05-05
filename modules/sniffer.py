from scapy.all import sniff, TCP, IP, conf

def packet_callback(packet):
    if packet.haslayer(TCP) and packet.haslayer(IP):
        # Detect unencrypted traffic (Telnet: 23, HTTP: 80, FTP: 21)
        if packet[TCP].dport in [23, 80, 21]:
            print(f"[!] ALERT: Unencrypted {packet[TCP].dport} traffic to {packet[IP].dst}")

def start_sniffing(interface=None):
    # If no interface is provided, automatically find the default gateway interface
    if interface is None:
        interface = conf.iface 
    
    print(f"[*] Monitoring traffic on {interface}...")
    try:
        sniff(iface=interface, prn=packet_callback, store=0)
    except Exception as e:
        print(f"Sniffer Error: {e}")
