from scapy.all import sniff, IP, TCP

class TrafficInspector:
    def __init__(self):
        self.insecure_ports = {21: "FTP", 23: "Telnet", 80: "HTTP"}
        self.detected_risks = []

    def packet_callback(self, packet):
        if packet.haslayer(TCP):
            port = packet[TCP].dport
            if port in self.insecure_ports:
                risk = f"Insecure {self.insecure_ports[port]} traffic detected to {packet[IP].dst}"
                if risk not in self.detected_risks:
                    self.detected_risks.append(risk)

    def start_capture(self, timeout=30):
        sniff(prn=self.packet_callback, timeout=timeout)
        return self.detected_risks
