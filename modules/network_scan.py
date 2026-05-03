import nmap
import socket

def quick_packet_sniff():
    # This uses basic Python sockets (Zero install required)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind(("0.0.0.0", 0))
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        # Capture just 1 packet to prove we can see traffic
        data = s.recvfrom(65565)
        return f"Live Traffic detected: {len(data[0])} bytes captured via USB Socket."
    except:
        return "Passive Sniffing: Restricted (Requires Admin privileges to see host traffic)."
        
def scan_local_ports():
    target = "127.0.0.1"
    scanner = nmap.PortScanner()
    findings = []
    score_deduction = 0
    
    try:
        scanner.scan(target, '80,445,3389', arguments="-sV")
        for port in [80, 445, 3389]:
            if target in scanner.all_hosts() and scanner[target].has_tcp(port):
                if scanner[target]['tcp'][port]['state'] == 'open':
                    findings.append(f"Port {port} is open and listening.")
                    score_deduction += 10
    except Exception as e:
        findings.append(f"Network scan error: {str(e)}")
        
    return score_deduction, findings
