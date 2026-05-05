import nmap

def scan_local_ports(target_ip='127.0.0.1'):
    scanner = nmap.PortScanner()
    # -sV: version detection, -sC: default scripts, -O: OS detection
    scanner.scan(target_ip, arguments='-sV -sC -O')
    
    findings = []
    danger_score = 0
    
    for host in scanner.all_hosts():
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                state = scanner[host][proto][port]['state']
                service = scanner[host][proto][port]['name']
                if state == 'open':
                    # Flag unencrypted protocols specifically
                    if service in ['telnet', 'ftp', 'http']:
                        findings.append(f"CRITICAL: Unencrypted {service.upper()} found on port {port}")
                        danger_score += 30
                    else:
                        findings.append(f"Info: Port {port} ({service}) is open")
    return danger_score, findings
