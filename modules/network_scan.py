import nmap

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
