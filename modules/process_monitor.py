import psutil

def check_processes():
    suspicious_names = ['nc.exe', 'netcat', 'nmap', 'wireshark']
    findings = []
    danger_score = 0
    
    for proc in psutil.process_iter(['pid', 'name', 'username']):
        try:
            pinfo = proc.info
            if pinfo['name'].lower() in suspicious_names:
                findings.append(f"WARNING: Suspicious process '{pinfo['name']}' (PID: {pinfo['pid']})")
                danger_score += 20
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return danger_score, findings
