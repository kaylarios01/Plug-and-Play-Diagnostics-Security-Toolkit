import psutil

def check_processes():
    blacklist = ["wireshark.exe", "nmap.exe", "putty.exe", "vncviewer.exe"]
    findings = []
    score_deduction = 0
    
    for proc in psutil.process_iter(['name']):
        try:
            name = proc.info['name'].lower()
            if name in blacklist:
                findings.append(f"Suspicious program found running: {name}")
                score_deduction += 15
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    return score_deduction, findings
