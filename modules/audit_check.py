import winreg

def check_windows_settings():
    findings = []
    score_deduction = 0
    
    try:
        path = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile"
        key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
        value, _ = winreg.QueryValueEx(key, "EnableFirewall")
        if value == 0:
            findings.append("Our Windows Firewall is currently turned OFF.")
            score_deduction += 50
    except Exception:
        findings.append("Could not verify Firewall status.")
        score_deduction += 5

    try:
        path = r"SYSTEM\CurrentControlSet\Services\BDESVC"
        winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, path)
    except FileNotFoundError:
        findings.append("BitLocker disk encryption is not detected.")
        score_deduction += 20
        
    return score_deduction, findings
