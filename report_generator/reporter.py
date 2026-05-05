from fpdf import FPDF
import os
from datetime import datetime

def generate_pdf_report(scores, findings):
    pdf = FPDF()
    pdf.add_page()
    
    # Title
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="CyberGuard Pro - Security Audit Report", ln=True, align='C')
    
    # Date
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)

    # Score Section
    total_score = sum(scores.values())
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt=f"Overall Safety Score: {total_score}%", ln=True)
    pdf.ln(5)

    # Findings Section
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Detailed Findings & Remediation:", ln=True)
    pdf.ln(5)

    pdf.set_font("Arial", size=11)
    for item in findings:
        # 1. Print the Finding in BOLD
        pdf.set_font("Arial", 'B', 11)
        pdf.multi_cell(0, 10, txt=f"Finding: {item}")
        
        # 2. Get the Fix and print it in ITALIC + GREEN
        advice = get_remediation(item)
        pdf.set_font("Arial", 'I', 11)
        pdf.set_text_color(30, 130, 76) # Green color for the solution
        pdf.multi_cell(0, 10, txt=f"Remediation: {advice}")
        
        # Reset color to black for next finding
        pdf.set_text_color(0, 0, 0)
        pdf.ln(2)

    # Save to Desktop
    desktop_path = os.path.join(os.path.expanduser("~"), "Desktop")
    report_name = f"Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    report_path = os.path.join(desktop_path, report_name)
    pdf.output(report_path)
    return report_path

def get_remediation(finding_text):
    remediations = {
        "SMBv1": "Disable SMBv1 immediately via 'Turn Windows features on or off' to prevent ransomware exploitation.",
        "Firewall": "Re-enable Windows Defender Firewall for all network profiles.",
        "password": "Update credentials to meet 12-character complexity requirements.",
        "Telnet": "Disable Telnet service and utilize SSH for secure remote access.",
        "FTP": "Disable FTP and migrate to SFTP (Secure FTP) for encrypted transfers.",
        "UAC": "Restore User Account Control settings to 'Default' level.",
        "Unrestricted": "Change PowerShell execution policy to 'RemoteSigned' to prevent malicious scripts."
    }
    # Match keywords from your 'traps' to the remediation text
    for key in remediations:
        if key.lower() in finding_text.lower():
            return remediations[key]
    return "Ensure the system is fully patched and follow industry-standard hardening benchmarks."
