from fpdf import FPDF
from datetime import datetime

def generate_pdf_report(scores, findings, output_path="CyberGuard_Report.pdf"):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", "B", 16)
    pdf.cell(0, 10, "CYBERGUARD PRO: SECURITY AUDIT REPORT", ln=True, align='C')
    
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True)
    
    pdf.ln(10)
    pdf.set_font("helvetica", "B", 14)
    pdf.cell(0, 10, "Diagnostic Summary:", ln=True)
    
    for module, score in scores.items():
        pdf.cell(0, 10, f"- {module} Safety: {max(0, 100-score)}/100", ln=True)
        
    pdf.ln(5)
    pdf.set_font("helvetica", "B", 12)
    pdf.cell(0, 10, "Detailed Findings:", ln=True)
    
    pdf.set_font("helvetica", size=10)
    for finding in findings:
        pdf.multi_cell(0, 8, f"• {finding}")
        
    pdf.output(output_path)
    return output_path
