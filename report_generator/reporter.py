from fpdf import FPDF
import os
from datetime import datetime

def generate_pdf_report(scores, findings):
    pdf = FPDF()
    pdf.add_page()
    
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="Security Diagnostics Toolkit - Report", ln=True, align='C')
    
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt=f"Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    
    pdf.ln(10)
    total_score = sum(scores.values())
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt=f"Overall Safety Score: {total_score}%", ln=True)
    
    pdf.ln(5)
    pdf.set_font("Arial", 'B', 12)
    pdf.cell(200, 10, txt="Findings:", ln=True)
    
    pdf.set_font("Arial", size=11)
    for item in findings:
        pdf.multi_cell(0, 10, txt=f"- {item}")
    
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    report_name = f"Security_Report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    report_path = os.path.join(base_dir, "reports", report_name)
    
    pdf.output(report_path)
    return report_path
