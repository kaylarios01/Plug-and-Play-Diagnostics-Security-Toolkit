from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

class ReportGenerator:
    def create_pdf(self, scan_results, audit_results):
        c = canvas.Canvas("Security_Risk_Report.pdf", pagesize=letter)
        c.drawString(100, 750, "SECURITY DIAGNOSTICS REPORT")
        c.line(100, 740, 500, 740)
        
        y = 700
        c.drawString(100, y, "Network Scan Results:")
        for res in scan_results:
            y -= 20
            c.drawString(120, y, f"- Host: {res['host']} ({res['os']})")
        
        y -= 40
        c.drawString(100, y, "Critical Audit Findings:")
        for find in audit_results[:10]: # Top 10 findings
            y -= 20
            c.drawString(120, y, f"- {find[:60]}...")
            
        c.save()
        return "Report generated successfully."
