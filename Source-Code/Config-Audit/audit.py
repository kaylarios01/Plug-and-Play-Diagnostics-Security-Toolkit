import subprocess
import os

class SecurityAuditor:
    def run_system_audit(self):
        # Runs Lynis audit in non-interactive mode
        report_path = "/tmp/lynis_report.txt"
        try:
            cmd = f"lynis audit system --quick > {report_path}"
            subprocess.run(cmd, shell=True, check=True)
            
            # Extract "Suggestions" and "Warnings" from the report
            with open(report_path, 'r') as f:
                report_content = f.readlines()
            
            findings = [line.strip() for line in report_content if "Suggestion" in line or "Warning" in line]
            return findings
        except Exception as e:
            return [f"Audit failed: {str(e)}"]

if __name__ == "__main__":
    auditor = SecurityAuditor()
    print(auditor.run_system_audit())
