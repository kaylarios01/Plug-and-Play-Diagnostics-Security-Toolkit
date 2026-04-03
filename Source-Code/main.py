import sys
from PyQt6.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QPushButton, QTextEdit, QLabel, QTabWidget, QLineEdit)
from PyQt6.QtCore import Qt

# Import your custom modules from your GitHub structure
from scanner import NetworkScanner
from audit import SecurityAuditor
from traffic import TrafficInspector
from simulation import ThreatSimulator
from report_gen import ReportGenerator

class SecurityToolkit(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Plug-and-Play Security Diagnostics Toolkit")
        self.setMinimumSize(800, 600)
        
        # Initialize Logic Modules
        self.scanner = NetworkScanner()
        self.auditor = SecurityAuditor()
        self.inspector = TrafficInspector()
        self.simulator = ThreatSimulator()
        self.reporter = ReportGenerator()

        # Main Layout
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        # Tabs for "Service Selection"
        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        # Create Tabs
        self.setup_scan_tab()
        self.setup_audit_tab()
        self.setup_results_tab()

    def setup_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Target IP / Range (e.g., 192.168.1.0/24):"))
        self.target_input = QLineEdit("127.0.0.1")
        layout.addWidget(self.target_input)
        
        btn_scan = QPushButton("Run Network Scan")
        btn_scan.clicked.connect(self.run_network_scan)
        layout.addWidget(btn_scan)
        
        self.scan_output = QTextEdit()
        self.scan_output.setReadOnly(True)
        layout.addWidget(self.scan_output)
        
        self.tabs.addTab(tab, "Network Scanning")

    def setup_audit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        btn_audit = QPushButton("Run Local System Audit (Lynis)")
        btn_audit.clicked.connect(self.run_audit)
        layout.addWidget(btn_audit)
        
        btn_traffic = QPushButton("Inspect Network Traffic (30s)")
        btn_traffic.clicked.connect(self.run_traffic_inspection)
        layout.addWidget(btn_traffic)
        
        self.audit_output = QTextEdit()
        self.audit_output.setReadOnly(True)
        layout.addWidget(self.audit_output)
        
        self.tabs.addTab(tab, "Auditing & Inspection")

    def setup_results_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        layout.addWidget(QLabel("Final Remediation & Reporting"))
        self.results_summary = QTextEdit()
        layout.addWidget(self.results_summary)
        
        btn_report = QPushButton("Generate Exportable PDF Report")
        btn_report.clicked.connect(self.generate_final_report)
        layout.addWidget(btn_report)
        
        self.tabs.addTab(tab, "Results & Reports")

    # --- Logic Connectors ---

    def run_network_scan(self):
        target = self.target_input.text()
        self.scan_output.append(f"Starting scan on {target}...")
        results = self.scanner.scan_target(target)
        for host in results:
            self.scan_output.append(f"Found Host: {host['host']} - OS: {host['os']}")
        self.results_summary.append("Network Scan Completed.")

    def run_audit(self):
        self.audit_output.append("Starting system audit...")
        findings = self.auditor.run_system_audit()
        for find in findings[:5]: # Show first 5
            self.audit_output.append(f"[!] {find}")
        self.results_summary.append(f"Audit completed with {len(findings)} findings.")

    def run_traffic_inspection(self):
        self.audit_output.append("Sniffing for insecure protocols...")
        risks = self.inspector.start_capture(timeout=10)
        if not risks:
            self.audit_output.append("No insecure traffic detected.")
        else:
            for risk in risks:
                self.audit_output.append(f"[CRITICAL] {risk}")

    def generate_final_report(self):
        # Dummy data passing for demo purposes
        msg = self.reporter.create_pdf([], [])
        self.results_summary.append(msg)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = SecurityToolkit()
    window.show()
    sys.exit(app.exec())
