import sys
import os
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QPushButton, 
                             QTextEdit, QLabel, QTabWidget, QLineEdit, 
                             QTableWidget, QTableWidgetItem, QHBoxLayout)
from PyQt6.QtCore import Qt, QThread, pyqtSignal
from PyQt6.QtGui import QFont, QColor

# Logic Imports (Ensure these files exist in your folders)
from network_scanning.scanner import NetworkScanner
from config_audit.auditor import SecurityAuditor
from process_review.profiler import ProcessReviewer
from report_generator.reporter import ReportGenerator

# --- Threading Worker: Keeps the GUI responsive during scans ---
class ScanWorker(QThread):
    log_signal = pyqtSignal(str)
    result_signal = pyqtSignal(list)

    def __init__(self, scanner, target):
        super().__init__()
        self.scanner = scanner
        self.target = target

    def run(self):
        self.log_signal.emit(f"[*] Initializing Nmap engine for {self.target}...")
        try:
            results = self.scanner.scan_target(self.target)
            self.result_signal.emit(results)
        except Exception as e:
            self.log_signal.emit(f"[!] Error: {str(e)}")

class SecurityDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Plug-and-Play Security Diagnostics Toolkit")
        self.setMinimumSize(1000, 750)
        
        # Initialize Logic
        self.scanner = NetworkScanner()
        self.auditor = SecurityAuditor()
        self.reviewer = ProcessReviewer()
        self.reporter = ReportGenerator()

        self.init_ui()
        self.apply_hacker_theme()

    def init_ui(self):
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QVBoxLayout(self.central_widget)

        # Header
        self.header = QLabel("SHIELD-DRIVE: ADVANCED DIAGNOSTICS")
        self.header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.header.setFont(QFont("Courier New", 20, QFont.Weight.Bold))
        self.main_layout.addWidget(self.header)

        self.tabs = QTabWidget()
        self.main_layout.addWidget(self.tabs)

        # Build Tabs
        self.setup_network_tab()
        self.setup_process_tab()
        self.setup_audit_tab()
        self.setup_remediation_tab()

    def apply_hacker_theme(self):
        self.setStyleSheet("""
            QMainWindow { background-color: #0a0a0a; }
            QTabWidget::pane { border: 1px solid #00ff00; background: #121212; }
            QTabBar::tab { background: #1a1a1a; color: #00ff00; padding: 10px; border: 1px solid #333; }
            QTabBar::tab:selected { background: #00ff00; color: black; font-weight: bold; }
            QTextEdit { background-color: #000; color: #00ff00; font-family: 'Courier New'; border: 1px solid #333; }
            QPushButton { background-color: #1a1a1a; color: #00ff00; border: 1px solid #00ff00; padding: 8px; border-radius: 4px; }
            QPushButton:hover { background-color: #00ff00; color: #000; }
            QLineEdit { background: #000; color: #00ff00; border: 1px solid #333; padding: 5px; }
            QLabel { color: #00ff00; }
            QTableWidget { background-color: #000; color: #00ff00; gridline-color: #333; }
            QHeaderView::section { background-color: #1a1a1a; color: #00ff00; border: 1px solid #333; }
        """)

    # --- TAB SETUPS ---

    def setup_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        input_layout = QHBoxLayout()
        input_layout.addWidget(QLabel("Target IP/Range:"))
        self.ip_input = QLineEdit("127.0.0.1")
        input_layout.addWidget(self.ip_input)
        
        self.scan_btn = QPushButton("EXECUTE NETWORK SCAN")
        self.scan_btn.clicked.connect(self.run_network_scan)
        input_layout.addWidget(self.scan_btn)
        layout.addLayout(input_layout)

        self.scan_log = QTextEdit()
        self.scan_log.setReadOnly(True)
        layout.addWidget(self.scan_log)
        self.tabs.addTab(tab, "Network Scan")

    def setup_process_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        btn = QPushButton("ANALYZE RUNNING PROCESSES")
        btn.clicked.connect(self.refresh_processes)
        layout.addWidget(btn)
        
        self.proc_table = QTableWidget(0, 4)
        self.proc_table.setHorizontalHeaderLabels(["PID", "Name", "User", "Risk Level"])
        layout.addWidget(self.proc_table)
        self.tabs.addTab(tab, "Process Review")

    def setup_audit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        btn = QPushButton("RUN HOST VULNERABILITY AUDIT")
        btn.clicked.connect(self.run_audit)
        layout.addWidget(btn)
        
        self.audit_log = QTextEdit()
        layout.addWidget(self.audit_log)
        self.tabs.addTab(tab, "Vulnerability Audit")

    def setup_remediation_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        self.remedy_view = QTextEdit()
        layout.addWidget(QLabel("ACTIONABLE SECURITY REMEDIATION STEPS:"))
        layout.addWidget(self.remedy_view)
        
        report_btn = QPushButton("GENERATE EXPORTABLE PDF REPORT")
        report_btn.clicked.connect(self.generate_final_report)
        layout.addWidget(report_btn)
        self.tabs.addTab(tab, "Remediation Guide")

    # --- LOGIC HANDLERS ---

    def run_network_scan(self):
        target = self.ip_input.text()
        self.scan_log.clear()
        self.scan_btn.setEnabled(False)
        
        # Start the background worker
        self.worker = ScanWorker(self.scanner, target)
        self.worker.log_signal.connect(lambda msg: self.scan_log.append(msg))
        self.worker.result_signal.connect(self.finish_scan)
        self.worker.start()

    def finish_scan(self, results):
        self.scan_btn.setEnabled(True)
        for host in results:
            self.scan_log.append(f"[+] {host['host']} is UP. Ports: {host.get('ports', 'None detected')}")
            if "80" in str(host.get('ports')):
                self.add_remediation("Insecure HTTP", "Port 80 (HTTP) is open. Recommend enforcing HTTPS/TLS.")

    def refresh_processes(self):
        self.proc_table.setRowCount(0)
        procs = self.reviewer.get_running_processes()
        for p in procs[:30]:
            row = self.proc_table.rowCount()
            self.proc_table.insertRow(row)
            self.proc_table.setItem(row, 0, QTableWidgetItem(str(p['pid'])))
            self.proc_table.setItem(row, 1, QTableWidgetItem(p['name']))
            self.proc_table.setItem(row, 2, QTableWidgetItem(p['username']))
            
            # Simple Risk Logic
            risk = "Low"
            if p['name'].lower() in ['ncat', 'wireshark', 'tcpdump']:
                risk = "⚠️ CRITICAL"
                self.add_remediation(f"Dangerous Tool: {p['name']}", "Identify if this process is authorized or a potential backdoor.")
            
            risk_item = QTableWidgetItem(risk)
            if risk == "⚠️ CRITICAL": risk_item.setForeground(QColor("red"))
            self.proc_table.setItem(row, 3, risk_item)

    def run_audit(self):
        findings = self.auditor.run_system_audit()
        self.audit_log.append("\n".join(findings))
        self.add_remediation("System Hardening", "Follow the audit logs above to patch identified insecure defaults.")

    def add_remediation(self, issue, fix):
        current_text = self.remedy_view.toPlainText()
        if issue not in current_text:
            self.remedy_view.append(f"🔴 ISSUE: {issue}\n🟢 FIX: {fix}\n{'-'*40}")

    def generate_final_report(self):
        content = self.remedy_view.toPlainText()
        self.reporter.generate_pdf(content)
        self.remedy_view.append("\n[✔] PDF Report saved to SanDisk USB: /reports/security_summary.pdf")
