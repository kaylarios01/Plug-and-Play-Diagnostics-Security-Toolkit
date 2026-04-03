import sys
from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QPushButton, 
                             QTextEdit, QLabel, QTabWidget, QLineEdit, QTableWidget, QTableWidgetItem)
from PyQt6.QtCore import Qt

# These imports point to your subfolders (ensure they have __init__.py files)
from network_scanning.scanner import NetworkScanner
from config_audit.auditor import SecurityAuditor
from traffic_simulation.sniffer import TrafficInspector
from threat_simulation.simulator import ThreatSimulator
from report_generator.reporter import ReportGenerator
from process_review.profiler import ProcessReviewer # New module

class SecurityDashboard(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Advanced Security Diagnostics Toolkit")
        self.setMinimumSize(900, 700)

        # Initialize Logic from your other folders
        self.scanner = NetworkScanner()
        self.auditor = SecurityAuditor()
        self.inspector = TrafficInspector()
        self.reviewer = ProcessReviewer()

        # UI Setup
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.layout = QVBoxLayout(self.central_widget)

        self.tabs = QTabWidget()
        self.layout.addWidget(self.tabs)

        self.setup_network_tab()
        self.setup_process_tab()
        self.setup_audit_tab()

    def setup_network_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        layout.addWidget(QLabel("Target IP (e.g., 192.168.1.1):"))
        self.ip_input = QLineEdit("127.0.0.1")
        layout.addWidget(self.ip_input)
        
        btn = QPushButton("Start Network Scan")
        btn.clicked.connect(self.run_scan)
        layout.addWidget(btn)
        
        self.scan_log = QTextEdit()
        layout.addWidget(self.scan_log)
        self.tabs.addTab(tab, "Network")

    def setup_process_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        btn = QPushButton("Refresh Running Processes")
        btn.clicked.connect(self.refresh_processes)
        layout.addWidget(btn)
        
        self.proc_table = QTableWidget(0, 3)
        self.proc_table.setHorizontalHeaderLabels(["PID", "Name", "User"])
        layout.addWidget(self.proc_table)
        
        self.tabs.addTab(tab, "Process Review")

    def setup_audit_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        btn = QPushButton("Run Vulnerability Audit")
        btn.clicked.connect(self.run_audit)
        layout.addWidget(btn)
        
        self.audit_log = QTextEdit()
        layout.addWidget(self.audit_log)
        self.tabs.addTab(tab, "Audit & Traffic")

    # --- Logic Triggers ---

    def run_scan(self):
        target = self.ip_input.text()
        self.scan_log.append(f"Scanning {target}...")
        results = self.scanner.scan_target(target)
        for host in results:
            self.scan_log.append(f"Found: {host['host']} [{host['status']}]")

    def refresh_processes(self):
        self.proc_table.setRowCount(0)
        procs = self.reviewer.get_running_processes()
        for p in procs[:20]: # Show top 20 for speed
            row = self.proc_table.rowCount()
            self.proc_table.insertRow(row)
            self.proc_table.setItem(row, 0, QTableWidgetItem(str(p['pid'])))
            self.proc_table.setItem(row, 1, QTableWidgetItem(p['name']))
            self.proc_table.setItem(row, 2, QTableWidgetItem(p['username']))

    def run_audit(self):
        findings = self.auditor.run_system_audit()
        self.audit_log.append("\n".join(findings))
