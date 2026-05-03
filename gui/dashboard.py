import sys
import re
import os
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, 
                             QLabel, QProgressBar, QPushButton, QFrame, QLineEdit, 
                             QTabWidget, QScrollArea, QStackedWidget)
from PyQt6.QtCore import Qt, QTimer

# Modules
from modules.network_scan import scan_local_ports
from modules.audit_check import check_windows_settings
from modules.process_monitor import check_processes
from modules.password_test import test_password_strength

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_history = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Sentinel-X Diagnostics Suite")
        self.setFixedSize(750, 700)
        
        # --- UNIFIED CYBER-GRID STYLING ---
        self.setStyleSheet("""
            QWidget { background-color: #1a1b26; color: #a9b1d6; font-family: 'Segoe UI', sans-serif; }
            QTabWidget::pane { border: 1px solid #414868; background: #1a1b26; border-radius: 5px; top: -1px; }
            QTabBar::tab { background: #24283b; padding: 15px 25px; border: 1px solid #414868; border-bottom: none; margin-right: 2px; color: #565f89; }
            QTabBar::tab:selected { background: #414868; color: #7aa2f7; font-weight: bold; border-bottom: 2px solid #7aa2f7; }
            
            QLabel#MainTitle { font-size: 28px; font-weight: bold; color: #7aa2f7; letter-spacing: 2px; }
            QLabel#Description { color: #565f89; font-style: italic; margin-bottom: 10px; }
            
            QFrame#ControlCard { background-color: #24283b; border-radius: 10px; padding: 20px; border: 1px solid #414868; }
            
            QPushButton#ActionBtn { background-color: #7aa2f7; color: #1a1b26; border-radius: 5px; padding: 12px; font-weight: bold; }
            QPushButton#ActionBtn:hover { background-color: #bb9af7; }
            
            QLineEdit { background-color: #1a1b26; border: 1px solid #414868; border-radius: 4px; padding: 10px; color: #c0caf5; font-family: 'Consolas'; }
        """)

        layout = QVBoxLayout()
        
        # --- HEADER ---
        header = QVBoxLayout()
        title = QLabel("SENTINEL-X SECURITY")
        title.setObjectName("MainTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        status_row = QHBoxLayout()
        self.blinker = QFrame()
        self.blinker.setFixedSize(10, 10)
        self.blinker.setStyleSheet("background-color: #73daca; border-radius: 5px;")
        status_row.addStretch()
        status_row.addWidget(QLabel("ENCRYPTED SESSION ACTIVE"))
        status_row.addWidget(self.blinker)
        status_row.addStretch()
        
        header.addWidget(title)
        header.addLayout(status_row)
        layout.addLayout(header)

        # --- TABS ---
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_host_tab(), "HOST AUDIT")
        self.tabs.addTab(self.create_password_tab(), "CREDENTIAL TEST")
        self.tabs.addTab(self.create_results_tab(), "REVIEW LOGS")
        layout.addWidget(self.tabs)

        self.setLayout(layout)
        
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.toggle_blinker)
        self.blink_timer.start(800)

    def toggle_blinker(self):
        curr = self.blinker.styleSheet()
        self.blinker.setStyleSheet(f"background-color: {'transparent' if '#73daca' in curr else '#73daca'}; border-radius: 5px;")

    # --- TAB 1: HOST SCANNING ---
    def create_host_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        desc = QLabel("Analyze the local machine for configuration weaknesses and active threats.")
        desc.setObjectName("Description")
        layout.addWidget(desc)

        # Card for Checkboxes with Descriptions
        card = QFrame()
        card.setObjectName("ControlCard")
        c_layout = QVBoxLayout(card)

        # Port Scan
        self.check_net = QCheckBox("Network Port Analysis")
        self.check_net.setStyleSheet("font-weight: bold; color: #bb9af7;")
        c_layout.addWidget(self.check_net)
        c_layout.addWidget(QLabel("   - Scans for open 'doors' that hackers use to enter the system via the network."))
        
        # Registry Audit
        self.check_audit = QCheckBox("Security Policy Audit")
        self.check_audit.setStyleSheet("font-weight: bold; color: #bb9af7;")
        c_layout.addWidget(self.check_audit)
        c_layout.addWidget(QLabel("   - Reviews Windows settings like Firewall and Encryption status to ensure they are ON."))
        
        # Process Monitor
        self.check_proc = QCheckBox("Malicious Process Inspection")
        self.check_proc.setStyleSheet("font-weight: bold; color: #bb9af7;")
        c_layout.addWidget(self.check_proc)
        c_layout.addWidget(QLabel("   - Cross-references running programs against a list of known malware signatures."))

        layout.addWidget(card)
        layout.addStretch()

        self.host_btn = QPushButton("INITIALIZE SYSTEM SCAN")
        self.host_btn.setObjectName("ActionBtn")
        self.host_btn.clicked.connect(self.run_host_logic)
        layout.addWidget(self.host_btn)
        return tab

    # --- TAB 2: PASSWORD TESTING (In-Page Results) ---
    def create_password_tab(self):
        self.pass_widget = QStackedWidget()
        
        # PAGE 1: INPUT
        input_page = QWidget()
        i_layout = QVBoxLayout(input_page)
        
        desc = QLabel("Stress-test passwords against common patterns and database leaks.")
        desc.setObjectName("Description")
        i_layout.addWidget(desc)

        card = QFrame()
        card.setObjectName("ControlCard")
        c_layout = QVBoxLayout(card)
        c_layout.addWidget(QLabel("ENTER CREDENTIALS (MASKED FOR PRIVACY)"))
        
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password) # Prevent shoulder surfing
        self.pass_input.setPlaceholderText("••••••••••••")
        c_layout.addWidget(self.pass_input)
        
        i_layout.addWidget(card)
        i_layout.addStretch()
        
        btn = QPushButton("TEST PASSWORD STRENGTH")
        btn.setObjectName("ActionBtn")
        btn.clicked.connect(self.run_pass_logic)
        i_layout.addWidget(btn)
        
        # PAGE 2: RESULTS
        self.pass_res_page = QWidget()
        self.pr_layout = QVBoxLayout(self.pass_res_page)
        
        self.pass_widget.addWidget(input_page)
        self.pass_widget.addWidget(self.pass_res_page)
        
        return self.pass_widget

    # --- TAB 3: RESULTS REVIEW ---
    def create_results_tab(self):
        tab = QWidget()
        self.res_layout = QVBoxLayout(tab)
        self.res_log = QLabel("No scans performed in this session.")
        self.res_log.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.res_layout.addWidget(self.res_log)
        return tab

    # --- LOGIC ---
    def run_pass_logic(self):
        pw = self.pass_input.text()
        if not pw: return
        
        # Logic
        score = 100
        findings = []
        if len(pw) < 10: 
            findings.append("Vulnerability: Length below recommended 10-character threshold.")
            score -= 30
        
        d, f = test_password_strength(pw)
        score -= d
        findings.extend(f)

        # Build In-Page Result
        for i in reversed(range(self.pr_layout.count())): 
            self.pr_layout.itemAt(i).widget().setParent(None)

        res_card = QFrame()
        res_card.setObjectName("ControlCard")
        v = QVBoxLayout(res_card)
        
        color = "#73daca" if score > 70 else "#f7768e"
        header = QLabel(f"STRENGTH SCORE: {score}/100")
        header.setStyleSheet(f"font-size: 20px; font-weight: bold; color: {color};")
        v.addWidget(header)
        
        for item in findings:
            v.addWidget(QLabel(f"• {item}"))
            
        self.pr_layout.addWidget(res_card)
        
        retry_btn = QPushButton("← ANALYZE ANOTHER PASSWORD")
        retry_btn.setObjectName("ActionBtn")
        retry_btn.clicked.connect(lambda: self.pass_widget.setCurrentIndex(0))
        self.pr_layout.addWidget(retry_btn)
        
        self.pass_widget.setCurrentIndex(1)
        self.update_history(f"Password Test: {score}/100")

    def run_host_logic(self):
        results = []
        if self.check_net.isChecked():
            _, f = scan_local_ports()
            results.extend(f)
        if self.check_audit.isChecked():
            _, f = check_windows_settings()
            results.extend(f)
        if self.check_proc.isChecked():
            _, f = check_processes()
            results.extend(f)
            
        self.update_history(f"Host Scan: {len(results)} findings identified.")
        self.tabs.setCurrentIndex(2) # Switch to Review Logs tab

    def update_history(self, entry):
        self.scan_history.append(entry)
        # Refresh the Results Tab view
        for i in reversed(range(self.res_layout.count())): 
            self.res_layout.itemAt(i).widget().setParent(None)
        
        for item in self.scan_history:
            lbl = QLabel(f"» {item}")
            lbl.setStyleSheet("padding: 5px; border-bottom: 1px solid #414868;")
            self.res_layout.addWidget(lbl)
        self.res_layout.addStretch()
