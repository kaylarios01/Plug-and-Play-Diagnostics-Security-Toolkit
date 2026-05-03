import sys
import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, 
                             QLabel, QProgressBar, QPushButton, QFrame, QLineEdit, QTabWidget)
from PyQt6.QtCore import Qt, QTimer
from modules.network_scan import scan_local_ports
from modules.audit_check import check_windows_settings
from modules.process_monitor import check_processes
from modules.password_test import test_password_strength
from gui.results_view import ResultsView

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Security Diagnostics Toolkit")
        self.setFixedSize(650, 600)
        
        # --- DRACULA STYLING ---
        self.setStyleSheet("""
            QWidget { background-color: #282a36; color: #f8f8f2; font-family: 'Segoe UI'; }
            QTabWidget::pane { border: 1px solid #44475a; background: #282a36; border-radius: 10px; }
            QTabBar::tab { background: #44475a; padding: 12px 30px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 5px; }
            QTabBar::tab:selected { background: #6272a4; color: #50fa7b; font-weight: bold; }
            QLabel#WelcomeHeader { font-size: 26px; font-weight: bold; color: #50fa7b; margin-bottom: 5px; }
            QFrame#Card { background-color: #383a59; border-radius: 12px; padding: 15px; }
            QPushButton#ActionBtn { background-color: #6272a4; color: white; border-radius: 8px; padding: 15px; font-weight: bold; font-size: 14px; }
            QPushButton#ActionBtn:hover { background-color: #50fa7b; color: #282a36; }
            QLineEdit { background-color: #44475a; border: 2px solid #6272a4; border-radius: 6px; padding: 10px; }
        """)

        layout = QVBoxLayout()
        
        # --- WELCOME SECTION ---
        welcome_frame = QVBoxLayout()
        welcome_header = QLabel("WELCOME TO THE TOOLKIT")
        welcome_header.setObjectName("WelcomeHeader")
        welcome_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        status_row = QHBoxLayout()
        self.blinker = QFrame()
        self.blinker.setFixedSize(12, 12)
        self.blinker.setStyleSheet("background-color: #50fa7b; border-radius: 6px;")
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.toggle_blinker)
        self.blink_timer.start(500)
        
        status_row.addStretch()
        status_row.addWidget(QLabel("SYSTEM ENGINE ACTIVE"))
        status_row.addWidget(self.blinker)
        status_row.addStretch()
        
        welcome_frame.addWidget(welcome_header)
        welcome_frame.addLayout(status_row)
        layout.addLayout(welcome_frame)

        # --- TAB WIDGET ---
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_host_scan_tab(), "Host Scanning")
        self.tabs.addTab(self.create_password_tab(), "Password Testing")
        layout.addWidget(self.tabs)

        self.setLayout(layout)

    def toggle_blinker(self):
        curr = self.blinker.styleSheet()
        self.blinker.setStyleSheet(f"background-color: {'transparent' if '#50fa7b' in curr else '#50fa7b'}; border-radius: 6px;")

    # --- TAB 1: HOST SCANNING ---
    def create_host_scan_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.addWidget(QLabel("SYSTEM VULNERABILITY CHECKS"))
        
        self.check_net = QCheckBox("Scan Local Network Ports")
        self.check_audit = QCheckBox("Audit Registry Security Settings")
        self.check_proc = QCheckBox("Deep Process Inspection")
        
        for cb in [self.check_net, self.check_audit, self.check_proc]:
            cb.setChecked(True)
            card_layout.addWidget(cb)
        
        layout.addWidget(card)
        layout.addStretch()

        self.scan_btn = QPushButton("RUN HOST SCAN")
        self.scan_btn.setObjectName("ActionBtn")
        self.scan_btn.clicked.connect(self.run_host_checks)
        layout.addWidget(self.scan_btn)
        return tab

    # --- TAB 2: PASSWORD TESTING ---
    def create_password_tab(self):
        tab = QWidget()
        layout = QVBoxLayout(tab)
        
        card = QFrame()
        card.setObjectName("Card")
        card_layout = QVBoxLayout(card)
        card_layout.addWidget(QLabel("STRESS-TEST CREDENTIALS"))
        
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Enter password here...")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        card_layout.addWidget(self.pass_input)
        
        layout.addWidget(card)
        layout.addStretch()

        self.pass_btn = QPushButton("ANALYZE PASSWORD STRENGTH")
        self.pass_btn.setObjectName("ActionBtn")
        self.pass_btn.clicked.connect(self.run_password_only)
        layout.addWidget(self.pass_btn)
        return tab

    # --- LOGIC ---
    def run_password_only(self):
        user_pass = self.pass_input.text()
        if not user_pass:
            return
        
        findings = []
        score = 100
        
        # Complexity checks
        if len(user_pass) < 8:
            findings.append("Password: Too short (Under 8 chars).")
            score -= 20
        if not re.search(r"\d", user_pass):
            findings.append("Password: No numbers detected.")
            score -= 10
            
        # Leak test
        d, f = test_password_strength(user_pass)
        score -= d
        findings.extend(f)
        
        self.show_results({"Password Integrity": score}, findings)

    def run_host_checks(self):
        all_findings = []
        scores = {}
        
        if self.check_net.isChecked():
            d, f = scan_local_ports()
            scores["Network"] = 33 - d
            all_findings.extend(f)
            
        if self.check_audit.isChecked():
            d, f = check_windows_settings()
            scores["Registry"] = 33 - d
            all_findings.extend(f)

        if self.check_proc.isChecked():
            d, f = check_processes()
            scores["Processes"] = 34 - d
            # CRITICAL FIX: If points were lost but findings are empty, add a fallback message
            if d > 0 and not f:
                all_findings.append(f"Process Monitor: Identified {d} security risks in active tasks.")
            all_findings.extend(f)

        self.show_results(scores, all_findings)

    def show_results(self, scores, findings):
        self.results_win = ResultsView(scores, findings)
        self.results_win.show()
        self.hide()
