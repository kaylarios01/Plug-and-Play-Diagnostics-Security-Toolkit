import sys
import re
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, 
                             QLabel, QProgressBar, QPushButton, QFrame, QLineEdit)
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
        self.setFixedSize(620, 650)
        
        # --- GLOBAL STYLING (DRACULA THEME) ---
        self.setStyleSheet("""
            QWidget {
                background-color: #282a36;
                color: #f8f8f2;
                font-family: 'Segoe UI', Arial;
            }
            QLabel#HeaderTitle {
                font-size: 22px;
                font-weight: bold;
                color: #50fa7b;
            }
            QLabel#SectionLabel {
                font-size: 14px;
                font-weight: bold;
                color: #bd93f9;
                margin-top: 10px;
            }
            QFrame#Card {
                background-color: #383a59;
                border-radius: 12px;
                border: 1px solid #44475a;
            }
            QLineEdit {
                background-color: #44475a;
                border: 2px solid #6272a4;
                border-radius: 6px;
                padding: 10px;
                color: #f8f8f2;
            }
            QCheckBox {
                font-size: 13px;
                spacing: 8px;
            }
            QPushButton#PrimaryBtn {
                background-color: #6272a4;
                border-radius: 8px;
                padding: 12px;
                font-weight: bold;
                font-size: 14px;
            }
            QPushButton#PrimaryBtn:hover {
                background-color: #50fa7b;
                color: #282a36;
            }
            QPushButton#CheckBtn {
                background-color: #50fa7b;
                color: #282a36;
                border-radius: 6px;
                font-weight: bold;
            }
            QPushButton#CheckBtn:hover {
                background-color: #40c462;
            }
        """)

        main_layout = QVBoxLayout()
        main_layout.setContentsMargins(25, 25, 25, 25)
        main_layout.setSpacing(15)

        # --- HEADER ---
        header = QHBoxLayout()
        title = QLabel("SECURITY CONTROL")
        title.setObjectName("HeaderTitle")
        
        # Stable Blinker logic
        self.blinker = QFrame()
        self.blinker.setFixedSize(14, 14)
        self.blinker.setStyleSheet("background-color: #50fa7b; border-radius: 7px;")
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.toggle_blinker)
        self.blink_timer.start(600)
        
        header.addWidget(title)
        header.addStretch()
        header.addWidget(QLabel("LIVE STATUS:"))
        header.addWidget(self.blinker)
        main_layout.addLayout(header)

        # --- SECTION 1: SYSTEM SCANS CARD ---
        system_card = QFrame()
        system_card.setObjectName("Card")
        system_layout = QVBoxLayout(system_card)
        
        system_layout.addWidget(QLabel("SYSTEM VULNERABILITY SCANS"))
        self.check_net = QCheckBox("Scan Local Network Ports (Nmap)")
        self.check_audit = QCheckBox("Audit Security Configuration (Registry)")
        self.check_proc = QCheckBox("Inspect Running Processes (Malware Check)")
        
        for cb in [self.check_net, self.check_audit, self.check_proc]:
            system_layout.addWidget(cb)
        
        main_layout.addWidget(system_card)

        # --- SECTION 2: PASSWORD CARD ---
        pass_card = QFrame()
        pass_card.setObjectName("Card")
        pass_layout = QVBoxLayout(pass_card)
        
        pass_layout.addWidget(QLabel("PASSWORD STRESS TEST"))
        
        pass_input_row = QHBoxLayout()
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Enter password to analyze...")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        
        self.check_pass_btn = QPushButton("Check")
        self.check_pass_btn.setObjectName("CheckBtn")
        self.check_pass_btn.setFixedSize(80, 38)
        self.check_pass_btn.clicked.connect(self.run_password_only)
        
        pass_input_row.addWidget(self.pass_input)
        pass_input_row.addWidget(self.check_pass_btn)
        pass_layout.addLayout(pass_input_row)
        
        main_layout.addWidget(pass_card)

        # --- PROGRESS & STATUS ---
        self.status_label = QLabel("System Ready")
        self.status_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        main_layout.addWidget(self.status_label)

        self.progress_bar = QProgressBar()
        self.progress_bar.setFixedHeight(12)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar { background-color: #44475a; border-radius: 6px; }
            QProgressBar::chunk { background-color: #bd93f9; border-radius: 6px; }
        """)
        main_layout.addWidget(self.progress_bar)

        # --- MAIN ACTION BUTTON ---
        self.start_btn = QPushButton("LAUNCH FULL DIAGNOSTIC")
        self.start_btn.setObjectName("PrimaryBtn")
        self.start_btn.clicked.connect(self.run_full_checks)
        main_layout.addWidget(self.start_btn)

        self.setLayout(main_layout)

    def toggle_blinker(self):
        curr = self.blinker.styleSheet()
        if "#50fa7b" in curr:
            self.blinker.setStyleSheet("background-color: transparent; border-radius: 7px;")
        else:
            self.blinker.setStyleSheet("background-color: #50fa7b; border-radius: 7px;")

    def validate_password(self, password):
        findings = []
        if len(password) < 8: findings.append("Password Test: Too short (Under 8 chars).")
        if not re.search(r"[A-Z]", password): findings.append("Password Test: Missing Uppercase.")
        if not re.search(r"\d", password): findings.append("Password Test: Missing Number.")
        if not re.search(r"[!@#$%^&*]", password): findings.append("Password Test: Missing Special Char.")
        return findings

    def run_password_only(self):
        user_pass = self.pass_input.text()
        if not user_pass:
            self.status_label.setText("Input required!")
            return
        
        all_findings = self.validate_password(user_pass)
        score = 100
        if all_findings: score -= 40
        
        deduction, leak_findings = test_password_strength(user_pass)
        score -= deduction
        all_findings.extend(leak_findings)
        
        self.show_results({"Individual Password Test": score}, all_findings)

    def run_full_checks(self):
        self.status_label.setText("Executing Diagnostic...")
        self.progress_bar.setValue(20)
        
        all_findings = []
        scores = {"Network": 25, "Audit": 25, "Processes": 25, "Password": 25}
        
        # 1. Network
        if self.check_net.isChecked():
            d, f = scan_local_ports()
            scores["Network"] -= d
            all_findings.extend(f)
        self.progress_bar.setValue(40)

        # 2. Audit
        if self.check_audit.isChecked():
            d, f = check_windows_settings()
            scores["Audit"] -= d
            all_findings.extend(f)
        self.progress_bar.setValue(60)

        # 3. Processes
        if self.check_proc.isChecked():
            d, f = check_processes()
            scores["Processes"] -= d
            all_findings.extend(f)
        self.progress_bar.setValue(80)

        # 4. Password
        user_pass = self.pass_input.text()
        if user_pass:
            p_f = self.validate_password(user_pass)
            if p_f:
                scores["Password"] -= 10
                all_findings.extend(p_f)
            d, f = test_password_strength(user_pass)
            scores["Password"] -= d
            all_findings.extend(f)
        else:
            scores["Password"] = 0
            all_findings.append("No password provided for the scan.")

        self.progress_bar.setValue(100)
        self.show_results(scores, all_findings)

    def show_results(self, scores, findings):
        self.results_win = ResultsView(scores, findings)
        self.results_win.show()
        self.hide()
