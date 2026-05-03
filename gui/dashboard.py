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
        self.setFixedSize(600, 600)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        
        main_layout = QVBoxLayout()

        # Header (Stable Blinker)
        header_layout = QHBoxLayout()
        title = QLabel("System Control Center")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #50fa7b;")
        self.blinker = QFrame()
        self.blinker.setFixedSize(12, 12)
        self.blinker.setStyleSheet("background-color: #50fa7b; border-radius: 6px;")
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.toggle_blinker)
        self.blink_timer.start(500)
        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(QLabel("Live Traffic:"))
        header_layout.addWidget(self.blinker)
        main_layout.addLayout(header_layout)

        # Step 1: System Scans
        main_layout.addWidget(QLabel("Step 1: System Safety Checks"))
        self.check_net = QCheckBox("Check for 'unlocked doors' (Ports)")
        self.check_audit = QCheckBox("Review computer safety settings (Registry)")
        self.check_proc = QCheckBox("Search for hidden programs (Processes)")
        for check in [self.check_net, self.check_audit, self.check_proc]:
            check.setStyleSheet("font-size: 14px; margin: 5px;")
            main_layout.addWidget(check)

        # Step 2: Password Test with "Check" Button
        main_layout.addWidget(QLabel("\nStep 2: Password Strength Stress-Test"))
        pass_row = QHBoxLayout()
        self.pass_input = QLineEdit()
        self.pass_input.setPlaceholderText("Type a password to test...")
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setStyleSheet("padding: 10px; background: #44475a; border: none; border-radius: 5px;")
        
        self.pass_check_btn = QPushButton("Check")
        self.pass_check_btn.setFixedWidth(80)
        self.pass_check_btn.setStyleSheet("background-color: #50fa7b; color: #2b2b2b; font-weight: bold; padding: 10px; border-radius: 5px;")
        self.pass_check_btn.clicked.connect(self.run_password_only)
        
        pass_row.addWidget(self.pass_input)
        pass_row.addWidget(self.pass_check_btn)
        main_layout.addLayout(pass_row)

        self.status_label = QLabel("Ready to begin.")
        main_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("QProgressBar { border: 2px solid #44475a; border-radius: 5px; text-align: center; } QProgressBar::chunk { background-color: #50fa7b; }")
        main_layout.addWidget(self.progress_bar)

        self.start_btn = QPushButton("Run Full Security Scan")
        self.start_btn.setStyleSheet("QPushButton { background-color: #6272a4; color: white; padding: 15px; font-size: 16px; border-radius: 8px; }")
        self.start_btn.clicked.connect(self.run_full_checks)
        main_layout.addWidget(self.start_btn)

        self.setLayout(main_layout)

    def toggle_blinker(self):
        current_style = self.blinker.styleSheet()
        if "#50fa7b" in current_style:
            self.blinker.setStyleSheet("background-color: transparent; border-radius: 6px;")
        else:
            self.blinker.setStyleSheet("background-color: #50fa7b; border-radius: 6px;")

    def validate_password(self, password):
        # Explicit findings to ensure they show up in the report
        findings = []
        if len(password) < 8: findings.append("Password Test: Failed (Less than 8 characters).")
        if not re.search(r"[A-Z]", password): findings.append("Password Test: Missing an UPPERCASE letter.")
        if not re.search(r"[a-z]", password): findings.append("Password Test: Missing a lowercase letter.")
        if not re.search(r"\d", password): findings.append("Password Test: Missing a number.")
        if not re.search(r"[!@#$%^&*()]", password): findings.append("Password Test: Missing a special character.")
        return findings

    def run_password_only(self):
        """Runs only the password test when the green 'Check' button is clicked."""
        user_pass = self.pass_input.text()
        if not user_pass:
            self.status_label.setText("Please enter a password first!")
            return
            
        all_findings = self.validate_password(user_pass)
        score = 100
        if all_findings: score -= 50
        
        leak_deduction, leak_findings = test_password_strength(user_pass)
        score -= leak_deduction
        all_findings.extend(leak_findings)
        
        # We pass a dummy score dict for the results view
        self.show_results({"Password Only": score}, all_findings)

    def run_full_checks(self):
        """Runs the entire suite and explains every deduction."""
        self.status_label.setText("Analyzing...")
        self.progress_bar.setValue(10)
        
        all_findings = []
        scores = {"Network": 25, "Audit": 25, "Processes": 25, "Password": 25}
        
        if self.check_net.isChecked():
            deduction, findings = scan_local_ports()
            scores["Network"] -= deduction
            all_findings.extend(findings)
        
        if self.check_audit.isChecked():
            deduction, findings = check_windows_settings()
            scores["Audit"] -= deduction
            # Ensure findings explain why points were lost
            if not findings and scores["Audit"] < 25:
                findings.append(f"Audit Check: Points deducted for security settings.")
            all_findings.extend(findings)

        if self.check_proc.isChecked():
            deduction, findings = check_processes()
            scores["Processes"] -= deduction
            all_findings.extend(findings)

        user_pass = self.pass_input.text()
        if user_pass:
            p_findings = self.validate_password(user_pass)
            if p_findings:
                scores["Password"] -= 10
                all_findings.extend(p_findings)
            
            l_deduction, l_findings = test_password_strength(user_pass)
            scores["Password"] -= l_deduction
            all_findings.extend(l_findings)
        else:
            all_findings.append("Password: No entry provided to test.")
            scores["Password"] = 0

        self.progress_bar.setValue(100)
        self.show_results(scores, all_findings)

    def show_results(self, scores, findings):
        self.results_win = ResultsView(scores, findings)
        self.results_win.show()
        self.hide()
