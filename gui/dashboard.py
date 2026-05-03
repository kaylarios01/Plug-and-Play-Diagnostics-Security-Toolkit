import sys
import re
import os
import platform
import getpass
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, 
                             QLabel, QPushButton, QFrame, QLineEdit, 
                             QTabWidget, QStackedWidget, QScrollArea)
from PyQt6.QtCore import Qt, QTimer

# Modules
from modules.network_scan import scan_local_ports
from modules.audit_check import check_windows_settings
from modules.process_monitor import check_processes
from modules.password_test import test_password_strength

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_history = [] # Stores dicts of scan data
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Sentinel-X Diagnostics Suite")
        self.setFixedSize(850, 750)
        
        # --- SENTINEL-X GLOBAL STYLING ---
        self.setStyleSheet("""
            QWidget { background-color: #1a1b26; color: #a9b1d6; font-family: 'Segoe UI'; }
            QTabWidget::pane { border: 1px solid #414868; background: #1a1b26; border-radius: 5px; }
            QTabBar::tab { background: #24283b; padding: 15px 25px; color: #565f89; border: 1px solid #414868; }
            QTabBar::tab:selected { background: #414868; color: #7aa2f7; border-bottom: 2px solid #7aa2f7; }
            QFrame#ControlCard { background-color: #24283b; border-radius: 10px; padding: 20px; border: 1px solid #414868; }
            QPushButton#ActionBtn { background-color: #7aa2f7; color: #1a1b26; border-radius: 5px; padding: 12px; font-weight: bold; }
            QPushButton#ActionBtn:hover { background-color: #bb9af7; }
            QLineEdit { background-color: #1a1b26; border: 1px solid #414868; border-radius: 4px; padding: 10px; color: #c0caf5; }
        """)

        layout = QVBoxLayout()
        
        # --- HEADER ---
        title = QLabel("SENTINEL-X SECURITY")
        title.setStyleSheet("font-size: 28px; font-weight: bold; color: #7aa2f7; margin-top: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        # --- TABS ---
        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_host_tab(), "HOST AUDIT")
        self.tabs.addTab(self.create_password_tab(), "CREDENTIAL TEST")
        self.tabs.addTab(self.create_history_tab(), "LOG HISTORY")
        layout.addWidget(self.tabs)

        self.setLayout(layout)

    # --- HOST SCAN TAB ---
    def create_host_tab(self):
        tab = QWidget()
        l = QVBoxLayout(tab)
        l.addWidget(QLabel("Analyze the local machine for configuration weaknesses."))
        
        card = QFrame(); card.setObjectName("ControlCard")
        cl = QVBoxLayout(card)
        self.check_net = QCheckBox("Network Port Analysis")
        self.check_audit = QCheckBox("Security Policy Audit")
        self.check_proc = QCheckBox("Process Inspection")
        for cb in [self.check_net, self.check_audit, self.check_proc]: cl.addWidget(cb)
        
        l.addWidget(card)
        l.addStretch()
        btn = QPushButton("INITIALIZE SYSTEM SCAN"); btn.setObjectName("ActionBtn")
        btn.clicked.connect(self.run_host_logic)
        l.addWidget(btn)
        return tab

    # --- PASSWORD TAB (WITH FIXES) ---
    def create_password_tab(self):
        self.pass_stack = QStackedWidget()
        
        # Page 1: Input
        p1 = QWidget(); l1 = QVBoxLayout(p1)
        card = QFrame(); card.setObjectName("ControlCard"); cl = QVBoxLayout(card)
        cl.addWidget(QLabel("ENTER PASSWORD (MASKED)"))
        self.pass_input = QLineEdit(); self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        cl.addWidget(self.pass_input)
        l1.addWidget(card); l1.addStretch()
        btn = QPushButton("RUN ANALYSIS"); btn.setObjectName("ActionBtn")
        btn.clicked.connect(self.run_pass_logic); l1.addWidget(btn)
        
        # Page 2: Results
        self.pass_res_page = QWidget(); self.pr_layout = QVBoxLayout(self.pass_res_page)
        
        self.pass_stack.addWidget(p1); self.pass_stack.addWidget(self.pass_res_page)
        return self.pass_stack

    # --- HISTORY TAB ---
    def create_history_tab(self):
        tab = QWidget()
        self.hist_layout = QVBoxLayout(tab)
        self.scroll = QScrollArea()
        self.scroll_content = QWidget()
        self.scroll_vbox = QVBoxLayout(self.scroll_content)
        self.scroll.setWidget(self.scroll_content)
        self.scroll.setWidgetResizable(True)
        self.hist_layout.addWidget(self.scroll)
        return tab

    # --- LOGIC ---
    def run_pass_logic(self):
        pw = self.pass_input.text()
        if not pw: return
        findings = []
        recommendations = []
        score = 100

        # Complexity Check
        if len(pw) < 10: 
            findings.append("Critical: Length below 10 characters.")
            recommendations.append("Increase length to at least 12-16 characters.")
            score -= 30
        if not re.search(r"[A-Z]", pw):
            findings.append("Weakness: No uppercase letters.")
            recommendations.append("Add at least one UPPERCASE letter (A-Z).")
            score -= 10
        if not re.search(r"\d", pw):
            findings.append("Weakness: No numbers detected.")
            recommendations.append("Add at least one digit (0-9).")
            score -= 10
        if not re.search(r"[!@#$%^&*]", pw):
            findings.append("Weakness: No symbols detected.")
            recommendations.append("Add a special character (e.g., !, @, #).")
            score -= 10

        # Leak Test
        d, f = test_password_strength(pw)
        score -= d; findings.extend(f)

        # UI Update
        for i in reversed(range(self.pr_layout.count())): self.pr_layout.itemAt(i).widget().setParent(None)
        res_card = QFrame(); res_card.setObjectName("ControlCard"); v = QVBoxLayout(res_card)
        v.addWidget(QLabel(f"STRENGTH SCORE: {max(0, score)}/100"))
        
        v.addWidget(QLabel("\nREASONS:"))
        for fin in findings: v.addWidget(QLabel(f"• {fin}"))
        
        v.addWidget(QLabel("\nHOW TO FIX:"))
        for rec in recommendations: 
            lbl = QLabel(f"→ {rec}"); lbl.setStyleSheet("color: #73daca; font-weight: bold;")
            v.addWidget(lbl)
            
        self.pr_layout.addWidget(res_card)
        back = QPushButton("← TEST ANOTHER"); back.setObjectName("ActionBtn")
        back.clicked.connect(lambda: self.pass_stack.setCurrentIndex(0))
        self.pr_layout.addWidget(back)
        self.pass_stack.setCurrentIndex(1)

    def run_host_logic(self):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        hostname = platform.node()
        user = getpass.getuser()
        
        scan_types = []
        findings = []
        if self.check_net.isChecked(): scan_types.append("Network"); _, f = scan_local_ports(); findings.extend(f)
        if self.check_audit.isChecked(): scan_types.append("Audit"); _, f = check_windows_settings(); findings.extend(f)
        if self.check_proc.isChecked(): scan_types.append("Processes"); _, f = check_processes(); findings.extend(f)

        # Save to History
        scan_data = {
            "time": timestamp,
            "host": hostname,
            "user": user,
            "types": ", ".join(scan_types),
            "findings": findings
        }
        self.scan_history.append(scan_data)
        self.refresh_history_ui()
        self.tabs.setCurrentIndex(2)

    def refresh_history_ui(self):
        for i in reversed(range(self.scroll_vbox.count())): 
            widget = self.scroll_vbox.itemAt(i).widget()
            if widget: widget.setParent(None)
            
        for scan in reversed(self.scan_history):
            log_item = QFrame(); log_item.setObjectName("ControlCard")
            l = QVBoxLayout(log_item)
            l.addWidget(QLabel(f"TIMESTAMP: {scan['time']}"))
            l.addWidget(QLabel(f"USER/HOST: {scan['user']} @ {scan['host']}"))
            l.addWidget(QLabel(f"SCANS RUN: {scan['types']}"))
            
            btn = QPushButton("VIEW FULL RESULTS PDF/REPORT")
            btn.setFixedWidth(250)
            btn.setStyleSheet("background: #414868; color: #7aa2f7; border: 1px solid #7aa2f7;")
            btn.clicked.connect(lambda checked, s=scan: self.open_full_report(s))
            l.addWidget(btn)
            self.scroll_vbox.addWidget(log_item)

    def open_full_report(self, scan):
        # This can launch your existing ResultsView window with the specific scan data
        from gui.results_view import ResultsView
        # Since Host Scan uses a 100-point total, we can mock the scores based on findings
        mock_scores = {"Audit": 33, "Network": 33, "Processes": 34}
        self.res_win = ResultsView(mock_scores, scan['findings'])
        self.res_win.show()
