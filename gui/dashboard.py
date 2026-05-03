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
        
        # --- Page 1: Input ---
        p1 = QWidget()
        l1 = QVBoxLayout(p1)
        l1.setSpacing(10)  # Controls space between card and button
        l1.setContentsMargins(20, 20, 20, 20)
        
        desc = QLabel("Stress-test credentials against complexity rules and known leaks.")
        desc.setStyleSheet("color: #565f89; font-style: italic; margin-bottom: 5px;")
        l1.addWidget(desc)

        # Input Card
        card = QFrame()
        card.setObjectName("ControlCard")
        cl = QVBoxLayout(card)
        
        cl.addWidget(QLabel("ENTER CREDENTIALS (MASKED)"))
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setPlaceholderText("••••••••••••")
        cl.addWidget(self.pass_input)
        
        l1.addWidget(card)
        
        # Action Button (Now sits right under the card)
        btn = QPushButton("RUN ANALYSIS")
        btn.setObjectName("ActionBtn")
        btn.clicked.connect(self.run_pass_logic)
        l1.addWidget(btn)
        
        l1.addStretch() # Pushes everything to the top together

        # --- Page 2: Results ---
        self.pass_res_page = QWidget()
        self.pr_layout = QVBoxLayout(self.pass_res_page)
        self.pr_layout.setContentsMargins(20, 20, 20, 20)
        
        self.pass_stack.addWidget(p1)
        self.pass_stack.addWidget(self.pass_res_page)
        
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
        # 1. Gather Metadata
        timestamp = datetime.now().strftime("%H:%M:%S | %Y-%m-%d")
        hostname = platform.node()
        user = getpass.getuser()
        
        scan_types = []
        findings = []
        scores = {"Network": 33, "Registry": 33, "Processes": 34}
        
        # 2. Execute Scans
        if self.check_net.isChecked():
            scan_types.append("Network")
            d, f = scan_local_ports()
            scores["Network"] -= d
            findings.extend(f)
            
        if self.check_audit.isChecked():
            scan_types.append("Audit")
            d, f = check_windows_settings()
            scores["Registry"] -= d
            findings.extend(f)

        if self.check_proc.isChecked():
            scan_types.append("Processes")
            d, f = check_processes()
            scores["Processes"] -= d
            findings.extend(f)

        # 3. Save to History (Consolidated)
        scan_data = {
            "title": f"Host Audit [{timestamp}]",
            "metadata": f"User: {user} | Host: {hostname} | Modules: {', '.join(scan_types)}",
            "findings": findings,
            "scores": scores
        }
        self.scan_history.append(scan_data)
        self.refresh_history_ui()

        # 4. Show Results Immediately (Popup)
        self.show_host_results(scores, findings)

    def show_host_results(self, scores, findings):
        # Using your existing ResultsView but ensuring it matches the theme
        from gui.results_view import ResultsView
        self.res_win = ResultsView(scores, findings)
        self.res_win.setStyleSheet("background-color: #1a1b26; color: #a9b1d6;")
        self.res_win.show()

    def refresh_history_ui(self):
        # Clear the old entries
        for i in reversed(range(self.scroll_vbox.count())): 
            widget = self.scroll_vbox.itemAt(i).widget()
            if widget: widget.setParent(None)
            
        for scan in reversed(self.scan_history):
            log_card = QFrame()
            log_card.setObjectName("ControlCard")
            # Horizontal layout to put text on left and buttons on right
            h_layout = QHBoxLayout(log_card)
            
            # Left: Metadata Info
            info_layout = QVBoxLayout()
            title = QLabel(scan['title'])
            title.setStyleSheet("font-weight: bold; color: #7aa2f7; font-size: 14px;")
            
            meta = QLabel(scan['metadata'])
            meta.setStyleSheet("color: #565f89; font-size: 11px;")
            meta.setWordWrap(True)
            
            info_layout.addWidget(title)
            info_layout.addWidget(meta)
            
            # Right: Action Buttons
            btn_layout = QVBoxLayout()
            
            view_btn = QPushButton("VIEW RESULTS")
            view_btn.setFixedSize(130, 28)
            view_btn.setStyleSheet("background: #414868; color: #7aa2f7; font-size: 10px; font-weight: bold;")
            # Links back to the results view popup
            view_btn.clicked.connect(lambda checked, s=scan: self.show_host_results(s['scores'], s['findings']))
            
            pdf_btn = QPushButton("DOWNLOAD PDF")
            pdf_btn.setFixedSize(130, 28)
            pdf_btn.setStyleSheet("background: #1a1b26; color: #a9b1d6; font-size: 10px; border: 1px solid #414868;")
            pdf_btn.clicked.connect(lambda: print("Exporting PDF...")) # Logic for PDF goes here
            
            btn_layout.addWidget(view_btn)
            btn_layout.addWidget(pdf_btn)
            
            h_layout.addLayout(info_layout, stretch=3)
            h_layout.addLayout(btn_layout, stretch=1)
            
            self.scroll_vbox.addWidget(log_card)
        
        self.scroll_vbox.addStretch()
      
    def open_full_report(self, scan):
        # This can launch your existing ResultsView window with the specific scan data
        from gui.results_view import ResultsView
        # Since Host Scan uses a 100-point total, we can mock the scores based on findings
        mock_scores = {"Audit": 33, "Network": 33, "Processes": 34}
        self.res_win = ResultsView(mock_scores, scan['findings'])
        self.res_win.show()
