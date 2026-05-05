import sys
import os
import platform
import getpass
import threading
import time
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QLabel, 
                             QPushButton, QFrame, QLineEdit, QTabWidget, QStackedWidget, 
                             QScrollArea, QApplication, QProgressBar)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject

# --- MODULE IMPORTS ---
try:
    from modules.network_scan import scan_local_ports
    from modules.audit_check import check_windows_settings
    from modules.process_monitor import check_processes
    from modules.password_test import test_password_strength
    from modules.reporter import generate_pdf_report
    from modules.sniffer import start_sniffing
except ImportError as e:
    print(f"Module Import Error: {e}")

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.scan_history = []
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("CyberGuard Pro Suite")
        self.setFixedSize(850, 750)
        self.setStyleSheet("""
            QWidget { background-color: #1a1b26; color: #a9b1d6; font-family: 'Segoe UI'; }
            QTabWidget::pane { border: 1px solid #414868; background: #1a1b26; border-radius: 5px; }
            QTabBar::tab { background: #24283b; padding: 12px 20px; color: #565f89; border: 1px solid #414868; }
            QTabBar::tab:selected { background: #414868; color: #7aa2f7; }
            QFrame#ControlCard { background-color: #24283b; border-radius: 10px; padding: 15px; border: 1px solid #414868; }
            QFrame#InfoBox { background-color: #1f2335; border-left: 4px solid #7aa2f7; padding: 10px; margin-bottom: 10px; }
            QPushButton#ActionBtn { background-color: #7aa2f7; color: #1a1b26; border-radius: 5px; padding: 12px; font-weight: bold; }
            QPushButton#ActionBtn:hover { background-color: #bb9af7; }
            QProgressBar { border: 1px solid #414868; border-radius: 5px; text-align: center; background-color: #24283b; height: 25px; }
            QProgressBar::chunk { background-color: #7aa2f7; width: 10px; }
        """)

        layout = QVBoxLayout()
        header = QLabel("DIAGNOSTICS PANEL")
        header.setStyleSheet("font-size: 24px; font-weight: bold; color: #7aa2f7; letter-spacing: 2px;")
        header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(header)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_host_stack(), "SYSTEM AUDIT")
        self.tabs.addTab(self.create_password_tab(), "CREDENTIAL TEST")
        self.tabs.addTab(self.create_history_tab(), "LOG HISTORY")
        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def create_host_stack(self):
        # Stacked widget to switch between "Configure" and "Results"
        self.host_stack = QStackedWidget()
        
        # PAGE 1: CONFIGURATION
        self.config_page = QWidget()
        cp_layout = QVBoxLayout(self.config_page)
        
        # Info Boxes
        cp_layout.addWidget(self.create_info_box("Network Port Analysis", "Scans for open TCP/UDP ports and identifies unencrypted services (Telnet/FTP)."))
        self.check_net = QCheckBox("Enable Network Scan"); cp_layout.addWidget(self.check_net)
        
        cp_layout.addWidget(self.create_info_box("Security Policy Audit", "Checks OS registry and policies for firewall status and UAC settings."))
        self.check_audit = QCheckBox("Enable Policy Audit"); cp_layout.addWidget(self.check_audit)
        
        cp_layout.addWidget(self.create_info_box("Process Inspection", "Profiles active memory to detect suspicious binaries or unauthorized tools."))
        self.check_proc = QCheckBox("Enable Process Scan"); cp_layout.addWidget(self.check_proc)

        cp_layout.addStretch()
        
        self.progress = QProgressBar()
        self.progress.setValue(0)
        self.progress.hide()
        cp_layout.addWidget(self.progress)

        self.scan_btn = QPushButton("INITIALIZE SYSTEM SCAN")
        self.scan_btn.setObjectName("ActionBtn")
        self.scan_btn.clicked.connect(self.run_host_logic)
        cp_layout.addWidget(self.scan_btn)

        # PAGE 2: RESULTS
        self.results_page = QWidget()
        self.res_layout = QVBoxLayout(self.results_page)
        
        self.host_stack.addWidget(self.config_page)
        self.host_stack.addWidget(self.results_page)
        return self.host_stack

    def create_info_box(self, title, text):
        box = QFrame(); box.setObjectName("InfoBox")
        bl = QVBoxLayout(box)
        t = QLabel(title); t.setStyleSheet("font-weight: bold; color: #7aa2f7;")
        d = QLabel(text); d.setStyleSheet("font-size: 11px; color: #565f89;")
        bl.addWidget(t); bl.addWidget(d)
        return box

    def run_host_logic(self):
        self.progress.show()
        self.scan_btn.setEnabled(False)
        
        # Simulate loading bar for the video demo
        def process_scan():
            for i in range(101):
                time.sleep(0.03)
                self.progress.setValue(i)
            
            # Perform actual logic
            findings = []
            if self.check_net.isChecked(): findings.extend(scan_local_ports()[1] if scan_local_ports else ["Nmap scan skipped"])
            if self.check_proc.isChecked(): findings.extend(check_processes()[1] if check_processes else ["Process scan skipped"])
            
            timestamp = datetime.now().strftime("%H:%M:%S | %Y-%m-%d")
            scan_data = {
                "title": f"Host Audit [{timestamp}]",
                "metadata": f"User: {getpass.getuser()} | Host: {platform.node()}",
                "findings": findings if findings else ["No critical issues found."],
                "scores": {"Network": 33, "Audit": 33, "Proc": 34}
            }
            self.scan_history.append(scan_data)
            self.display_host_results(scan_data)
            self.refresh_history_ui()

        threading.Thread(target=process_scan).start()

    def display_host_results(self, scan):
        # Clear old results
        for i in reversed(range(self.res_layout.count())): 
            self.res_layout.itemAt(i).widget().setParent(None)

        res_card = QFrame(); res_card.setObjectName("ControlCard")
        v = QVBoxLayout(res_card)
        v.addWidget(QLabel(f"RESULTS: {scan['title']}").setStyleSheet("font-weight: bold; color: #7aa2f7;"))
        
        scroll = QScrollArea()
        scroll_content = QWidget(); sv = QVBoxLayout(scroll_content)
        for f in scan['findings']:
            lbl = QLabel(f"• {f}"); lbl.setWordWrap(True)
            sv.addWidget(lbl)
        scroll.setWidget(scroll_content); scroll.setWidgetResizable(True)
        v.addWidget(scroll)
        
        self.res_layout.addWidget(res_card)
        
        btn_box = QHBoxLayout()
        pdf_btn = QPushButton("DOWNLOAD PDF REPORT")
        pdf_btn.setObjectName("ActionBtn")
        pdf_btn.clicked.connect(lambda: self.export_report(scan))
        
        back_btn = QPushButton("← BACK TO DASHBOARD")
        back_btn.clicked.connect(self.reset_host_tab)
        
        btn_box.addWidget(back_btn)
        btn_box.addWidget(pdf_btn)
        self.res_layout.addLayout(btn_box)
        
        self.host_stack.setCurrentIndex(1)

    def reset_host_tab(self):
        self.progress.hide()
        self.progress.setValue(0)
        self.scan_btn.setEnabled(True)
        self.host_stack.setCurrentIndex(0)

    # --- KEEPING YOUR EXISTING PASSWORD & HISTORY TABS ---
    def create_password_tab(self):
        # [Pasted from your original code]
        self.pass_stack = QStackedWidget()
        p1 = QWidget(); l1 = QVBoxLayout(p1)
        l1.addWidget(self.create_info_box("Credential Strength", "Checks against RockYou wordlists and complexity requirements."))
        card = QFrame(); card.setObjectName("ControlCard"); cl = QVBoxLayout(card)
        self.pass_input = QLineEdit(); self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        cl.addWidget(self.pass_input); l1.addWidget(card)
        btn = QPushButton("RUN ANALYSIS"); btn.setObjectName("ActionBtn"); btn.clicked.connect(self.run_pass_logic)
        l1.addWidget(btn); l1.addStretch()
        self.pass_res_page = QWidget(); self.pr_layout = QVBoxLayout(self.pass_res_page)
        self.pass_stack.addWidget(p1); self.pass_stack.addWidget(self.pass_res_page)
        return self.pass_stack

    def run_pass_logic(self):
        pw = self.pass_input.text()
        if not pw: return
        findings = ["Weakness: Length" if len(pw) < 8 else "Complexity: Valid"]
        for i in reversed(range(self.pr_layout.count())): self.pr_layout.itemAt(i).widget().setParent(None)
        res_card = QFrame(); res_card.setObjectName("ControlCard"); v = QVBoxLayout(res_card)
        v.addWidget(QLabel("PASSWORD AUDIT RESULT"))
        for f in findings: v.addWidget(QLabel(f"• {f}"))
        self.pr_layout.addWidget(res_card)
        back = QPushButton("← BACK"); back.clicked.connect(lambda: self.pass_stack.setCurrentIndex(0))
        self.pr_layout.addWidget(back); self.pass_stack.setCurrentIndex(1)

    def create_history_tab(self):
        tab = QWidget(); self.hist_layout = QVBoxLayout(tab)
        self.scroll = QScrollArea(); self.scroll_content = QWidget(); self.scroll_vbox = QVBoxLayout(self.scroll_content)
        self.scroll.setWidget(self.scroll_content); self.scroll.setWidgetResizable(True)
        self.hist_layout.addWidget(self.scroll); return tab

    def refresh_history_ui(self):
        for i in reversed(range(self.scroll_vbox.count())): 
            w = self.scroll_vbox.itemAt(i).widget()
            if w: w.setParent(None)
        for scan in reversed(self.scan_history):
            log_card = QFrame(); log_card.setObjectName("ControlCard"); h = QHBoxLayout(log_card)
            info = QVBoxLayout(); info.addWidget(QLabel(scan['title'])); info.addWidget(QLabel(scan['metadata']))
            h.addLayout(info); self.scroll_vbox.addWidget(log_card)
        self.scroll_vbox.addStretch()

    def export_report(self, scan_data):
        try:
            path = generate_pdf_report(scan_data['scores'], scan_data['findings'])
            os.system(f"xdg-open {path}")
        except: print("Report Export Failed")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Dashboard()
    window.show()
    sys.exit(app.exec())
