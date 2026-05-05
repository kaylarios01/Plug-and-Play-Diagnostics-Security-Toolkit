import sys
import re
import os
import platform
import getpass
import threading
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QLabel, 
                             QPushButton, QFrame, QLineEdit, QTabWidget, QStackedWidget, 
                             QScrollArea, QApplication)
from PyQt6.QtCore import Qt

try:
    from modules.network_scan import scan_local_ports
    from modules.audit_check import check_windows_settings
    from modules.process_monitor import check_processes
    from modules.password_test import test_password_strength
    from modules.reporter import generate_pdf_report
    from modules.sniffer import start_sniffing # Added Sniffer module
except ImportError:
    print("Warning: Some modules could not be imported. Ensure 'modules' folder exists.")

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
            QTabBar::tab { background: #24283b; padding: 15px 25px; color: #565f89; border: 1px solid #414868; }
            QTabBar::tab:selected { background: #414868; color: #7aa2f7; border-bottom: 2px solid #7aa2f7; }
            QFrame#ControlCard { background-color: #24283b; border-radius: 10px; padding: 20px; border: 1px solid #414868; }
            QPushButton#ActionBtn { background-color: #7aa2f7; color: #1a1b26; border-radius: 5px; padding: 12px; font-weight: bold; }
            QPushButton#ActionBtn:hover { background-color: #bb9af7; }
            QLineEdit { background-color: #1a1b26; border: 1px solid #414868; border-radius: 4px; padding: 10px; color: #c0caf5; }
        """)

        layout = QVBoxLayout()
        title = QLabel("CYBERGUARD PRO : DIAGNOSTICS")
        title.setStyleSheet("font-size: 26px; font-weight: bold; color: #7aa2f7; letter-spacing: 2px; margin-top: 15px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)
        
        subtitle = QLabel("SECURE ISOLATED AUDIT ENVIRONMENT")
        subtitle.setStyleSheet("font-size: 10px; color: #565f89; margin-bottom: 10px;")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(subtitle)

        self.tabs = QTabWidget()
        self.tabs.addTab(self.create_host_tab(), "HOST AUDIT")
        self.tabs.addTab(self.create_password_tab(), "CREDENTIAL TEST")
        self.tabs.addTab(self.create_history_tab(), "LOG HISTORY")
        layout.addWidget(self.tabs)
        self.setLayout(layout)

    def create_host_tab(self):
        tab = QWidget()
        l = QVBoxLayout(tab)
        l.addWidget(QLabel("Analyze the local machine for configuration weaknesses."))
        card = QFrame()
        card.setObjectName("ControlCard")
        cl = QVBoxLayout(card)
        self.check_net = QCheckBox("Network Port Analysis")
        self.check_audit = QCheckBox("Security Policy Audit")
        self.check_proc = QCheckBox("Process Inspection")
        self.check_sniff = QCheckBox("Live Traffic Monitoring (Sniffer)") # Added Sniffer Checkbox
        for cb in [self.check_net, self.check_audit, self.check_proc, self.check_sniff]:
            cl.addWidget(cb)
        l.addWidget(card)
        l.addStretch()
        btn = QPushButton("INITIALIZE SYSTEM SCAN")
        btn.setObjectName("ActionBtn")
        btn.clicked.connect(self.run_host_logic)
        l.addWidget(btn)
        return tab

    def create_password_tab(self):
        self.pass_stack = QStackedWidget()
        p1 = QWidget()
        l1 = QVBoxLayout(p1)
        l1.setSpacing(10)
        l1.setContentsMargins(20, 20, 20, 20)
        desc = QLabel("Stress-test credentials against complexity rules and known leaks.")
        desc.setStyleSheet("color: #565f89; font-style: italic; margin-bottom: 5px;")
        l1.addWidget(desc)
        card = QFrame()
        card.setObjectName("ControlCard")
        cl = QVBoxLayout(card)
        cl.addWidget(QLabel("ENTER CREDENTIALS (MASKED)"))
        self.pass_input = QLineEdit()
        self.pass_input.setEchoMode(QLineEdit.EchoMode.Password)
        self.pass_input.setPlaceholderText("••••••••••••")
        cl.addWidget(self.pass_input)
        l1.addWidget(card)
        btn = QPushButton("RUN ANALYSIS")
        btn.setObjectName("ActionBtn")
        btn.clicked.connect(self.run_pass_logic)
        l1.addWidget(btn)
        l1.addStretch()
        self.pass_res_page = QWidget()
        self.pr_layout = QVBoxLayout(self.pass_res_page)
        self.pr_layout.setContentsMargins(20, 20, 20, 20)
        self.pass_stack.addWidget(p1)
        self.pass_stack.addWidget(self.pass_res_page)
        return self.pass_stack

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

    def run_pass_logic(self):
        pw = self.pass_input.text()
        if not pw: return
        findings, recommendations, score = [], [], 100
        if len(pw) < 10:
            findings.append("Critical: Length below 10 characters.")
            recommendations.append("Increase length to at least 12-16 characters.")
            score -= 30
        if not re.search(r"[A-Z]", pw):
            findings.append("Weakness: No uppercase letters.")
            score -= 10
        if not re.search(r"\d", pw):
            findings.append("Weakness: No numbers.")
            score -= 10
        
        for i in reversed(range(self.pr_layout.count())):
            self.pr_layout.itemAt(i).widget().setParent(None)
        res_card = QFrame()
        res_card.setObjectName("ControlCard")
        v = QVBoxLayout(res_card)
        v.addWidget(QLabel(f"STRENGTH SCORE: {max(0, score)}/100"))
        for fin in findings: v.addWidget(QLabel(f"• {fin}"))
        self.pr_layout.addWidget(res_card)
        back = QPushButton("← TEST ANOTHER")
        back.setObjectName("ActionBtn")
        back.clicked.connect(lambda: self.pass_stack.setCurrentIndex(0))
        self.pr_layout.addWidget(back)
        self.pass_stack.setCurrentIndex(1)

    def run_host_logic(self):
        timestamp = datetime.now().strftime("%H:%M:%S | %Y-%m-%d")
        findings = []
        
        if self.check_sniff.isChecked():
            # Run sniffer in a separate thread so GUI doesn't freeze
            threading.Thread(target=start_sniffing, args=("eth0",), daemon=True).start()
            findings.append("Monitoring: Network Sniffer initialized on eth0")

        scan_data = {
            "title": f"Host Audit [{timestamp}]",
            "metadata": f"User: {getpass.getuser()} | Host: {platform.node()}",
            "findings": findings if findings else ["System Baseline Audit Initiated"],
            "scores": {"Network": 33, "Registry": 33, "Processes": 34}
        }
        self.scan_history.append(scan_data)
        self.refresh_history_ui()

    def export_report(self, scan_data):
        try:
            os.makedirs("reports", exist_ok=True)
            path = generate_pdf_report(scan_data['scores'], scan_data['findings'])
            print(f"Report saved: {path}")
            os.system(f"xdg-open {path}")
        except Exception as e:
            print(f"Report Error: {e}")

    def refresh_history_ui(self):
        for i in reversed(range(self.scroll_vbox.count())):
            widget = self.scroll_vbox.itemAt(i).widget()
            if widget: widget.setParent(None)
        for scan in reversed(self.scan_history):
            log_card = QFrame()
            log_card.setObjectName("ControlCard")
            h_layout = QHBoxLayout(log_card)
            info_layout = QVBoxLayout()
            info_layout.addWidget(QLabel(scan['title']))
            info_layout.addWidget(QLabel(scan['metadata']))
            
            btn_layout = QVBoxLayout()
            pdf_btn = QPushButton("DOWNLOAD PDF")
            pdf_btn.clicked.connect(lambda checked, s=scan: self.export_report(s))
            btn_layout.addWidget(pdf_btn)
            
            h_layout.addLayout(info_layout)
            h_layout.addLayout(btn_layout)
            self.scroll_vbox.addWidget(log_card)
        self.scroll_vbox.addStretch()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = Dashboard()
    window.show()
    sys.exit(app.exec())
