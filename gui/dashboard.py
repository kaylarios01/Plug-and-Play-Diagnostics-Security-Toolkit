import sys
import os
import platform
import getpass
import threading
import time
from datetime import datetime
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, QLabel, 
                             QPushButton, QFrame, QLineEdit, QTabWidget, QStackedWidget, 
                             QScrollArea, QApplication, QProgressBar, QComboBox, QDialog)
from PyQt6.QtCore import Qt, QTimer, pyqtSignal, QObject

# --- MODULE IMPORTS ---
try:
    from modules.network_scan import scan_local_ports
    from modules.audit_check import check_windows_settings
    from modules.process_monitor import check_processes
    from modules.password_test import test_password_strength
    from modules.reporter import generate_pdf_report, get_remediation
    from modules.sniffer import start_sniffing
except ImportError as e:
    print(f"Module Import Error: {e}")

# --- REMEDIATION POP-UP CLASS ---
class RemediationDialog(QDialog):
    def __init__(self, findings, parent=None):
        super().__init__(parent)
        self.setWindowTitle("CyberGuard Pro | Actionable Remediation")
        self.setFixedSize(550, 500)
        self.setStyleSheet("background-color: #1a1b26; color: #a9b1d6;")
        
        layout = QVBoxLayout(self)
        title = QLabel("REMEDIATION STEPS")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #73daca; margin-bottom: 10px;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        content = QWidget()
        vbox = QVBoxLayout(content)

        for f in findings:
            card = QFrame()
            card.setStyleSheet("background-color: #24283b; border-radius: 8px; padding: 12px; margin-bottom: 8px; border: 1px solid #414868;")
            cv = QVBoxLayout(card)
            
            f_lbl = QLabel(f"<b>FINDING:</b> {f}")
            f_lbl.setWordWrap(True)
            
            advice = get_remediation(f)
            a_lbl = QLabel(f"<b>FIX:</b> {advice}")
            a_lbl.setStyleSheet("color: #7aa2f7;")
            a_lbl.setWordWrap(True)
            
            cv.addWidget(f_lbl)
            cv.addWidget(a_lbl)
            vbox.addWidget(card)

        scroll.setWidget(content)
        layout.addWidget(scroll)
        
        close_btn = QPushButton("CLOSE")
        close_btn.setStyleSheet("background-color: #414868; padding: 10px; border-radius: 5px; font-weight: bold;")
        close_btn.clicked.connect(self.accept)
        layout.addWidget(close_btn)

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
            QPushButton#ResetBtn { background-color: #f7768e; color: #1a1b26; border-radius: 5px; padding: 5px; font-weight: bold; }
            QProgressBar { border: 1px solid #414868; border-radius: 5px; text-align: center; background-color: #24283b; height: 25px; }
            QProgressBar::chunk { background-color: #7aa2f7; width: 10px; }
            QComboBox { background-color: #1a1b26; border: 1px solid #414868; padding: 5px; color: #c0caf5; }
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
        self.host_stack = QStackedWidget()
        self.config_page = QWidget()
        cp_layout = QVBoxLayout(self.config_page)

        cp_layout.addWidget(self.create_info_box("Network Port Analysis", "Scans for open TCP/UDP ports and identifies unencrypted services (Telnet/FTP)."))
        self.check_net = QCheckBox("Enable Network Scan"); cp_layout.addWidget(self.check_net)
        cp_layout.addWidget(self.create_info_box("Security Policy Audit", "Checks OS registry and policies for firewall status and UAC settings."))
        self.check_audit = QCheckBox("Enable Policy Audit"); cp_layout.addWidget(self.check_audit)
        cp_layout.addWidget(self.create_info_box("Process Inspection", "Profiles active memory to detect suspicious binaries or unauthorized tools."))
        self.check_proc = QCheckBox("Enable Process Scan"); cp_layout.addWidget(self.check_proc)

        cp_layout.addStretch()
        self.progress = QProgressBar()
        self.progress.setValue(0); self.progress.hide()
        cp_layout.addWidget(self.progress)

        self.scan_btn = QPushButton("INITIALIZE SYSTEM SCAN")
        self.scan_btn.setObjectName("ActionBtn")
        self.scan_btn.clicked.connect(self.run_host_logic)
        cp_layout.addWidget(self.scan_btn)

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
        self.progress.show(); self.scan_btn.setEnabled(False)
        def process_scan():
            for i in range(101):
                time.sleep(0.02)
                self.progress.setValue(i)
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
        for i in reversed(range(self.res_layout.count())): self.res_layout.itemAt(i).widget().setParent(None)
        res_card = QFrame(); res_card.setObjectName("ControlCard")
        v = QVBoxLayout(res_card)
        v.addWidget(QLabel(f"RESULTS: {scan['title']}").setStyleSheet("font-weight: bold; color: #7aa2f7;"))
        scroll = QScrollArea()
        scroll_content = QWidget(); sv = QVBoxLayout(scroll_content)
        for f in scan['findings']:
            lbl = QLabel(f"• {f}"); lbl.setWordWrap(True); sv.addWidget(lbl)
        scroll.setWidget(scroll_content); scroll.setWidgetResizable(True)
        v.addWidget(scroll)
        self.res_layout.addWidget(res_card)
        btn_box = QHBoxLayout()
        pdf_btn = QPushButton("DOWNLOAD PDF REPORT"); pdf_btn.setObjectName("ActionBtn")
        pdf_btn.clicked.connect(lambda: self.export_report(scan))
        back_btn = QPushButton("← BACK TO DASHBOARD"); back_btn.clicked.connect(self.reset_host_tab)
        btn_box.addWidget(back_btn); btn_box.addWidget(pdf_btn)
        self.res_layout.addLayout(btn_box)
        self.host_stack.setCurrentIndex(1)

    def reset_host_tab(self):
        self.progress.hide(); self.progress.setValue(0); self.scan_btn.setEnabled(True)
        self.host_stack.setCurrentIndex(0)

    def create_password_tab(self):
        self.pass_stack = QStackedWidget()
        p1 = QWidget(); l1 = QVBoxLayout(p1)
        l1.addWidget(self.create_info_box("Credential Strength", "Checks against wordlists and complexity requirements."))
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
        
        findings = []
        score = 100

        # --- 1. Internal Complexity Checks ---
        if len(pw) < 10:
            findings.append("Weakness: Length below 10 characters.")
            score -= 20
        if not re.search(r"[A-Z]", pw):
            findings.append("Weakness: No uppercase letters.")
            score -= 10
        if not re.search(r"\d", pw):
            findings.append("Weakness: No numbers.")
            score -= 10

        # --- 2. Call the RockYou Module ---
        if test_password_strength:
            deduction, leak_findings = test_password_strength(pw)
            score -= deduction
            findings.extend(leak_findings)

        # --- 3. Update the UI ---
        for i in reversed(range(self.pr_layout.count())):
            self.pr_layout.itemAt(i).widget().setParent(None)

        res_card = QFrame()
        res_card.setObjectName("ControlCard")
        v = QVBoxLayout(res_card)
        
        # Color coding the score
        color = "#f7768e" if score < 60 else "#73daca"
        score_lbl = QLabel(f"STRENGTH SCORE: {max(0, score)}/100")
        score_lbl.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {color};")
        v.addWidget(score_lbl)

        for f in findings:
            v.addWidget(QLabel(f"• {f}"))
            
        self.pr_layout.addWidget(res_card)
        back = QPushButton("← BACK")
        back.clicked.connect(lambda: self.pass_stack.setCurrentIndex(0))
        self.pr_layout.addWidget(back)
        self.pass_stack.setCurrentIndex(1)

    def create_history_tab(self):
        tab = QWidget(); self.hist_layout = QVBoxLayout(tab)
        
        # --- AVERAGE SAFETY SCORE PANEL ---
        self.avg_card = QFrame(); self.avg_card.setObjectName("ControlCard")
        self.avg_card.setStyleSheet("background-color: #1f2335; border-radius: 8px; border: 1px solid #7aa2f7;")
        avg_l = QHBoxLayout(self.avg_card)
        self.avg_label = QLabel("GLOBAL SAFETY AVERAGE: 0%")
        self.avg_label.setStyleSheet("font-size: 16px; font-weight: bold; color: #73daca;")
        avg_l.addWidget(self.avg_label, alignment=Qt.AlignmentFlag.AlignCenter)
        self.hist_layout.addWidget(self.avg_card)

        # Filter Bar
        filter_bar = QFrame(); filter_bar.setStyleSheet("background-color: #24283b; border-radius: 5px; border: 1px solid #414868;")
        fb_layout = QHBoxLayout(filter_bar)
        self.search_bar = QLineEdit(); self.search_bar.setPlaceholderText("Search...")
        self.search_bar.textChanged.connect(self.refresh_history_ui)
        fb_layout.addWidget(self.search_bar, stretch=2)
        self.date_filter = QComboBox(); self.date_filter.addItems(["Newest First", "Oldest First"])
        self.type_filter = QComboBox(); self.type_filter.addItems(["All Scans", "Host Audit", "Password Audit"])
        self.risk_filter = QComboBox(); self.risk_filter.addItems(["All Risk", "High Risk", "Safe"])
        for w in [self.date_filter, self.type_filter, self.risk_filter]:
            w.currentIndexChanged.connect(self.refresh_history_ui); fb_layout.addWidget(w)
        clear_btn = QPushButton("CLEAR"); clear_btn.setObjectName("ResetBtn"); clear_btn.clicked.connect(self.clear_all_filters)
        fb_layout.addWidget(clear_btn); self.hist_layout.addWidget(filter_bar)

        self.scroll = QScrollArea(); self.scroll_content = QWidget(); self.scroll_vbox = QVBoxLayout(self.scroll_content)
        self.scroll.setWidget(self.scroll_content); self.scroll.setWidgetResizable(True)
        self.hist_layout.addWidget(self.scroll); return tab

    def clear_all_filters(self):
        self.search_bar.clear(); self.date_filter.setCurrentIndex(0); self.type_filter.setCurrentIndex(0); self.risk_filter.setCurrentIndex(0)
        self.refresh_history_ui()

    def refresh_history_ui(self):
        for i in reversed(range(self.scroll_vbox.count())): 
            w = self.scroll_vbox.itemAt(i).widget(); 
            if w: w.setParent(None)

        if not self.scan_history:
            self.avg_label.setText("GLOBAL SAFETY AVERAGE: N/A")
            return

        # Update Average
        total_sum = sum([sum(s['scores'].values()) for s in self.scan_history])
        avg = total_sum // len(self.scan_history)
        self.avg_label.setText(f"GLOBAL SAFETY AVERAGE: {avg}%")

        search = self.search_bar.text().lower()
        stype = self.type_filter.currentText()
        risk_lvl = self.risk_filter.currentText()

        filtered = []
        for s in self.scan_history:
            score = sum(s['scores'].values())
            match_search = search in s['title'].lower() or search in s['metadata'].lower()
            match_type = stype == "All Scans" or stype.split()[0].lower() in s['title'].lower()
            match_risk = True
            if risk_lvl == "High Risk": match_risk = score < 50
            elif risk_lvl == "Safe": match_risk = score > 80
            if match_search and match_type and match_risk: filtered.append(s)

        filtered.sort(key=lambda x: x['title'], reverse=(self.date_filter.currentIndex()==0))

        for scan in filtered:
            score = sum(scan['scores'].values())
            color = "#f7768e" if score < 50 else "#73daca"
            log_card = QFrame(); log_card.setObjectName("ControlCard"); h = QHBoxLayout(log_card)
            
            # LEFT: SCORE
            score_lbl = QLabel(f"{score}%"); score_lbl.setFixedWidth(50)
            score_lbl.setStyleSheet(f"font-size: 18px; font-weight: bold; color: {color};")
            h.addWidget(score_lbl)

            # MIDDLE: INFO
            info = QVBoxLayout()
            t_lbl = QLabel(scan['title']); t_lbl.setStyleSheet(f"font-weight: bold; color: #a9b1d6;")
            info.addWidget(t_lbl); info.addWidget(QLabel(scan['metadata']))
            h.addLayout(info, stretch=2)

            # RIGHT: ACTIONS
            btn_layout = QHBoxLayout()
            fix_btn = QPushButton("FIX"); fix_btn.setFixedWidth(60)
            fix_btn.setStyleSheet("background-color: #7aa2f7; color: #1a1b26; font-weight: bold;")
            fix_btn.clicked.connect(lambda checked, s=scan: self.show_remediation(s))
            
            pdf_btn = QPushButton("PDF"); pdf_btn.setFixedWidth(60)
            pdf_btn.clicked.connect(lambda checked, s=scan: self.export_report(s))
            
            btn_layout.addWidget(fix_btn); btn_layout.addWidget(pdf_btn)
            h.addLayout(btn_layout)
            self.scroll_vbox.addWidget(log_card)
        self.scroll_vbox.addStretch()

    def show_remediation(self, scan):
        self.rem_popup = RemediationDialog(scan['findings'], self)
        self.rem_popup.exec()

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
