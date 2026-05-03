from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QScrollArea, QFrame
from PyQt6.QtCore import Qt

class ResultsView(QWidget):
    def __init__(self, scores, findings):
        super().__init__()
        self.scores = scores
        self.findings = findings
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Security Assessment Report")
        self.setFixedSize(500, 650)
        self.setStyleSheet("background-color: #282a36; color: #f8f8f2;")

        layout = QVBoxLayout()

        # Overall Score Explanation
        total_score = sum(self.scores.values())
        
        # Color Logic
        if total_score >= 80: color, label = "#50fa7b", "SECURE"
        elif total_score >= 50: color, label = "#f1fa8c", "VULNERABLE"
        else: color, label = "#ff5555", "CRITICAL DANGER"

        score_header = QLabel(f"Overall Safety Score: {total_score}/100")
        score_header.setStyleSheet(f"font-size: 24px; font-weight: bold; color: {color};")
        score_header.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(score_header)

        desc = QLabel(f"Rating: {label}\n(100 is perfectly secure, 0 is highly at risk)")
        desc.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(desc)

        # Findings Area
        layout.addWidget(QLabel("\nDetailed Security Findings:"))
        scroll = QScrollArea()
        content = QWidget()
        scroll_layout = QVBoxLayout(content)

        if not self.findings:
            scroll_layout.addWidget(QLabel("✓ No security issues found."))
        else:
            for item in self.findings:
                finding_lbl = QLabel(f"• {item}")
                finding_lbl.setWordWrap(True)
                finding_lbl.setStyleSheet("color: #ffb86c; margin-bottom: 5px;")
                scroll_layout.addWidget(finding_lbl)

        scroll.setWidget(content)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        # NAVIGATION BUTTONS
        btn_layout = QVBoxLayout()
        
        self.back_btn = QPushButton("← Test Another Password / Scan Again")
        self.back_btn.setStyleSheet("""
            QPushButton { background-color: #6272a4; padding: 12px; border-radius: 5px; font-weight: bold; }
            QPushButton:hover { background-color: #44475a; }
        """)
        self.back_btn.clicked.connect(self.go_back)
        btn_layout.addWidget(self.back_btn)

        layout.addLayout(btn_layout)
        self.setLayout(layout)

    def go_back(self):
        # This re-opens the main dashboard
        from gui.dashboard import Dashboard
        self.main_dash = Dashboard()
        self.main_dash.show()
        self.close()
