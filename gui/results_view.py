from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                             QPushButton, QScrollArea, QFrame)
from PyQt6.QtCore import Qt

class ResultsView(QWidget):
    def __init__(self, scores, findings):
        super().__init__()
        self.scores = scores 
        self.findings = findings 
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Our Security Analysis Results")
        self.setFixedSize(600, 700)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        
        layout = QVBoxLayout()

        score_layout = QVBoxLayout()
        total_score = sum(self.scores.values())
        
        self.gauge_label = QLabel(f"{total_score}%")
        color = "#50fa7b" if total_score > 89 else "#f1fa8c" if total_score > 59 else "#ff5555"
        self.gauge_label.setStyleSheet(f"font-size: 48px; font-weight: bold; color: {color};")
        self.gauge_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        
        score_layout.addWidget(QLabel("Our Overall Safety Score:"))
        score_layout.addWidget(self.gauge_label)
        layout.addLayout(score_layout)

        layout.addWidget(QLabel("What we found:"))
        scroll = QScrollArea()
        scroll_content = QWidget()
        scroll_layout = QVBoxLayout()

        for item in self.findings:
            row = QHBoxLayout()
            row_label = QLabel(f"• {item}")
            row_label.setWordWrap(True)
            
            fix_btn = QPushButton("Quick Fix")
            fix_btn.setStyleSheet("background-color: #ffb86c; color: #2b2b2b; font-weight: bold; padding: 5px;")
            fix_btn.setFixedWidth(80)
            
            row.addWidget(row_label)
            row.addWidget(fix_btn)
            scroll_layout.addLayout(row)

        scroll_content.setLayout(scroll_layout)
        scroll.setWidget(scroll_content)
        scroll.setWidgetResizable(True)
        layout.addWidget(scroll)

        self.pdf_btn = QPushButton("Download Our PDF Report to USB")
        self.pdf_btn.setStyleSheet("background-color: #50fa7b; color: #2b2b2b; font-size: 16px; padding: 10px;")
        layout.addWidget(self.pdf_btn)

        self.setLayout(layout)
