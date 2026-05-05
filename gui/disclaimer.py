import sys
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QFrame, QScrollArea
from PyQt6.QtCore import Qt

class DisclaimerWindow(QWidget):
    def __init__(self, on_accept_callback):
        super().__init__()
        self.on_accept = on_accept_callback
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("CyberGuard Pro | Legal Authorization")
        self.setFixedSize(600, 500)
        
        self.setStyleSheet("""
            QWidget { background-color: #1a1b26; color: #a9b1d6; font-family: 'Segoe UI'; }
            QFrame#MainCard { background-color: #24283b; border-radius: 12px; border: 1px solid #414868; padding: 20px; }
            QLabel#WarningTitle { font-size: 20px; font-weight: bold; color: #f7768e; letter-spacing: 1px; }
            QPushButton#AcceptBtn { background-color: #73daca; color: #1a1b26; border-radius: 6px; padding: 15px; font-weight: bold; font-size: 14px; }
            QPushButton#AcceptBtn:hover { background-color: #9ece6a; }
        """)

        layout = QVBoxLayout()
        card = QFrame()
        card.setObjectName("MainCard")
        card_layout = QVBoxLayout(card)

        title = QLabel("LEGAL NOTICE & PRIVACY POLICY")
        title.setObjectName("WarningTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("border: none; background: transparent;")
        
        content = QWidget()
        content_layout = QVBoxLayout(content)
        
        legal_text = QLabel(
            "<b>1. AUTHORIZATION:</b> This toolkit is provided for professional security auditing. "
            "By clicking 'I AGREE', you confirm that you have explicit, written permission to perform "
            "diagnostic scans on this host and its associated network.<br><br>"
            "<b>2. SCOPE OF WORK:</b> The diagnostics performed include port analysis, credential "
            "complexity testing, and system process auditing. These actions can trigger security alerts "
            "on managed networks.<br><br>"
            "<b>3. LIABILITY:</b> The developers of CyberGuard Pro disclaim all liability for any "
            "unauthorized use, data loss, or system instability resulting from the use of these tools. "
            "The user assumes 100% of the risk associated with penetration testing and vulnerability assessment.<br><br>"
            "<b>4. DATA PRIVACY:</b> This tool operates in an isolated environment. No data is harvested, "
            "stored externally, or transmitted. All reports are saved locally to the persistent USB volume."
        )
        legal_text.setWordWrap(True)
        legal_text.setStyleSheet("font-size: 13px; color: #c0caf5;")
        content_layout.addWidget(legal_text)
        scroll.setWidget(content)
        card_layout.addWidget(scroll)

        layout.addWidget(card)

        self.accept_btn = QPushButton("I AGREE")
        self.accept_btn.setObjectName("AcceptBtn")
        self.accept_btn.clicked.connect(self.handle_accept)
        layout.addWidget(self.accept_btn)
        
        self.setLayout(layout)

    def handle_accept(self):
        self.on_accept()
        self.close()
