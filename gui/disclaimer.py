import sys
from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QFrame, QScrollArea
from PyQt6.QtCore import Qt

class DisclaimerWindow(QWidget):
    def __init__(self, on_accept_callback):
        super().__init__()
        self.on_accept = on_accept_callback
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Sentinel-X | Security Consent")
        self.setFixedSize(550, 450)
        
        # --- TOKYO NIGHT / SENTINEL-X STYLING ---
        self.setStyleSheet("""
            QWidget { background-color: #1a1b26; color: #a9b1d6; font-family: 'Segoe UI'; }
            QFrame#MainCard { background-color: #24283b; border-radius: 12px; border: 1px solid #414868; padding: 20px; }
            QLabel#WarningTitle { font-size: 22px; font-weight: bold; color: #f7768e; letter-spacing: 1px; }
            QPushButton#AcceptBtn { background-color: #73daca; color: #1a1b26; border-radius: 6px; padding: 15px; font-weight: bold; font-size: 14px; }
            QPushButton#AcceptBtn:hover { background-color: #9ece6a; }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(25, 25, 25, 25)

        card = QFrame()
        card.setObjectName("MainCard")
        card_layout = QVBoxLayout(card)

        title = QLabel("ETHICAL USAGE AGREEMENT")
        title.setObjectName("WarningTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)

        text = QLabel(
            "This toolkit is designed for AUTHORIZED security auditing and educational purposes only.\n\n"
            "By proceeding, you acknowledge:\n"
            "• You have explicit permission to audit this host system.\n"
            "• You will not use these tools for malicious intent or unauthorized access.\n"
            "• Sentinel-X operates as a 'Zero-Footprint' utility; no data is sent externally.\n\n"
            "The developers are not responsible for any misuse or system damage."
        )
        text.setWordWrap(True)
        text.setStyleSheet("font-size: 13px; line-height: 1.6; color: #c0caf5; margin-top: 10px;")
        card_layout.addWidget(text)
        
        layout.addWidget(card)

        self.accept_btn = QPushButton("I AGREE & INITIALIZE SYSTEM")
        self.accept_btn.setObjectName("AcceptBtn")
        self.accept_btn.clicked.connect(self.handle_accept)
        layout.addWidget(self.accept_btn)

        self.setLayout(layout)

    def handle_accept(self):
        self.on_accept() # Triggers the dashboard launch
        self.close()
