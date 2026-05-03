from PyQt6.QtWidgets import QWidget, QVBoxLayout, QLabel, QPushButton, QFrame, QScrollArea
from PyQt6.QtCore import Qt

class DisclaimerWindow(QWidget):
    def __init__(self, on_accept_callback):
        super().__init__()
        self.on_accept = on_accept_callback
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Sentinel-X | Legal Notice")
        self.setFixedSize(600, 500)
        
        # --- MATCHING SENTINEL-X STYLING ---
        self.setStyleSheet("""
            QWidget { background-color: #1a1b26; color: #a9b1d6; font-family: 'Segoe UI'; }
            QFrame#MainCard { background-color: #24283b; border-radius: 12px; border: 1px solid #414868; }
            QLabel#WarningTitle { font-size: 22px; font-weight: bold; color: #f7768e; letter-spacing: 1px; }
            QPushButton#AcceptBtn { background-color: #73daca; color: #1a1b26; border-radius: 6px; padding: 12px; font-weight: bold; }
            QPushButton#AcceptBtn:hover { background-color: #9ece6a; }
            QScrollArea { border: none; background-color: transparent; }
        """)

        layout = QVBoxLayout()
        layout.setContentsMargins(30, 30, 30, 30)

        # Main Container
        card = QFrame()
        card.setObjectName("MainCard")
        card_layout = QVBoxLayout(card)

        # Header
        title = QLabel("ETHICAL USAGE AGREEMENT")
        title.setObjectName("WarningTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        card_layout.addWidget(title)

        # Scrollable Disclaimer Text
        scroll = QScrollArea()
        content = QLabel(
            "This toolkit is designed for AUTHORIZED security auditing and educational "
            "purposes ONLY.\n\n"
            "By proceeding, you acknowledge:\n"
            "1. You have explicit permission to audit the host system.\n"
            "2. You will not use these tools for malicious intent.\n"
            "3. The developers are not responsible for any misuse or damage.\n\n"
            "Sentinel-X is a 'Zero-Footprint' utility. No data is transmitted externally."
        )
        content.setWordWrap(True)
        content.setStyleSheet("font-size: 13px; line-height: 1.5; color: #c0caf5;")
        scroll.setWidget(content)
        card_layout.addWidget(scroll)

        layout.addWidget(card)

        # Accept Button
        self.btn = QPushButton("I AGREE & INITIALIZE SYSTEM")
        self.btn.setObjectName("AcceptBtn")
        self.btn.clicked.connect(self.accept_terms)
        layout.addWidget(self.btn)

        self.setLayout(layout)

    def accept_terms(self):
        self.on_accept()
        self.close()
