import sys
import os
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton, QMessageBox
from PyQt6.QtCore import Qt

class DisclaimerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Toolkit Consent & Safety")
        self.setFixedSize(450, 350)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        
        layout = QVBoxLayout()

        title = QLabel("Security Diagnostics Toolkit")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #50fa7b;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        disclaimer_text = QLabel(
            "This tool is designed to help you understand your computer's safety.\n\n"
            "• It only scans the machine it is currently connected to.\n"
            "• No data is sent to the internet; everything stays on this USB.\n"
            "• Use this tool only on devices you own or have permission to test.\n\n"
            "By clicking 'I Accept', you agree to these terms."
        )
        disclaimer_text.setWordWrap(True)
        disclaimer_text.setStyleSheet("font-size: 13px; line-height: 1.5;")
        layout.addWidget(disclaimer_text)

        # Action Buttons
        self.accept_btn = QPushButton("I Accept")
        self.accept_btn.setStyleSheet("""
            QPushButton { background-color: #50fa7b; color: #2b2b2b; font-weight: bold; padding: 10px; border-radius: 5px; }
            QPushButton:hover { background-color: #40c46b; }
        """)
        self.accept_btn.clicked.connect(self.start_dashboard)
        layout.addWidget(self.accept_btn)

        self.exit_btn = QPushButton("Exit")
        self.exit_btn.setStyleSheet("color: #ff5555; text-decoration: underline; background: transparent;")
        self.exit_btn.clicked.connect(sys.exit)
        layout.addWidget(self.exit_btn)

        self.setLayout(layout)

    def start_dashboard(self):
        print("Terms Accepted. Proceeding to Dashboard...")
        self.close()
        QMessageBox.information(self, "Success", "Launching Dashboard... (Next step)")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    window = DisclaimerWindow()
    window.show()
    
    sys.exit(app.exec())
