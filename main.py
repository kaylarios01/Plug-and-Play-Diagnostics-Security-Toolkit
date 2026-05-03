import sys
import os
from PyQt6.QtWidgets import QApplication, QWidget, QVBoxLayout, QLabel, QPushButton
from PyQt6.QtCore import Qt
from gui.dashboard import Dashboard

class DisclaimerWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Toolkit Consent")
        self.setFixedSize(450, 350)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        
        layout = QVBoxLayout()
        title = QLabel("Security Diagnostics Toolkit")
        title.setStyleSheet("font-size: 18px; font-weight: bold; color: #50fa7b;")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        layout.addWidget(title)

        text = QLabel(
            "This tool is for our local educational use.\n\n"
            "• It only scans this computer.\n"
            "• No data leaves this USB.\n"
            "• Use it only on machines we have permission to test.\n\n"
            "By clicking 'I Accept', we agree to these terms."
        )
        text.setWordWrap(True)
        layout.addWidget(text)

        self.accept_btn = QPushButton("I Accept")
        self.accept_btn.setStyleSheet("""
            QPushButton { background-color: #50fa7b; color: #2b2b2b; font-weight: bold; padding: 10px; border-radius: 5px; }
            QPushButton:hover { background-color: #40c060; }
        """)
        self.accept_btn.clicked.connect(self.launch_app)
        layout.addWidget(self.accept_btn)

        self.setLayout(layout)

    def launch_app(self):
        self.dashboard = Dashboard()
        self.dashboard.show()
        self.close()

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")
    
    # Ensure the app knows where to find our folders
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.append(current_dir)
    
    win = DisclaimerWindow()
    win.show()
    sys.exit(app.exec())
