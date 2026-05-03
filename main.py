import sys
import os
from PyQt6.QtWidgets import QApplication
from gui.disclaimer import DisclaimerWindow
from gui.dashboard import Dashboard

class AppController:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setStyle("Fusion")
        
        # Ensure pathing is correct for USB execution
        current_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.append(current_dir)

        # 1. Start with the Disclaimer
        # We pass the show_dashboard function as a 'callback'
        self.disclaimer = DisclaimerWindow(on_accept_callback=self.show_dashboard)
        self.disclaimer.show()
        
        sys.exit(self.app.exec())

    def show_dashboard(self):
        # 2. Launch the Dashboard only after Consent
        self.main_window = Dashboard()
        self.main_window.show()

if __name__ == "__main__":
    AppController()
