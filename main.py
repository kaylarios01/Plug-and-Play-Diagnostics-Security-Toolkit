import sys
import os
import site

# --- CRITICAL USB PATH FIX ---
# 1. Get the absolute path to the USB folder
root_path = os.path.dirname(os.path.abspath(__file__))

# 2. Force Python to see the root and modules folder first
if root_path not in sys.path:
    sys.path.insert(0, root_path)
    sys.path.insert(0, os.path.join(root_path, 'modules'))

# 3. Force Python to see system-installed libraries (like nmap)
sys.path.extend(site.getsitepackages())

# --- STANDARD IMPORTS ---
from PyQt6.QtWidgets import QApplication
from gui.disclaimer import DisclaimerWindow
from gui.dashboard import Dashboard

class SentinelController:
    def __init__(self):
        self.app = QApplication(sys.argv)
        self.app.setStyle("Fusion")
        
        # Start with the Disclaimer
        self.disclaimer = DisclaimerWindow(on_accept_callback=self.show_dashboard)
        self.disclaimer.show()
        
        sys.exit(self.app.exec())

    def show_dashboard(self):
        if hasattr(self, 'disclaimer'):
            self.disclaimer.close()
            
        self.main_toolkit = Dashboard()
        self.main_toolkit.show()

if __name__ == "__main__":
    SentinelController()
