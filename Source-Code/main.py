import sys
import os
from PyQt6.QtWidgets import QApplication
from gui.dashboard import SecurityDashboard

# Mockup of a Backend Controller to manage your modules
class ToolkitController:
    def __init__(self):
        self.version = "1.0.0"
        self.is_live_usb = os.path.exists("/home/kali") # Detects if on Kali Live

    def run_scan(self, target):
        print(f"Starting Scan on {target}...")
        # This is where you'd call your Nmap/Scapy scripts
        return {"status": "Complete", "threats": 3}

def main():
    # Fix for high-DPI scaling (makes it look better on modern laptop screens)
    os.environ["QT_AUTO_SCREEN_SCALE_FACTOR"] = "1"
    
    app = QApplication(sys.argv)
    app.setStyle("Fusion") 

    # Advanced Touch: Global Hacker-Style Stylesheet
    app.setStyleSheet("""
        QMainWindow { background-color: #121212; }
        QPushButton { 
            background-color: #1e1e1e; 
            color: #00ff00; 
            border: 1px solid #00ff00;
            border-radius: 5px;
            padding: 5px;
        }
        QPushButton:hover { background-color: #00ff00; color: #000; }
        QLabel { color: #ffffff; }
    """)
    
    # Pass the controller to the dashboard so they can talk
    controller = ToolkitController()
    window = SecurityDashboard(controller=controller) 
    
    window.setWindowTitle("Plug-and-Play Security Diagnostics")
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
