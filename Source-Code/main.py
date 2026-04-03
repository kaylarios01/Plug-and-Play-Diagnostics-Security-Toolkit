import sys
from PyQt6.QtWidgets import QApplication
# Import the Dashboard class from the gui subfolder
from gui.dashboard import SecurityDashboard

def main():
    app = QApplication(sys.argv)
    
    # Optional: Set a dark theme/stylesheet here for a "hacker" look
    app.setStyle("Fusion") 
    
    window = SecurityDashboard()
    window.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
