import sys
import os
from PyQt6.QtWidgets import QApplication
from gui.disclaimer import DisclaimerWindow
from gui.dashboard import Dashboard

class SentinelController:
    def __init__(self):
        # 1. Create the application instance
        self.app = QApplication(sys.argv)
        
        # Use 'Fusion' style for a consistent look across different Windows versions
        self.app.setStyle("Fusion")
        
        # 2. Ensure the system path includes the current directory for USB portability
        current_dir = os.path.dirname(os.path.abspath(__file__))
        sys.path.append(current_dir)

        # 3. Initialize the Disclaimer (The Gatekeeper)
        # We pass self.show_dashboard as the callback function
        self.disclaimer = DisclaimerWindow(on_accept_callback=self.show_dashboard)
        self.disclaimer.show()
        
        # 4. Keep the app running
        sys.exit(self.app.exec())

    def show_dashboard(self):
        """
        This method is triggered only when the user clicks 'I Agree' 
        in the Disclaimer window.
        """
        # Initialize and show the main toolkit
        self.main_toolkit = Dashboard()
        self.main_toolkit.show()

if __name__ == "__main__":
    # Start the controller
    SentinelController()
