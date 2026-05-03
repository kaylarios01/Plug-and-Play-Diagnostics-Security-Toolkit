import sys
from PyQt6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QCheckBox, 
                             QLabel, QProgressBar, QPushButton, QFrame)
from PyQt6.QtCore import Qt, QTimer

class Dashboard(QWidget):
    def __init__(self):
        super().__init__()
        self.init_ui()

    def init_ui(self):
        self.setWindowTitle("Security Diagnostics Toolkit - Dashboard")
        self.setFixedSize(600, 500)
        self.setStyleSheet("background-color: #2b2b2b; color: #ffffff;")
        
        main_layout = QVBoxLayout()

        header_layout = QHBoxLayout()
        title = QLabel("System Control Center")
        title.setStyleSheet("font-size: 20px; font-weight: bold; color: #50fa7b;")
        
        self.blinker = QFrame()
        self.blinker.setFixedSize(12, 12)
        self.blinker.setStyleSheet("background-color: #50fa7b; border-radius: 6px;")
        
        self.blink_timer = QTimer()
        self.blink_timer.timeout.connect(self.toggle_blinker)
        self.blink_timer.start(500)

        header_layout.addWidget(title)
        header_layout.addStretch()
        header_layout.addWidget(QLabel("Live Traffic:"))
        header_layout.addWidget(self.blinker)
        main_layout.addLayout(header_layout)

        main_layout.addWidget(QLabel("Select our safety checks:"))
        
        self.check_net = QCheckBox("Check for 'unlocked doors' (Ports)")
        self.check_audit = QCheckBox("Review our computer's safety settings (Registry)")
        self.check_proc = QCheckBox("Search for hidden programs (Processes)")
        self.check_pass = QCheckBox("Test if our passwords are easy to guess (RockYou)")
        
        for check in [self.check_net, self.check_audit, self.check_proc, self.check_pass]:
            check.setStyleSheet("font-size: 14px; margin: 5px;")
            main_layout.addWidget(check)

        main_layout.addStretch()

        self.status_label = QLabel("Ready to begin.")
        main_layout.addWidget(self.status_label)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar { border: 2px solid #44475a; border-radius: 5px; text-align: center; }
            QProgressBar::chunk { background-color: #50fa7b; }
        """)
        main_layout.addWidget(self.progress_bar)

        self.start_btn = QPushButton("Start Our Security Review")
        self.start_btn.setStyleSheet("""
            QPushButton { background-color: #6272a4; color: white; padding: 15px; font-size: 16px; border-radius: 8px; }
            QPushButton:hover { background-color: #44475a; }
        """)
        main_layout.addWidget(self.start_btn)

        self.setLayout(main_layout)

    def toggle_blinker(self):
        if self.blinker.isVisible():
            self.blinker.hide()
        else:
            self.blinker.show()
