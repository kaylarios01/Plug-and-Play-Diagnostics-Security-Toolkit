#!/bin/bash
echo "Installing dependencies for Security Diagnostics Toolkit..."
sudo apt update
sudo apt install -y nmap lynis hydra python3-pip
pip3 install PyQt6 python-nmap scapy reportlab psutil
echo "Setup complete. Run with: sudo python3 main.py"
