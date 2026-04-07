# Traffic Inspection

## Overview
This module handles network traffic inspection for the capstone project. It looks at network activity and flags anything that might be insecure or unusual.

## What it does
- Checks network sessions
- Detects insecure protocols (HTTP, FTP, TELNET, etc.)
- Flags unusual ports or behavior

## How to run
From this folder:
python examples/run_inspector.py

## Notes
- Uses shared code from the `core/` folder
- Output from this module is used by the Alerts System
