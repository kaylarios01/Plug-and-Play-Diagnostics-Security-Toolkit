# Alerts System

## Overview
This module takes the results from traffic inspection and turns them into alerts.

## What it does
- Processes flags from the Traffic Inspection module
- Assigns severity levels (Low, High, Critical, etc.)
- Generates alerts with descriptions

## How to run
From this folder:
python examples/run_alerts.py

## Notes
- Uses shared schemas from the `core/` folder
- Rules are defined in rules.json / rules.yaml
