"""
Standalone Alert Engine Demo

Shows how to use the AlertEngine module independently,
processing pre-existing inspection data (e.g., from file or API).
Demonstrates modular independence and composability.
"""

import json
import logging
from security_toolkit.modules.alert_engine import AlertEngine, get_default_rules

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def get_sample_inspection_data():
    """Get sample inspection data for demo."""
    return {
        "timestamp": "2026-03-30T10:30:00",
        "duration": 60,
        "sessions": [
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "8.8.8.8",
                "src_port": 54321,
                "dst_port": 443,
                "protocol": "TCP",
                "timestamp": "2026-03-30T10:30:00",
                "metadata": {"ttl": 64, "packet_size": 1500},
            },
            {
                "src_ip": "192.168.1.100",
                "dst_ip": "10.0.0.5",
                "src_port": 54322,
                "dst_port": 80,
                "protocol": "HTTP",
                "timestamp": "2026-03-30T10:30:01",
                "metadata": {"ttl": 64, "packet_size": 512},
            },
        ],
        "summary": {
            "total_sessions": 2,
            "total_flags": 1,
            "protocols_seen": ["TCP", "HTTP"],
            "unique_ips": 3,
        },
        "flags": [
            {
                "type": "insecure_protocol",
                "detail": "HTTP detected on 192.168.1.100:54322 -> 10.0.0.5:80",
                "severity_hint": "medium",
            },
        ],
    }


def main():
    """Run standalone alert engine."""
    print("=" * 70)
    print("SECURITY TOOLKIT - STANDALONE ALERT ENGINE")
    print("=" * 70)
    print()
    
    # Get sample inspection data
    inspection_data = get_sample_inspection_data()
    
    # Create alert engine
    alert_engine = AlertEngine(rule_engine=get_default_rules())
    
    print("Processing inspection data with alert engine...")
    print("-" * 70)
    
    # Process inspection
    result = alert_engine.process(inspection_data)
    
    print()
    print("ALERT GENERATION COMPLETE")
    print("-" * 70)
    print()
    
    print(f"Timestamp: {result['timestamp']}")
    print()
    
    print("SUMMARY:")
    print(f"  Total Alerts: {result['summary']['total_alerts']}")
    print(f"  By Severity: {result['summary']['by_severity']}")
    print(f"  Alert Types: {result['summary']['alert_types']}")
    print()
    
    print("ALERTS:")
    if result['alerts']:
        for alert in result['alerts']:
            print(f"  [{alert['severity']}] {alert['id']}")
            print(f"    Type: {alert['type']}")
            print(f"    Description: {alert['description']}")
            print(f"    Evidence: {alert['evidence']}")
            print()
    else:
        print("  No alerts generated")
    
    print("=" * 70)
    print("Raw output (JSON):")
    print("=" * 70)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
