"""
Standalone Network Inspector Demo

Shows how to use the NetworkInspector module independently,
without the alert engine. Demonstrates modular independence.
"""

import json
import logging
from security_toolkit.modules.network_inspector import NetworkInspector

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)


def main():
    """Run standalone network inspection."""
    print("=" * 70)
    print("SECURITY TOOLKIT - STANDALONE NETWORK INSPECTOR")
    print("=" * 70)
    print()
    
    # Create inspector (uses mock mode by default on non-root systems)
    inspector = NetworkInspector(use_mock=False)
    
    print("Starting network inspection...")
    print("-" * 70)
    
    # Run inspection
    result = inspector.run(duration=5)
    
    print()
    print("INSPECTION COMPLETE")
    print("-" * 70)
    print()
    
    # Display results
    print(f"Timestamp: {result['timestamp']}")
    print(f"Duration: {result['duration']} seconds")
    print()
    
    print("SUMMARY:")
    print(f"  Total Sessions: {result['summary']['total_sessions']}")
    print(f"  Total Flags: {result['summary']['total_flags']}")
    print(f"  Protocols Seen: {', '.join(result['summary']['protocols_seen'])}")
    print(f"  Unique IPs: {result['summary']['unique_ips']}")
    print()
    
    print("SESSIONS CAPTURED:")
    for session in result['sessions'][:5]:  # Show first 5
        print(f"  {session['src_ip']}:{session['src_port']} -> "
              f"{session['dst_ip']}:{session['dst_port']} ({session['protocol']})")
    
    if len(result['sessions']) > 5:
        print(f"  ... and {len(result['sessions']) - 5} more")
    
    print()
    print("SECURITY FLAGS:")
    for flag in result['flags']:
        print(f"  [{flag['severity_hint'].upper()}] {flag['type']}")
        print(f"    {flag['detail']}")
    
    print()
    print("=" * 70)
    print("Raw output (JSON):")
    print("=" * 70)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
