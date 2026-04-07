"""
Utility functions for network inspection.

Provides helper functions for packet capture, IP validation, protocol detection,
and session aggregation.
"""

import logging
import socket
from typing import Dict, List, Tuple, Optional
from datetime import datetime

logger = logging.getLogger(__name__)


def is_valid_ip(ip: str) -> bool:
    """Validate IPv4 address format."""
    try:
        socket.inet_aton(ip)
        return True
    except (socket.error, TypeError):
        return False


def is_insecure_protocol(protocol: str) -> bool:
    """
    Check if protocol is considered insecure.
    
    Insecure protocols: HTTP, FTP, Telnet, clear-text IMAP/POP3, SNMP.
    """
    insecure = {"HTTP", "FTP", "TELNET", "IMAP", "POP3", "SNMP"}
    return protocol.upper() in insecure


def is_unusual_port(port: int) -> bool:
    """
    Check if port is unusual or suspicious.
    
    Criteria:
    - Ports below 1024 are reserved (often suspicious if used by user processes)
    - Certain ranges associated with trojans/malware
    """
    # Reserved but less common ports that might warrant attention
    unusual_ports = {
        23,      # Telnet
        69,      # TFTP
        513,     # Rlogin
        514,     # Syslog
        2049,    # NFS
        3389,    # RDP (if seen on unexpected hosts)
        5900,    # VNC
        8080,    # Alternative HTTP
        8888,    # Alternative HTTP
    }
    return port in unusual_ports


def detect_repeated_attempts(
    sessions: List[Dict],
    threshold: int = 3,
    time_window_seconds: int = 60,
) -> List[Tuple[str, str, int]]:
    """
    Detect repeated connection attempts (basic anomaly detection).
    
    Returns list of (source_ip, dest_ip, attempt_count) tuples
    where attempt_count exceeds threshold.
    
    Args:
        sessions: List of session dictionaries.
        threshold: Minimum attempts to consider anomalous.
        time_window_seconds: Time window for aggregation.
        
    Returns:
        List of (src_ip, dst_ip, count) for suspicious patterns.
    """
    attempt_map: Dict[Tuple[str, str], int] = {}
    
    for session in sessions:
        key = (session["src_ip"], session["dst_ip"])
        attempt_map[key] = attempt_map.get(key, 0) + 1
    
    suspicious = [
        (src, dst, count)
        for (src, dst), count in attempt_map.items()
        if count >= threshold
    ]
    
    return suspicious


def aggregate_sessions(sessions: List[Dict]) -> Dict:
    """
    Generate summary statistics from sessions.
    
    Args:
        sessions: List of session dictionaries.
        
    Returns:
        Dict with statistics.
    """
    protocols = set()
    ips = set()
    flags = []
    
    for session in sessions:
        protocols.add(session.get("protocol", "UNKNOWN"))
        ips.add(session.get("src_ip"))
        ips.add(session.get("dst_ip"))
    
    return {
        "total_sessions": len(sessions),
        "protocols_seen": sorted(list(protocols)),
        "unique_ips": len(ips),
    }


def get_current_timestamp() -> str:
    """Get current UTC timestamp in ISO 8601 format."""
    return datetime.utcnow().isoformat()


def generate_flag_id(flag_type: str, detail: str) -> str:
    """Generate a deterministic ID for a flag."""
    import hashlib
    data = f"{flag_type}:{detail}".encode()
    return hashlib.md5(data).hexdigest()[:12]
