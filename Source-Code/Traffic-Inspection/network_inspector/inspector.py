"""
Network Traffic Inspector module.

Passively inspects network traffic to detect security issues including:
- Insecure protocol usage
- Unusual port activity
- Repeated connection attempts
- Session metadata anomalies

No packet injection or active probing is performed.
"""

import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

from security_toolkit.core.interfaces import Inspector
from security_toolkit.core.schemas import (
    InspectionResult,
    InspectionSummary,
    Session,
    Flag,
)
from .utils import (
    is_insecure_protocol,
    is_unusual_port,
    detect_repeated_attempts,
    aggregate_sessions,
    get_current_timestamp,
    generate_flag_id,
)

logger = logging.getLogger(__name__)


class NetworkInspector(Inspector):
    """
    Passive network traffic inspector.
    
    Captures and analyzes network sessions to identify security issues
    like insecure protocols, unusual ports, and suspicious patterns.
    
    Can operate in real mode (requires scapy) or mock mode (for testing).
    """

    def __init__(self, use_mock: bool = False):
        """
        Initialize inspector.
        
        Args:
            use_mock: If True, use mock data instead of real packet capture.
                     Useful for testing and non-root environments.
        """
        self.use_mock = use_mock
        self.scapy_available = False
        
        if not use_mock:
            try:
                from scapy.all import sniff, IP, TCP, UDP
                self.sniff = sniff
                self.IP = IP
                self.TCP = TCP
                self.UDP = UDP
                self.scapy_available = True
                logger.debug("Scapy loaded - real packet capture available")
            except ImportError:
                logger.warning(
                    "Scapy not available. Falling back to mock mode. "
                    "Install scapy for real packet capture: pip install scapy"
                )
                self.use_mock = True

    def run(self, duration: int = 60) -> Dict[str, Any]:
        """
        Execute network inspection for specified duration.
        
        Args:
            duration: Inspection duration in seconds (default: 60).
            
        Returns:
            Dict conforming to InspectionResult schema.
            
        Raises:
            ValueError: If duration is invalid.
            RuntimeError: If capture fails.
        """
        if duration <= 0:
            raise ValueError("Duration must be positive")
        
        logger.info(f"Starting network inspection for {duration} seconds")
        
        if self.use_mock:
            logger.debug("Using mock mode - no real packets captured")
            sessions = self._get_mock_sessions()
        else:
            try:
                sessions = self._capture_real_packets(duration)
            except Exception as e:
                logger.error(f"Real packet capture failed: {e}")
                raise RuntimeError(f"Failed to capture packets: {e}")
        
        # Convert sessions to dicts for analysis
        sessions_dicts = [
            {
                "src_ip": s.src_ip,
                "dst_ip": s.dst_ip,
                "src_port": s.src_port,
                "dst_port": s.dst_port,
                "protocol": s.protocol,
                "timestamp": s.timestamp,
                "metadata": s.metadata,
            }
            for s in sessions
        ]
        
        # Analyze sessions and generate flags
        flags = self._analyze_sessions(sessions)
        
        # Generate summary
        summary_data = aggregate_sessions(sessions_dicts)
        summary_data["total_flags"] = len(flags)
        summary = InspectionSummary(
            total_sessions=summary_data["total_sessions"],
            total_flags=summary_data["total_flags"],
            protocols_seen=summary_data["protocols_seen"],
            unique_ips=summary_data["unique_ips"],
        )
        
        # Create result
        result = InspectionResult(
            timestamp=get_current_timestamp(),
            duration=duration,
            sessions=sessions,
            summary=summary,
            flags=flags,
        )
        
        logger.info(
            f"Inspection complete: {summary.total_sessions} sessions, "
            f"{summary.total_flags} flags"
        )
        
        return result.to_dict()

    def _capture_real_packets(self, duration: int) -> List[Session]:
        """
        Capture real network packets using scapy.
        
        Args:
            duration: Capture duration in seconds.
            
        Returns:
            List of Session objects.
        """
        if not self.scapy_available:
            raise RuntimeError("Scapy not available for real packet capture")
        
        logger.info(f"Capturing packets for {duration} seconds...")
        sessions_captured = []
        packet_count = [0]
        
        def packet_callback(packet):
            """Process each captured packet."""
            packet_count[0] += 1
            
            try:
                # Only process IP packets
                if not self.IP in packet:
                    return
                
                ip_layer = packet[self.IP]
                src_ip = ip_layer.src
                dst_ip = ip_layer.dst
                protocol = ip_layer.proto
                
                # Extract port information if available
                src_port = None
                dst_port = None
                protocol_name = self._get_protocol_name(protocol)
                
                if self.TCP in packet:
                    tcp_layer = packet[self.TCP]
                    src_port = tcp_layer.sport
                    dst_port = tcp_layer.dport
                    protocol_name = "TCP"
                elif self.UDP in packet:
                    udp_layer = packet[self.UDP]
                    src_port = udp_layer.sport
                    dst_port = udp_layer.dport
                    protocol_name = "UDP"
                
                # Create session record
                session = Session(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port or 0,
                    dst_port=dst_port or 0,
                    protocol=protocol_name,
                    timestamp=get_current_timestamp(),
                    metadata={"ttl": ip_layer.ttl, "packet_size": len(packet)},
                )
                sessions_captured.append(session)
                
            except Exception as e:
                logger.debug(f"Error processing packet: {e}")
        
        try:
            self.sniff(prn=packet_callback, timeout=duration, store=False)
        except PermissionError:
            logger.error("Packet capture requires elevated privileges")
            raise RuntimeError("Packet capture requires root/administrator access")
        
        logger.info(f"Captured {packet_count[0]} packets")
        return sessions_captured

    def _get_mock_sessions(self) -> List[Session]:
        """
        Generate mock session data for testing/demo purposes.
        
        Returns:
            List of Session objects with variety of protocols and patterns.
        """
        current_time = get_current_timestamp()
        
        sessions = [
            # Normal HTTPS traffic
            Session(
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=54321,
                dst_port=443,
                protocol="TCP",
                timestamp=current_time,
                metadata={"ttl": 64, "packet_size": 1500},
            ),
            # Insecure HTTP traffic (flagged)
            Session(
                src_ip="192.168.1.100",
                dst_ip="10.0.0.5",
                src_port=54322,
                dst_port=80,
                protocol="HTTP",
                timestamp=current_time,
                metadata={"ttl": 64, "packet_size": 512},
            ),
            # FTP traffic (insecure, flagged)
            Session(
                src_ip="192.168.1.100",
                dst_ip="172.16.0.10",
                src_port=54323,
                dst_port=21,
                protocol="FTP",
                timestamp=current_time,
                metadata={"ttl": 64, "packet_size": 256},
            ),
            # DNS query
            Session(
                src_ip="192.168.1.100",
                dst_ip="8.8.8.8",
                src_port=53451,
                dst_port=53,
                protocol="DNS",
                timestamp=current_time,
                metadata={"ttl": 64, "packet_size": 65},
            ),
            # Unusual port traffic (VNC)
            Session(
                src_ip="192.168.1.100",
                dst_ip="192.168.1.50",
                src_port=54324,
                dst_port=5900,
                protocol="TCP",
                timestamp=current_time,
                metadata={"ttl": 64, "packet_size": 256},
            ),
            # Telnet (insecure, flagged)
            Session(
                src_ip="192.168.1.101",
                dst_ip="192.168.1.200",
                src_port=54325,
                dst_port=23,
                protocol="TELNET",
                timestamp=current_time,
                metadata={"ttl": 64, "packet_size": 128},
            ),
        ]
        
        return sessions

    def _analyze_sessions(self, sessions: List[Session]) -> List[Flag]:
        """
        Analyze sessions for security issues.
        
        Args:
            sessions: List of captured sessions.
            
        Returns:
            List of Flag objects representing discovered issues.
        """
        flags = []
        flagged_sessions = set()
        
        for session in sessions:
            session_key = (session.src_ip, session.dst_ip, session.protocol)
            
            # Check for insecure protocols
            if is_insecure_protocol(session.protocol):
                if session_key not in flagged_sessions:
                    flags.append(Flag(
                        type="insecure_protocol",
                        detail=f"{session.protocol} detected on "
                               f"{session.src_ip}:{session.src_port} -> "
                               f"{session.dst_ip}:{session.dst_port}",
                        severity_hint="medium",
                    ))
                    flagged_sessions.add(session_key)
            
            # Check for unusual ports
            if is_unusual_port(session.dst_port):
                port_key = (session.src_ip, session.dst_ip, session.dst_port)
                if port_key not in flagged_sessions:
                    flags.append(Flag(
                        type="unusual_port",
                        detail=f"Unusual port {session.dst_port} accessed by "
                               f"{session.src_ip} to {session.dst_ip}",
                        severity_hint="low",
                    ))
                    flagged_sessions.add(port_key)
        
        # Check for repeated connection attempts
        session_dicts = [
            {
                "src_ip": s.src_ip,
                "dst_ip": s.dst_ip,
                "protocol": s.protocol,
            }
            for s in sessions
        ]
        
        repeated = detect_repeated_attempts(session_dicts, threshold=3)
        for src_ip, dst_ip, count in repeated:
            flags.append(Flag(
                type="repeated_attempts",
                detail=f"{count} connection attempts from {src_ip} to {dst_ip}",
                severity_hint="medium",
            ))
        
        logger.debug(f"Analysis complete: {len(flags)} flags identified")
        return flags

    @staticmethod
    def _get_protocol_name(protocol_num: int) -> str:
        """Map protocol number to name."""
        protocol_map = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
        }
        return protocol_map.get(protocol_num, f"PROTO_{protocol_num}")
