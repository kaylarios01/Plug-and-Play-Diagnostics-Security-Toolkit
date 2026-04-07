"""
Shared data schemas for security toolkit modules.

Defines Pydantic models that serve as contracts for data exchanged
between modules. All modules must conform strictly to these schemas.
This ensures loose coupling and interoperability.
"""

from typing import List, Dict, Any, Optional, Literal
from dataclasses import dataclass, asdict
from datetime import datetime
import json


@dataclass
class Flag:
    """
    A security flag or finding from inspection.
    
    Attributes:
        type: Category of flag (e.g., "insecure_protocol", "unusual_port").
        detail: Human-readable description.
        severity_hint: Suggested severity ("low", "medium", "high", "critical").
    """
    type: str
    detail: str
    severity_hint: Literal["low", "medium", "high", "critical"]


@dataclass
class Session:
    """
    Network session or interaction captured during inspection.
    
    Attributes:
        src_ip: Source IP address.
        dst_ip: Destination IP address.
        src_port: Source port number.
        dst_port: Destination port number.
        protocol: Protocol name (TCP, UDP, HTTP, FTP, DNS, etc.).
        timestamp: When session was observed (ISO 8601).
        metadata: Additional context (packet count, bytes, etc.).
    """
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    timestamp: str
    metadata: Dict[str, Any]


@dataclass
class InspectionSummary:
    """
    Summary statistics from inspection.
    
    Attributes:
        total_sessions: Number of sessions captured.
        total_flags: Number of flags raised.
        protocols_seen: List of unique protocols.
        unique_ips: Number of unique IP addresses.
    """
    total_sessions: int
    total_flags: int
    protocols_seen: List[str]
    unique_ips: int


@dataclass
class InspectionResult:
    """
    Complete inspection result - strict output contract for inspectors.
    
    ALL inspectors must return data conforming to this schema.
    
    Attributes:
        timestamp: When inspection completed (ISO 8601).
        duration: Inspection duration in seconds.
        sessions: List of captured sessions.
        summary: Aggregated statistics.
        flags: List of security flags discovered.
    """
    timestamp: str
    duration: int
    sessions: List[Session]
    summary: InspectionSummary
    flags: List[Flag]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, recursively handling nested dataclasses."""
        return {
            "timestamp": self.timestamp,
            "duration": self.duration,
            "sessions": [asdict(s) for s in self.sessions],
            "summary": asdict(self.summary),
            "flags": [asdict(f) for f in self.flags],
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "InspectionResult":
        """Construct from dictionary with validation."""
        if not isinstance(data, dict):
            raise ValueError("InspectionResult data must be a dictionary")
        
        required_keys = {"timestamp", "duration", "sessions", "summary", "flags"}
        if not required_keys.issubset(data.keys()):
            raise ValueError(f"Missing required keys: {required_keys - set(data.keys())}")
        
        sessions = [
            Session(
                src_ip=s["src_ip"],
                dst_ip=s["dst_ip"],
                src_port=s["src_port"],
                dst_port=s["dst_port"],
                protocol=s["protocol"],
                timestamp=s["timestamp"],
                metadata=s.get("metadata", {}),
            )
            for s in data["sessions"]
        ]
        
        summary_data = data["summary"]
        summary = InspectionSummary(
            total_sessions=summary_data["total_sessions"],
            total_flags=summary_data["total_flags"],
            protocols_seen=summary_data["protocols_seen"],
            unique_ips=summary_data["unique_ips"],
        )
        
        flags = [
            Flag(
                type=f["type"],
                detail=f["detail"],
                severity_hint=f["severity_hint"],
            )
            for f in data["flags"]
        ]
        
        return cls(
            timestamp=data["timestamp"],
            duration=data["duration"],
            sessions=sessions,
            summary=summary,
            flags=flags,
        )


@dataclass
class Alert:
    """
    A generated security alert.
    
    Attributes:
        id: Unique alert identifier.
        type: Alert category (e.g., "insecure_protocol_detected").
        severity: Alert severity level.
        description: Human-readable alert description.
        evidence: Supporting data/context.
        timestamp: When alert was generated (ISO 8601).
    """
    id: str
    type: str
    severity: Literal["Low", "Medium", "High", "Critical"]
    description: str
    evidence: Dict[str, Any]
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class AlertSummary:
    """
    Summary of generated alerts.
    
    Attributes:
        total_alerts: Total number of alerts generated.
        by_severity: Count of alerts by severity level.
        alert_types: Count of alerts by type.
    """
    total_alerts: int
    by_severity: Dict[str, int]
    alert_types: Dict[str, int]


@dataclass
class AlertEngineResult:
    """
    Complete alert engine output - strict output contract for alert processors.
    
    ALL alert processors must return data conforming to this schema.
    
    Attributes:
        alerts: List of generated alerts.
        summary: Aggregated alert statistics.
        timestamp: When processing completed (ISO 8601).
    """
    alerts: List[Alert]
    summary: AlertSummary
    timestamp: str = None

    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alerts": [asdict(a) for a in self.alerts],
            "summary": asdict(self.summary),
            "timestamp": self.timestamp,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "AlertEngineResult":
        """Construct from dictionary with validation."""
        if not isinstance(data, dict):
            raise ValueError("AlertEngineResult data must be a dictionary")
        
        required_keys = {"alerts", "summary"}
        if not required_keys.issubset(data.keys()):
            raise ValueError(f"Missing required keys: {required_keys - set(data.keys())}")
        
        alerts = [
            Alert(
                id=a["id"],
                type=a["type"],
                severity=a["severity"],
                description=a["description"],
                evidence=a["evidence"],
                timestamp=a.get("timestamp"),
            )
            for a in data["alerts"]
        ]
        
        summary_data = data["summary"]
        summary = AlertSummary(
            total_alerts=summary_data["total_alerts"],
            by_severity=summary_data["by_severity"],
            alert_types=summary_data["alert_types"],
        )
        
        return cls(
            alerts=alerts,
            summary=summary,
            timestamp=data.get("timestamp"),
        )
