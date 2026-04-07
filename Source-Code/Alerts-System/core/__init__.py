"""Core module - interfaces and schemas for security toolkit."""

from .interfaces import Inspector, AlertProcessor, Deduplicator
from .schemas import (
    Flag,
    Session,
    InspectionSummary,
    InspectionResult,
    Alert,
    AlertSummary,
    AlertEngineResult,
)

__all__ = [
    "Inspector",
    "AlertProcessor",
    "Deduplicator",
    "Flag",
    "Session",
    "InspectionSummary",
    "InspectionResult",
    "Alert",
    "AlertSummary",
    "AlertEngineResult",
]
