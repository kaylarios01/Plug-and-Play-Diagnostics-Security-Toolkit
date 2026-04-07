"""Alert Engine module - rule-based alert generation."""

from .engine import (
    AlertEngine,
    HashBasedDeduplicator,
    SignatureBasedDeduplicator,
)
from .rules import RuleEngine, Rule, get_default_rules

__all__ = [
    "AlertEngine",
    "HashBasedDeduplicator",
    "SignatureBasedDeduplicator",
    "RuleEngine",
    "Rule",
    "get_default_rules",
]
