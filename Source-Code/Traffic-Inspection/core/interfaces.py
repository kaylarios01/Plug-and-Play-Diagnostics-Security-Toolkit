"""
Core interfaces for security toolkit modules.

Defines abstract base classes that establish contracts for all toolkit components.
Modules implement these interfaces but do not directly import from each other,
maintaining loose coupling and enabling independent operation.
"""

from abc import ABC, abstractmethod
from typing import Any, Dict
import logging

logger = logging.getLogger(__name__)


class Inspector(ABC):
    """
    Abstract base class for security inspection modules.
    
    Defines the contract that all inspection implementations must follow.
    Inspectors passively observe and analyze system components without
    modifying state or actively probing.
    """

    @abstractmethod
    def run(self, duration: int = 60) -> Dict[str, Any]:
        """
        Execute inspection and return findings.
        
        Args:
            duration: Inspection duration in seconds (default: 60).
            
        Returns:
            Dict conforming to the shared inspection schema (see schemas.py).
            Must contain: timestamp, duration, sessions, summary, flags.
            
        Raises:
            RuntimeError: If inspection fails or cannot be performed.
            ValueError: If parameters are invalid.
        """
        pass


class AlertProcessor(ABC):
    """
    Abstract base class for alert processing engines.
    
    Defines the contract that all alert processors must implement.
    Processors accept structured inspection data and apply rule-based
    logic to generate actionable alerts.
    """

    @abstractmethod
    def process(self, inspection_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process inspection data and generate alerts.
        
        Args:
            inspection_data: Dict conforming to the inspection schema.
            
        Returns:
            Dict conforming to the alert schema (see schemas.py).
            Must contain: alerts, summary.
            
        Raises:
            ValueError: If input data does not conform to schema.
            RuntimeError: If processing fails.
        """
        pass

    @abstractmethod
    def add_rule(self, rule: Dict[str, Any]) -> None:
        """
        Add or update an alert rule.
        
        Args:
            rule: Rule configuration dict with required keys: name, condition, severity.
        """
        pass


class Deduplicator(ABC):
    """
    Abstract base class for deduplication strategies.
    
    Ensures alerts/findings are not duplicated in output.
    """

    @abstractmethod
    def is_duplicate(self, item: Dict[str, Any]) -> bool:
        """
        Check if item is a duplicate of previously seen items.
        
        Args:
            item: The item to check (alert, finding, etc.).
            
        Returns:
            True if duplicate, False otherwise.
        """
        pass

    @abstractmethod
    def reset(self) -> None:
        """Clear deduplication state."""
        pass
