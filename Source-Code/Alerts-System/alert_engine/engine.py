"""
Alert Engine module.

Processes inspection results and generates security alerts using
configurable rules. Handles deduplication and aggregation.
"""

import logging
import hashlib
from typing import Dict, Any, List, Set
from datetime import datetime

from security_toolkit.core.interfaces import AlertProcessor, Deduplicator
from security_toolkit.core.schemas import (
    AlertEngineResult,
    Alert,
    AlertSummary,
)
from .rules import RuleEngine, get_default_rules

logger = logging.getLogger(__name__)


class HashBasedDeduplicator(Deduplicator):
    """
    Deduplication strategy using content hashing.
    
    Treats items as duplicates if they hash to the same value.
    """

    def __init__(self):
        """Initialize deduplicator."""
        self.seen_hashes: Set[str] = set()

    def is_duplicate(self, item: Dict[str, Any]) -> bool:
        """
        Check if item is a duplicate.
        
        Args:
            item: Item to check.
            
        Returns:
            True if duplicate, False otherwise.
        """
        # Create hash from item content
        item_str = str(sorted(item.items()))
        item_hash = hashlib.sha256(item_str.encode()).hexdigest()
        
        if item_hash in self.seen_hashes:
            return True
        
        self.seen_hashes.add(item_hash)
        return False

    def reset(self) -> None:
        """Clear deduplication state."""
        self.seen_hashes.clear()


class SignatureBasedDeduplicator(Deduplicator):
    """
    Deduplication strategy using item signatures.
    
    Signatures are created from key fields (alert type, severity, description).
    Items with identical signatures are considered duplicates.
    """

    def __init__(self):
        """Initialize deduplicator."""
        self.seen_signatures: Set[str] = set()

    def is_duplicate(self, item: Dict[str, Any]) -> bool:
        """
        Check if item is a duplicate based on signature.
        
        Args:
            item: Item to check.
            
        Returns:
            True if duplicate, False otherwise.
        """
        # Create signature from key fields
        signature = f"{item.get('type')}:{item.get('severity')}:{item.get('description')}"
        
        if signature in self.seen_signatures:
            return True
        
        self.seen_signatures.add(signature)
        return False

    def reset(self) -> None:
        """Clear deduplication state."""
        self.seen_signatures.clear()


class AlertEngine(AlertProcessor):
    """
    Rule-based alert generation engine.
    
    Processes inspection results and applies configurable rules to generate
    security alerts. Handles deduplication and aggregation.
    
    Can be used standalone or composed in a pipeline with other modules.
    """

    def __init__(
        self,
        rule_engine: RuleEngine = None,
        deduplicator: Deduplicator = None,
    ):
        """
        Initialize alert engine.
        
        Args:
            rule_engine: RuleEngine instance (default: new engine with default rules).
            deduplicator: Deduplicator instance (default: SignatureBasedDeduplicator).
        """
        self.rule_engine = rule_engine or get_default_rules()
        self.deduplicator = deduplicator or SignatureBasedDeduplicator()
        logger.debug(
            f"AlertEngine initialized with {len(self.rule_engine.rules)} rules"
        )

    def add_rule(self, rule_dict: Dict[str, Any]) -> None:
        """
        Add or update an alert rule.
        
        Args:
            rule_dict: Rule configuration (must contain 'name' field).
        """
        from .rules import Rule
        
        name = rule_dict.get("name")
        if not name:
            raise ValueError("Rule dict must contain 'name' field")
        
        severity = rule_dict.get("severity", "Medium")
        if severity not in ("Low", "Medium", "High", "Critical"):
            raise ValueError(f"Invalid severity: {severity}")
        
        description_template = rule_dict.get("description_template", "Alert")
        condition_func = rule_dict.get("condition")
        
        if not callable(condition_func):
            raise ValueError("Rule dict must contain 'condition' callable")
        
        rule = Rule(name, condition_func, severity, description_template)
        self.rule_engine.update_rule(rule)

    def process(self, inspection_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process inspection data and generate alerts.
        
        Applies all rules to inspection findings, deduplicates results,
        and generates a structured alert output.
        
        Args:
            inspection_data: Dict conforming to InspectionResult schema.
            
        Returns:
            Dict conforming to AlertEngineResult schema.
            
        Raises:
            ValueError: If input data doesn't conform to schema.
        """
        logger.info("Starting alert processing")
        
        # Validate input schema
        self._validate_inspection_data(inspection_data)
        
        # Reset deduplicator for this run
        self.deduplicator.reset()
        
        # Extract flags from inspection data
        flags = inspection_data.get("flags", [])
        logger.debug(f"Processing {len(flags)} flags")
        
        alerts: List[Alert] = []
        alert_counter = 0
        
        # Apply rules to each flag
        for flag in flags:
            # Convert flag to dict if needed
            if hasattr(flag, '__dict__'):
                flag_dict = flag.__dict__
            else:
                flag_dict = flag
            
            # Evaluate rules
            rule_matches = self.rule_engine.evaluate(flag_dict)
            
            for rule_name, severity, description in rule_matches:
                # Create alert
                alert_dict = {
                    "type": flag_dict.get("type"),
                    "severity": severity,
                    "description": description,
                    "rule_matched": rule_name,
                }
                
                # Check for duplicates
                if self.deduplicator.is_duplicate(alert_dict):
                    logger.debug(f"Duplicate alert skipped: {rule_name}")
                    continue
                
                # Generate alert ID
                alert_id = self._generate_alert_id(alert_counter)
                alert_counter += 1
                
                alert = Alert(
                    id=alert_id,
                    type=alert_dict["type"],
                    severity=severity,
                    description=description,
                    evidence={
                        "flag_detail": flag_dict.get("detail"),
                        "rule_matched": rule_name,
                        "severity_hint": flag_dict.get("severity_hint"),
                    },
                )
                
                alerts.append(alert)
                logger.debug(
                    f"Generated alert: {alert_id} ({severity}) - {description}"
                )
        
        # Generate summary
        summary = self._generate_summary(alerts)
        
        # Create result
        result = AlertEngineResult(
            alerts=alerts,
            summary=summary,
        )
        
        logger.info(
            f"Alert processing complete: {len(alerts)} alerts generated "
            f"({summary.by_severity})"
        )
        
        return result.to_dict()

    def _validate_inspection_data(self, data: Dict[str, Any]) -> None:
        """
        Validate that data conforms to InspectionResult schema.
        
        Args:
            data: Data to validate.
            
        Raises:
            ValueError: If validation fails.
        """
        required_keys = {"timestamp", "duration", "sessions", "summary", "flags"}
        
        if not isinstance(data, dict):
            raise ValueError("Inspection data must be a dictionary")
        
        missing_keys = required_keys - set(data.keys())
        if missing_keys:
            raise ValueError(
                f"Inspection data missing required keys: {missing_keys}"
            )
        
        if not isinstance(data.get("flags"), list):
            raise ValueError("'flags' must be a list")
        
        logger.debug("Inspection data validation passed")

    @staticmethod
    def _generate_alert_id(counter: int) -> str:
        """Generate unique alert ID."""
        timestamp = datetime.utcnow().isoformat()[:19].replace(":", "").replace("-", "")
        return f"ALERT-{timestamp}-{counter:04d}"

    @staticmethod
    def _generate_summary(alerts: List[Alert]) -> AlertSummary:
        """
        Generate summary statistics from alerts.
        
        Args:
            alerts: List of alerts.
            
        Returns:
            AlertSummary object.
        """
        by_severity = {
            "Low": 0,
            "Medium": 0,
            "High": 0,
            "Critical": 0,
        }
        
        alert_types = {}
        
        for alert in alerts:
            by_severity[alert.severity] = by_severity.get(alert.severity, 0) + 1
            alert_types[alert.type] = alert_types.get(alert.type, 0) + 1
        
        return AlertSummary(
            total_alerts=len(alerts),
            by_severity=by_severity,
            alert_types=alert_types,
        )

    def set_deduplicator(self, deduplicator: Deduplicator) -> None:
        """
        Set deduplication strategy.
        
        Args:
            deduplicator: Deduplicator instance.
        """
        self.deduplicator = deduplicator
        logger.debug(f"Deduplicator changed to {deduplicator.__class__.__name__}")

    def reset(self) -> None:
        """Reset engine state (mainly deduplicator)."""
        self.deduplicator.reset()
        logger.debug("AlertEngine state reset")
