"""
Rule system for alert generation.

Provides configurable rules that map from inspection findings to alerts
with appropriate severity levels.
"""

import logging
import json
import yaml
from typing import Dict, Any, List, Callable, Optional
from pathlib import Path

logger = logging.getLogger(__name__)


class Rule:
    """
    A single alert rule.
    
    Maps conditions to severity levels. Rules are applied to inspection
    findings to generate alerts.
    
    Attributes:
        name: Rule identifier.
        condition: Function that returns True if rule matches.
        severity: Severity level for matches (Low, Medium, High, Critical).
        description_template: Template for alert description.
    """

    def __init__(
        self,
        name: str,
        condition: Callable[[Dict[str, Any]], bool],
        severity: str,
        description_template: str,
    ):
        """
        Initialize rule.
        
        Args:
            name: Unique rule identifier.
            condition: Callable that evaluates to True for matches.
            severity: Severity level.
            description_template: Message template (supports format strings).
        """
        if severity not in ("Low", "Medium", "High", "Critical"):
            raise ValueError(f"Invalid severity: {severity}")
        
        self.name = name
        self.condition = condition
        self.severity = severity
        self.description_template = description_template

    def matches(self, finding: Dict[str, Any]) -> bool:
        """Check if finding matches this rule's condition."""
        try:
            return self.condition(finding)
        except Exception as e:
            logger.warning(f"Error evaluating rule {self.name}: {e}")
            return False

    def generate_description(self, finding: Dict[str, Any]) -> str:
        """Generate description for matched finding."""
        try:
            return self.description_template.format(**finding)
        except KeyError:
            return self.description_template


class RuleEngine:
    """
    Manages and applies alert rules.
    
    Supports loading rules from code, JSON, or YAML files.
    Applies rules to inspection findings to determine alerts.
    """

    def __init__(self):
        """Initialize empty rule engine."""
        self.rules: Dict[str, Rule] = {}

    def add_rule(self, rule: Rule) -> None:
        """
        Add rule to engine.
        
        Args:
            rule: Rule object to add.
            
        Raises:
            ValueError: If rule with same name already exists.
        """
        if rule.name in self.rules:
            raise ValueError(f"Rule {rule.name} already exists")
        self.rules[rule.name] = rule
        logger.debug(f"Added rule: {rule.name}")

    def update_rule(self, rule: Rule) -> None:
        """Add or update rule."""
        self.rules[rule.name] = rule
        logger.debug(f"Updated rule: {rule.name}")

    def remove_rule(self, rule_name: str) -> None:
        """Remove rule by name."""
        if rule_name in self.rules:
            del self.rules[rule_name]
            logger.debug(f"Removed rule: {rule_name}")

    def get_rule(self, rule_name: str) -> Optional[Rule]:
        """Get rule by name."""
        return self.rules.get(rule_name)

    def list_rules(self) -> List[str]:
        """Get list of all rule names."""
        return list(self.rules.keys())

    def evaluate(self, finding: Dict[str, Any]) -> List[tuple]:
        """
        Evaluate all rules against finding.
        
        Args:
            finding: Finding dict (e.g., a flag from inspection).
            
        Returns:
            List of (rule_name, severity, description) tuples for matches.
        """
        matches = []
        for rule_name, rule in self.rules.items():
            if rule.matches(finding):
                description = rule.generate_description(finding)
                matches.append((rule_name, rule.severity, description))
                logger.debug(f"Rule {rule_name} matched finding: {finding}")
        return matches

    @classmethod
    def load_from_json(cls, file_path: str) -> "RuleEngine":
        """
        Load rules from JSON file.
        
        Expected format:
        {
            "rules": [
                {
                    "name": "rule_name",
                    "severity": "High",
                    "description_template": "Message {field}",
                    "field_checks": {
                        "type": "insecure_protocol",
                        "severity_hint": "medium"
                    }
                }
            ]
        }
        
        Args:
            file_path: Path to JSON rule file.
            
        Returns:
            RuleEngine with loaded rules.
        """
        engine = cls()
        
        try:
            with open(file_path, 'r') as f:
                data = json.load(f)
            
            for rule_config in data.get("rules", []):
                engine._add_rule_from_config(rule_config)
            
            logger.info(f"Loaded {len(engine.rules)} rules from {file_path}")
        except Exception as e:
            logger.error(f"Failed to load rules from {file_path}: {e}")
            raise
        
        return engine

    @classmethod
    def load_from_yaml(cls, file_path: str) -> "RuleEngine":
        """
        Load rules from YAML file.
        
        Similar format to JSON but in YAML format.
        
        Args:
            file_path: Path to YAML rule file.
            
        Returns:
            RuleEngine with loaded rules.
        """
        engine = cls()
        
        try:
            with open(file_path, 'r') as f:
                data = yaml.safe_load(f)
            
            for rule_config in data.get("rules", []):
                engine._add_rule_from_config(rule_config)
            
            logger.info(f"Loaded {len(engine.rules)} rules from {file_path}")
        except ImportError:
            logger.error("PyYAML not installed. Install with: pip install pyyaml")
            raise
        except Exception as e:
            logger.error(f"Failed to load rules from {file_path}: {e}")
            raise
        
        return engine

    @staticmethod
    def _add_rule_from_config(engine: "RuleEngine", config: Dict[str, Any]) -> None:
        """
        Add rule from configuration dict.
        
        Args:
            config: Rule configuration.
        """
        name = config.get("name")
        severity = config.get("severity", "Medium")
        description_template = config.get("description_template", "Alert matched")
        field_checks = config.get("field_checks", {})
        
        if not name:
            raise ValueError("Rule config must have 'name' field")
        
        # Create condition function from field checks
        def create_condition(checks):
            def condition(finding):
                for field, expected_value in checks.items():
                    if finding.get(field) != expected_value:
                        return False
                return True
            return condition
        
        condition = create_condition(field_checks)
        rule = Rule(name, condition, severity, description_template)
        engine.add_rule(rule)

    def _add_rule_from_config(self, config: Dict[str, Any]) -> None:
        """Internal helper to add rule from config dict."""
        name = config.get("name")
        severity = config.get("severity", "Medium")
        description_template = config.get("description_template", "Alert matched")
        field_checks = config.get("field_checks", {})
        
        if not name:
            raise ValueError("Rule config must have 'name' field")
        
        # Create condition function from field checks
        def create_condition(checks):
            def condition(finding):
                for field, expected_value in checks.items():
                    if finding.get(field) != expected_value:
                        return False
                return True
            return condition
        
        condition = create_condition(field_checks)
        rule = Rule(name, condition, severity, description_template)
        self.add_rule(rule)


def get_default_rules() -> RuleEngine:
    """
    Get engine with default rules.
    
    Default rules cover common security findings:
    - Insecure protocols (HTTP, FTP, Telnet)
    - Unusual ports
    - Repeated connection attempts
    
    Returns:
        RuleEngine with default rules.
    """
    engine = RuleEngine()
    
    # Rule: Insecure protocol detected
    engine.add_rule(Rule(
        name="insecure_protocol_http",
        condition=lambda f: f.get("type") == "insecure_protocol" and "HTTP" in f.get("detail", ""),
        severity="High",
        description_template="Unencrypted HTTP traffic detected: {detail}",
    ))
    
    engine.add_rule(Rule(
        name="insecure_protocol_ftp",
        condition=lambda f: f.get("type") == "insecure_protocol" and "FTP" in f.get("detail", ""),
        severity="High",
        description_template="Unencrypted FTP traffic detected: {detail}",
    ))
    
    engine.add_rule(Rule(
        name="insecure_protocol_telnet",
        condition=lambda f: f.get("type") == "insecure_protocol" and "TELNET" in f.get("detail", ""),
        severity="Critical",
        description_template="Insecure Telnet protocol detected: {detail}",
    ))
    
    # Rule: Unusual port access
    engine.add_rule(Rule(
        name="unusual_port_access",
        condition=lambda f: f.get("type") == "unusual_port",
        severity="Low",
        description_template="Unusual port access detected: {detail}",
    ))
    
    # Rule: Repeated connection attempts
    engine.add_rule(Rule(
        name="repeated_connection_attempts",
        condition=lambda f: f.get("type") == "repeated_attempts",
        severity="Medium",
        description_template="Suspicious connection pattern detected: {detail}",
    ))
    
    logger.debug("Default rules loaded")
    return engine
