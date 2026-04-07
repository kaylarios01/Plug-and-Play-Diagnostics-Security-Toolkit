"""
Unit tests for AlertEngine module.

Tests cover:
- Rule engine functionality
- Alert generation
- Deduplication
- Schema compliance
- Edge cases
"""

import pytest
import logging
from datetime import datetime

from security_toolkit.modules.alert_engine import (
    AlertEngine,
    HashBasedDeduplicator,
    SignatureBasedDeduplicator,
    RuleEngine,
    Rule,
    get_default_rules,
)
from security_toolkit.core.schemas import AlertEngineResult

logger = logging.getLogger(__name__)


class TestAlertEngineInitialization:
    """Test alert engine initialization."""

    def test_engine_creation_with_defaults(self):
        """Test creating engine with default rules."""
        engine = AlertEngine()
        assert engine is not None
        assert engine.rule_engine is not None

    def test_engine_creation_with_custom_rules(self):
        """Test creating engine with custom rule engine."""
        custom_rules = RuleEngine()
        engine = AlertEngine(rule_engine=custom_rules)
        assert engine.rule_engine is custom_rules

    def test_engine_creation_with_custom_deduplicator(self):
        """Test creating engine with custom deduplicator."""
        custom_dedup = HashBasedDeduplicator()
        engine = AlertEngine(deduplicator=custom_dedup)
        assert engine.deduplicator is custom_dedup


class TestAlertEngineBasicOperation:
    """Test basic alert engine operations."""

    def get_sample_inspection(self):
        """Get sample inspection data for testing."""
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
                    "metadata": {},
                }
            ],
            "summary": {
                "total_sessions": 1,
                "total_flags": 1,
                "protocols_seen": ["TCP"],
                "unique_ips": 2,
            },
            "flags": [
                {
                    "type": "insecure_protocol",
                    "detail": "HTTP detected",
                    "severity_hint": "medium",
                }
            ],
        }

    def test_process_valid_input(self):
        """Test processing valid inspection data."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)

        assert result is not None
        assert isinstance(result, dict)

    def test_process_returns_correct_schema(self):
        """Test that process() returns data conforming to schema."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)

        # Required fields
        assert "alerts" in result
        assert "summary" in result
        assert "timestamp" in result

        # Correct types
        assert isinstance(result["alerts"], list)
        assert isinstance(result["summary"], dict)
        assert isinstance(result["timestamp"], str)

    def test_process_generates_alerts(self):
        """Test that process generates alerts from flags."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)

        # Should generate at least one alert
        assert len(result["alerts"]) > 0


class TestAlertEngineRules:
    """Test rule management."""

    def test_add_rule(self):
        """Test adding a rule to the engine."""
        engine = AlertEngine()
        initial_count = len(engine.rule_engine.list_rules())

        rule_dict = {
            "name": "test_rule",
            "severity": "High",
            "description_template": "Test alert",
            "condition": lambda x: True,
        }

        engine.add_rule(rule_dict)
        assert len(engine.rule_engine.list_rules()) > initial_count

    def test_add_rule_invalid_severity(self):
        """Test that invalid severity raises error."""
        engine = AlertEngine()

        rule_dict = {
            "name": "test_rule",
            "severity": "Invalid",
            "description_template": "Test",
            "condition": lambda x: True,
        }

        with pytest.raises(ValueError):
            engine.add_rule(rule_dict)

    def test_add_rule_missing_name(self):
        """Test that rule without name raises error."""
        engine = AlertEngine()

        rule_dict = {
            "severity": "High",
            "description_template": "Test",
            "condition": lambda x: True,
        }

        with pytest.raises(ValueError):
            engine.add_rule(rule_dict)


class TestAlertEngineDeduplication:
    """Test deduplication functionality."""

    def test_hash_based_deduplication(self):
        """Test hash-based deduplication."""
        dedup = HashBasedDeduplicator()

        item1 = {"type": "alert", "message": "test"}
        item2 = {"type": "alert", "message": "test"}
        item3 = {"type": "alert", "message": "different"}

        # First occurrence should not be duplicate
        assert not dedup.is_duplicate(item1)
        # Identical item should be duplicate
        assert dedup.is_duplicate(item2)
        # Different item should not be duplicate
        assert not dedup.is_duplicate(item3)

    def test_signature_based_deduplication(self):
        """Test signature-based deduplication."""
        dedup = SignatureBasedDeduplicator()

        item1 = {"type": "alert", "severity": "High", "description": "test"}
        item2 = {
            "type": "alert",
            "severity": "High",
            "description": "test",
            "extra_field": "ignored",
        }  # Extra field should be ignored
        item3 = {"type": "alert", "severity": "Medium", "description": "test"}

        # First occurrence should not be duplicate
        assert not dedup.is_duplicate(item1)
        # Same signature should be duplicate
        assert dedup.is_duplicate(item2)
        # Different severity should not be duplicate
        assert not dedup.is_duplicate(item3)

    def test_deduplicator_reset(self):
        """Test deduplicator reset."""
        dedup = SignatureBasedDeduplicator()

        item = {"type": "alert", "severity": "High", "description": "test"}

        # First occurrence
        assert not dedup.is_duplicate(item)
        # Duplicate
        assert dedup.is_duplicate(item)

        # Reset
        dedup.reset()

        # Should not be duplicate anymore
        assert not dedup.is_duplicate(item)


class TestAlertEngineSummary:
    """Test summary generation."""

    def get_sample_inspection(self):
        """Get sample inspection data."""
        return {
            "timestamp": "2026-03-30T10:30:00",
            "duration": 60,
            "sessions": [],
            "summary": {
                "total_sessions": 0,
                "total_flags": 2,
                "protocols_seen": [],
                "unique_ips": 0,
            },
            "flags": [
                {
                    "type": "insecure_protocol",
                    "detail": "HTTP detected",
                    "severity_hint": "medium",
                },
                {
                    "type": "insecure_protocol",
                    "detail": "FTP detected",
                    "severity_hint": "high",
                },
            ],
        }

    def test_summary_has_required_fields(self):
        """Test that summary has all required fields."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)
        summary = result["summary"]

        required_fields = {"total_alerts", "by_severity", "alert_types"}
        assert required_fields.issubset(summary.keys())

    def test_summary_counts_match(self):
        """Test that summary counts match actual alerts."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)

        assert (
            result["summary"]["total_alerts"] == len(result["alerts"])
        )

    def test_summary_severity_distribution(self):
        """Test severity distribution in summary."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)
        summary = result["summary"]

        # All severity levels should be present
        assert "Low" in summary["by_severity"]
        assert "Medium" in summary["by_severity"]
        assert "High" in summary["by_severity"]
        assert "Critical" in summary["by_severity"]


class TestAlertEngineValidation:
    """Test input validation."""

    def test_invalid_input_not_dict(self):
        """Test that non-dict input raises error."""
        engine = AlertEngine()

        with pytest.raises(ValueError):
            engine.process("not a dict")

    def test_invalid_input_missing_fields(self):
        """Test that missing required fields raise error."""
        engine = AlertEngine()

        invalid_input = {
            "timestamp": "2026-03-30T10:30:00",
            # Missing 'duration', 'sessions', 'summary', 'flags'
        }

        with pytest.raises(ValueError):
            engine.process(invalid_input)

    def test_invalid_input_flags_not_list(self):
        """Test that non-list flags raise error."""
        engine = AlertEngine()

        invalid_input = {
            "timestamp": "2026-03-30T10:30:00",
            "duration": 60,
            "sessions": [],
            "summary": {},
            "flags": "not a list",
        }

        with pytest.raises(ValueError):
            engine.process(invalid_input)


class TestAlertEngineSchema:
    """Test schema compliance."""

    def get_sample_inspection(self):
        """Get sample inspection data."""
        return {
            "timestamp": "2026-03-30T10:30:00",
            "duration": 60,
            "sessions": [],
            "summary": {
                "total_sessions": 0,
                "total_flags": 1,
                "protocols_seen": [],
                "unique_ips": 0,
            },
            "flags": [
                {
                    "type": "insecure_protocol",
                    "detail": "HTTP detected",
                    "severity_hint": "medium",
                }
            ],
        }

    def test_result_can_be_validated_against_schema(self):
        """Test that result validates against schema."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)

        # Should not raise
        validated = AlertEngineResult.from_dict(result)
        assert validated.summary.total_alerts == result["summary"]["total_alerts"]

    def test_result_to_json(self):
        """Test converting result to JSON."""
        engine = AlertEngine()
        inspection = self.get_sample_inspection()

        result = engine.process(inspection)

        # Create AlertEngineResult from dict
        alert_result = AlertEngineResult.from_dict(result)
        json_str = alert_result.to_json()

        # Should be valid JSON
        import json
        parsed = json.loads(json_str)
        assert "alerts" in parsed
        assert "summary" in parsed


class TestRuleEngine:
    """Test rule engine functionality."""

    def test_default_rules_loaded(self):
        """Test that default rules can be loaded."""
        engine = get_default_rules()

        rule_names = engine.list_rules()
        assert len(rule_names) > 0

    def test_default_rules_cover_findings(self):
        """Test that default rules cover common findings."""
        engine = get_default_rules()

        rule_names = engine.list_rules()

        # Should have rules for common finding types
        assert any("protocol" in name for name in rule_names)

    def test_rule_evaluation(self):
        """Test evaluating a finding against rules."""
        engine = get_default_rules()

        finding = {
            "type": "insecure_protocol",
            "detail": "HTTP detected on 192.168.1.1:80",
            "severity_hint": "medium",
        }

        matches = engine.evaluate(finding)

        # Should match at least one rule
        assert len(matches) > 0

    def test_rule_no_matches(self):
        """Test finding that matches no rules."""
        engine = get_default_rules()

        finding = {
            "type": "unknown_type",
            "detail": "Unknown finding",
            "severity_hint": "low",
        }

        matches = engine.evaluate(finding)

        # Should match no rules
        assert len(matches) == 0


class TestAlertEngineEdgeCases:
    """Test edge cases."""

    def test_empty_flags(self):
        """Test processing inspection with no flags."""
        engine = AlertEngine()

        inspection = {
            "timestamp": "2026-03-30T10:30:00",
            "duration": 60,
            "sessions": [],
            "summary": {
                "total_sessions": 0,
                "total_flags": 0,
                "protocols_seen": [],
                "unique_ips": 0,
            },
            "flags": [],
        }

        result = engine.process(inspection)

        assert len(result["alerts"]) == 0
        assert result["summary"]["total_alerts"] == 0

    def test_engine_reuse(self):
        """Test that engine can process multiple times."""
        engine = AlertEngine()

        inspection = {
            "timestamp": "2026-03-30T10:30:00",
            "duration": 60,
            "sessions": [],
            "summary": {
                "total_sessions": 0,
                "total_flags": 1,
                "protocols_seen": [],
                "unique_ips": 0,
            },
            "flags": [
                {
                    "type": "insecure_protocol",
                    "detail": "HTTP detected",
                    "severity_hint": "medium",
                }
            ],
        }

        result1 = engine.process(inspection)
        result2 = engine.process(inspection)

        # Results should be consistent
        assert result1["summary"]["total_alerts"] == result2["summary"]["total_alerts"]

    def test_engine_reset(self):
        """Test engine reset functionality."""
        engine = AlertEngine(deduplicator=SignatureBasedDeduplicator())

        inspection = {
            "timestamp": "2026-03-30T10:30:00",
            "duration": 60,
            "sessions": [],
            "summary": {
                "total_sessions": 0,
                "total_flags": 1,
                "protocols_seen": [],
                "unique_ips": 0,
            },
            "flags": [
                {
                    "type": "insecure_protocol",
                    "detail": "HTTP detected",
                    "severity_hint": "medium",
                }
            ],
        }

        result1 = engine.process(inspection)
        count1 = result1["summary"]["total_alerts"]

        engine.reset()

        result2 = engine.process(inspection)
        count2 = result2["summary"]["total_alerts"]

        # Should be same after reset
        assert count1 == count2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
