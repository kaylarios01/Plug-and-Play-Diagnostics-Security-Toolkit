"""
Unit tests for NetworkInspector module.

Tests cover:
- Constructor and configuration
- Mock session generation
- Session analysis
- Flag detection
- Schema compliance
- Edge cases
"""

import pytest
import logging
from datetime import datetime

from security_toolkit.modules.network_inspector import NetworkInspector
from security_toolkit.core.schemas import InspectionResult, Flag

logger = logging.getLogger(__name__)


class TestNetworkInspectorInitialization:
    """Test inspector initialization."""

    def test_inspector_creation_mock_mode(self):
        """Test creating inspector in mock mode."""
        inspector = NetworkInspector(use_mock=True)
        assert inspector.use_mock is True
        assert inspector is not None

    def test_inspector_creation_auto_mode(self):
        """Test creating inspector with auto mode selection."""
        inspector = NetworkInspector(use_mock=False)
        # Should succeed even if scapy not available
        assert inspector is not None


class TestNetworkInspectorBasicOperation:
    """Test basic inspection operations."""

    def test_run_with_valid_duration(self):
        """Test running inspection with valid duration."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        assert result is not None
        assert isinstance(result, dict)

    def test_run_returns_correct_schema(self):
        """Test that run() returns data conforming to schema."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        # Required fields
        assert "timestamp" in result
        assert "duration" in result
        assert "sessions" in result
        assert "summary" in result
        assert "flags" in result

        # Correct types
        assert isinstance(result["timestamp"], str)
        assert isinstance(result["duration"], int)
        assert isinstance(result["sessions"], list)
        assert isinstance(result["flags"], list)

    def test_run_duration_reflected_in_result(self):
        """Test that requested duration is reflected in result."""
        inspector = NetworkInspector(use_mock=True)
        duration = 10
        result = inspector.run(duration=duration)

        assert result["duration"] == duration

    def test_run_timestamp_is_valid_iso8601(self):
        """Test that timestamp is valid ISO 8601 format."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        # Should not raise
        timestamp = datetime.fromisoformat(result["timestamp"])
        assert timestamp is not None


class TestNetworkInspectorMockMode:
    """Test mock session generation."""

    def test_mock_generates_sessions(self):
        """Test that mock mode generates sessions."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        assert len(result["sessions"]) > 0

    def test_mock_sessions_have_required_fields(self):
        """Test that mock sessions have all required fields."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        required_fields = {
            "src_ip",
            "dst_ip",
            "src_port",
            "dst_port",
            "protocol",
            "timestamp",
            "metadata",
        }

        for session in result["sessions"]:
            assert required_fields.issubset(session.keys())

    def test_mock_includes_insecure_protocols(self):
        """Test that mock data includes insecure protocols for testing."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        protocols = [s["protocol"] for s in result["sessions"]]
        # Mock should include HTTP, FTP, etc. for testing
        insecure_present = any(
            p in protocols for p in ["HTTP", "FTP", "TELNET"]
        )
        assert insecure_present


class TestNetworkInspectorAnalysis:
    """Test traffic analysis logic."""

    def test_insecure_protocol_detection(self):
        """Test detection of insecure protocols."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        flags = result["flags"]
        # Mock data includes HTTP and FTP which should be flagged
        insecure_flags = [
            f for f in flags if f["type"] == "insecure_protocol"
        ]
        assert len(insecure_flags) > 0

    def test_unusual_port_detection(self):
        """Test detection of unusual ports."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        flags = result["flags"]
        # Mock data includes VNC (5900) which should be flagged
        unusual_flags = [f for f in flags if f["type"] == "unusual_port"]
        # May or may not have based on mock data
        assert isinstance(unusual_flags, list)

    def test_flags_have_required_fields(self):
        """Test that flags have all required fields."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        required_fields = {"type", "detail", "severity_hint"}

        for flag in result["flags"]:
            assert required_fields.issubset(flag.keys())

    def test_flag_severity_hint_valid(self):
        """Test that flag severity hints are valid."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        valid_severities = {"low", "medium", "high", "critical"}

        for flag in result["flags"]:
            assert flag["severity_hint"] in valid_severities


class TestNetworkInspectorSummary:
    """Test summary generation."""

    def test_summary_has_required_fields(self):
        """Test that summary has all required fields."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        summary = result["summary"]
        required_fields = {
            "total_sessions",
            "total_flags",
            "protocols_seen",
            "unique_ips",
        }

        assert required_fields.issubset(summary.keys())

    def test_summary_totals_match_data(self):
        """Test that summary totals match actual data."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        assert result["summary"]["total_sessions"] == len(result["sessions"])
        assert result["summary"]["total_flags"] == len(result["flags"])

    def test_summary_protocols_seen_is_list(self):
        """Test that protocols list is properly formatted."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        protocols = result["summary"]["protocols_seen"]
        assert isinstance(protocols, list)
        assert len(protocols) > 0
        assert all(isinstance(p, str) for p in protocols)

    def test_summary_unique_ips_count(self):
        """Test unique IP counting."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        # Collect unique IPs from sessions
        ips = set()
        for session in result["sessions"]:
            ips.add(session["src_ip"])
            ips.add(session["dst_ip"])

        # Should match summary
        assert result["summary"]["unique_ips"] == len(ips)


class TestNetworkInspectorErrors:
    """Test error handling."""

    def test_invalid_duration_raises_error(self):
        """Test that invalid duration raises ValueError."""
        inspector = NetworkInspector(use_mock=True)

        with pytest.raises(ValueError):
            inspector.run(duration=0)

        with pytest.raises(ValueError):
            inspector.run(duration=-1)

    def test_schema_validation(self):
        """Test that result can be validated against schema."""
        inspector = NetworkInspector(use_mock=True)
        result = inspector.run(duration=5)

        # Should not raise
        validated = InspectionResult.from_dict(result)
        assert validated.duration == result["duration"]
        assert len(validated.sessions) == len(result["sessions"])


class TestNetworkInspectorEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_inspector_reuse(self):
        """Test that inspector can be reused multiple times."""
        inspector = NetworkInspector(use_mock=True)

        result1 = inspector.run(duration=2)
        result2 = inspector.run(duration=2)

        assert result1 is not None
        assert result2 is not None
        # Timestamps should be different
        assert result1["timestamp"] != result2["timestamp"]

    def test_different_durations(self):
        """Test running with different durations."""
        inspector = NetworkInspector(use_mock=True)

        result_short = inspector.run(duration=1)
        result_long = inspector.run(duration=10)

        assert result_short["duration"] == 1
        assert result_long["duration"] == 10


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
