"""
Unit tests for tool wrapper functionality.

SPDX-License-Identifier: MIT
"""
import sys
import os
import tempfile
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))

import pytest
from iothackbot.core.tool_wrapper import (
    VulnerabilitySeverity,
    VulnerabilityFinding,
    ToolWrapper,
    ExternalToolWrapper,
)
from iothackbot.core.scope.scope_manager import (
    ScopeManager,
    ProgramScope,
    ScopeAsset,
    AssetType,
    BugBountyPlatform,
)


class TestVulnerabilitySeverity:
    """Test VulnerabilitySeverity enum"""

    def test_severity_values(self):
        """Test severity enum values"""
        assert VulnerabilitySeverity.CRITICAL.value == "critical"
        assert VulnerabilitySeverity.HIGH.value == "high"
        assert VulnerabilitySeverity.MEDIUM.value == "medium"
        assert VulnerabilitySeverity.LOW.value == "low"
        assert VulnerabilitySeverity.INFO.value == "informational"

    def test_severity_count(self):
        """Test that all expected severities exist"""
        severities = list(VulnerabilitySeverity)
        assert len(severities) == 5


class TestVulnerabilityFinding:
    """Test VulnerabilityFinding dataclass"""

    def test_finding_creation(self):
        """Test creating a vulnerability finding"""
        finding = VulnerabilityFinding(
            title="XSS in Search Parameter",
            description="Reflected XSS vulnerability",
            severity=VulnerabilitySeverity.HIGH,
            target="https://example.com/search",
            vulnerability_type="xss"
        )
        assert finding.title == "XSS in Search Parameter"
        assert finding.severity == VulnerabilitySeverity.HIGH
        assert finding.vulnerability_type == "xss"

    def test_finding_defaults(self):
        """Test finding default values"""
        finding = VulnerabilityFinding(
            title="Test",
            description="Test",
            severity=VulnerabilitySeverity.LOW,
            target="http://test.com",
            vulnerability_type="test"
        )
        assert finding.proof_of_concept == ""
        assert finding.request == ""
        assert finding.response == ""
        assert finding.steps_to_reproduce == []
        assert finding.confidence == "high"

    def test_finding_auto_timestamp(self):
        """Test that discovered_at is auto-populated"""
        finding = VulnerabilityFinding(
            title="Test",
            description="Test",
            severity=VulnerabilitySeverity.INFO,
            target="http://test.com",
            vulnerability_type="test"
        )
        assert finding.discovered_at is not None

    def test_finding_with_all_fields(self):
        """Test finding with all fields populated"""
        finding = VulnerabilityFinding(
            title="SQL Injection",
            description="SQL injection in login form",
            severity=VulnerabilitySeverity.CRITICAL,
            target="https://example.com/login",
            vulnerability_type="sqli",
            proof_of_concept="' OR 1=1--",
            request="POST /login HTTP/1.1\n...",
            response="HTTP/1.1 200 OK\n...",
            steps_to_reproduce=["Navigate to login", "Enter payload"],
            bugcrowd_priority="P1",
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_id="CWE-89",
            tool="sqlmap"
        )
        assert finding.bugcrowd_priority == "P1"
        assert finding.cvss_score == 9.8
        assert finding.cwe_id == "CWE-89"


class MockToolWrapper(ToolWrapper):
    """Mock implementation of ToolWrapper for testing"""

    def tool_name(self) -> str:
        return "mock_tool"

    def attack_type(self) -> str:
        return "xss"

    def run_scan(self, target: str, **kwargs):
        return [
            VulnerabilityFinding(
                title="Mock Finding",
                description="Test finding",
                severity=VulnerabilitySeverity.MEDIUM,
                target=target,
                vulnerability_type="xss"
            )
        ]


class TestToolWrapper:
    """Test ToolWrapper abstract class"""

    @pytest.fixture
    def temp_config_dir(self):
        """Create a temporary directory for scope configurations"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_tool(self, temp_config_dir):
        """Create a mock tool with scope manager"""
        scope_manager = ScopeManager(config_dir=temp_config_dir)
        return MockToolWrapper(scope_manager=scope_manager)

    def test_tool_wrapper_initialization(self, mock_tool):
        """Test tool wrapper initialization"""
        assert mock_tool.tool_name() == "mock_tool"
        assert mock_tool.attack_type() == "xss"
        assert mock_tool.scope_manager is not None

    def test_execute_without_scope(self, mock_tool):
        """Test execution without scope loaded"""
        success, findings, msg = mock_tool.execute("https://example.com")
        assert success is True
        assert len(findings) == 1
        assert "successfully" in msg.lower()

    def test_execute_with_valid_scope(self, mock_tool, temp_config_dir):
        """Test execution with valid scope"""
        # Set up a scope
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            in_scope=[
                ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
            ],
            allowed_attack_types={"xss", "sqli"}
        )
        mock_tool.scope_manager.current_scope = scope

        success, findings, msg = mock_tool.execute("https://example.com")
        assert success is True
        assert len(findings) == 1

    def test_execute_with_out_of_scope_target(self, mock_tool, temp_config_dir):
        """Test execution with out-of-scope target"""
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            in_scope=[
                ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
            ]
        )
        mock_tool.scope_manager.current_scope = scope

        success, findings, msg = mock_tool.execute("https://other.com")
        assert success is False
        assert len(findings) == 0
        assert "not found in scope" in msg or "VIOLATION" in msg

    def test_execute_with_forbidden_attack(self, mock_tool, temp_config_dir):
        """Test execution with forbidden attack type"""
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            in_scope=[
                ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
            ],
            forbidden_attack_types={"xss"}
        )
        mock_tool.scope_manager.current_scope = scope

        success, findings, msg = mock_tool.execute("https://example.com")
        assert success is False
        assert len(findings) == 0
        assert "forbidden" in msg.lower()

    def test_priority_to_cvss_mapping(self, mock_tool):
        """Test priority to CVSS score mapping"""
        assert mock_tool._priority_to_cvss(1) == 9.5
        assert mock_tool._priority_to_cvss(2) == 7.5
        assert mock_tool._priority_to_cvss(3) == 5.5
        assert mock_tool._priority_to_cvss(4) == 3.0
        assert mock_tool._priority_to_cvss(5) == 0.0
        assert mock_tool._priority_to_cvss(99) == 0.0  # Unknown priority

    def test_get_cwe_mapping(self, mock_tool):
        """Test CWE ID lookup"""
        assert mock_tool._get_cwe_mapping("xss") == "CWE-79"
        assert mock_tool._get_cwe_mapping("sqli") == "CWE-89"
        assert mock_tool._get_cwe_mapping("csrf") == "CWE-352"
        assert mock_tool._get_cwe_mapping("ssrf") == "CWE-918"

    def test_get_cwe_mapping_normalized(self, mock_tool):
        """Test CWE mapping with various input formats"""
        assert mock_tool._get_cwe_mapping("XSS") == "CWE-79"
        assert mock_tool._get_cwe_mapping("SQL_INJECTION") == "CWE-89"
        assert mock_tool._get_cwe_mapping("sql-injection") == "CWE-89"

    def test_get_cwe_mapping_unknown(self, mock_tool):
        """Test CWE mapping for unknown type"""
        assert mock_tool._get_cwe_mapping("unknown_vuln_type") is None


class MockExternalTool(ExternalToolWrapper):
    """Mock implementation of ExternalToolWrapper for testing"""

    def tool_name(self) -> str:
        return "mock_external_tool"

    def attack_type(self) -> str:
        return "recon"

    def get_command(self, target: str, **kwargs):
        return ["echo", f"scanning {target}"]

    def parse_output(self, stdout: str, stderr: str):
        if "scanning" in stdout:
            return [
                VulnerabilityFinding(
                    title="Found something",
                    description=stdout,
                    severity=VulnerabilitySeverity.INFO,
                    target="test",
                    vulnerability_type="info"
                )
            ]
        return []


class TestExternalToolWrapper:
    """Test ExternalToolWrapper class"""

    @pytest.fixture
    def temp_config_dir(self):
        """Create a temporary directory for scope configurations"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def mock_external_tool(self, temp_config_dir):
        """Create a mock external tool"""
        scope_manager = ScopeManager(config_dir=temp_config_dir)
        return MockExternalTool(scope_manager=scope_manager)

    def test_external_tool_run_scan(self, mock_external_tool):
        """Test running external tool scan"""
        findings = mock_external_tool.run_scan("example.com")
        assert len(findings) == 1
        assert "scanning example.com" in findings[0].description

    def test_external_tool_get_command(self, mock_external_tool):
        """Test command generation"""
        command = mock_external_tool.get_command("example.com")
        assert command == ["echo", "scanning example.com"]


class TestVulnerabilityRating:
    """Test vulnerability rating functionality"""

    @pytest.fixture
    def temp_config_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def tool_with_findings(self, temp_config_dir):
        """Create a tool that produces findings for rating"""
        class RatingTestTool(ToolWrapper):
            def tool_name(self) -> str:
                return "rating_test"

            def attack_type(self) -> str:
                return "xss"

            def run_scan(self, target: str, **kwargs):
                return [
                    VulnerabilityFinding(
                        title="XSS",
                        description="Found XSS",
                        severity=VulnerabilitySeverity.HIGH,
                        target=target,
                        vulnerability_type="xss"
                    )
                ]

        scope_manager = ScopeManager(config_dir=temp_config_dir)
        return RatingTestTool(scope_manager=scope_manager)

    def test_findings_get_rated(self, tool_with_findings):
        """Test that findings get CWE IDs assigned"""
        success, findings, _ = tool_with_findings.execute("https://example.com")
        assert success is True
        assert len(findings) == 1
        # CWE mapping should be applied
        assert findings[0].cwe_id == "CWE-79"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
