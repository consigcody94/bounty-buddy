"""
Unit tests for constants module.

SPDX-License-Identifier: MIT
"""
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))

import pytest
from iothackbot.core.constants import (
    # Network constants
    DEFAULT_CONNECT_TIMEOUT,
    DEFAULT_UDP_TIMEOUT,
    DEFAULT_HTTP_TIMEOUT,
    DEFAULT_MAX_CONCURRENT_CONNECTIONS,
    DEFAULT_MAX_CONCURRENT_UDP,
    DEFAULT_CHUNK_SIZE,
    COMMON_IOT_PORTS,
    ONVIF_PORTS,
    WS_DISCOVERY_MULTICAST_IP,
    WS_DISCOVERY_MULTICAST_PORT,
    # MQTT constants
    MQTT_DEFAULT_PORT,
    MQTT_TLS_PORT,
    MQTT_IOT_TOPICS,
    # Vulnerability constants
    CWE_MAPPINGS,
    PRIORITY_TO_CVSS,
    # File type constants
    ARTIFACT_MIME_TYPES,
    ARTIFACT_EXTENSIONS,
    EXTRACTABLE_MIME_TYPES,
    # Attack type constants
    DEFAULT_ALLOWED_ATTACK_TYPES,
    DEFAULT_FORBIDDEN_ATTACK_TYPES,
    # Brute force constants
    MAX_BRUTE_FORCE_ATTEMPTS,
    BRUTE_FORCE_ATTEMPT_DELAY,
    # Output constants
    COLORS,
    SEVERITY_COLORS,
)


class TestNetworkConstants:
    """Test network-related constants"""

    def test_timeout_values_positive(self):
        """Test that timeout values are positive"""
        assert DEFAULT_CONNECT_TIMEOUT > 0
        assert DEFAULT_UDP_TIMEOUT > 0
        assert DEFAULT_HTTP_TIMEOUT > 0

    def test_concurrency_limits_positive(self):
        """Test that concurrency limits are positive"""
        assert DEFAULT_MAX_CONCURRENT_CONNECTIONS > 0
        assert DEFAULT_MAX_CONCURRENT_UDP > 0
        assert DEFAULT_CHUNK_SIZE > 0

    def test_common_iot_ports_valid(self):
        """Test that IoT ports are valid port numbers"""
        for port in COMMON_IOT_PORTS:
            assert isinstance(port, int)
            assert 1 <= port <= 65535

    def test_onvif_ports_valid(self):
        """Test that ONVIF ports are valid"""
        for port in ONVIF_PORTS:
            assert isinstance(port, int)
            assert 1 <= port <= 65535

    def test_ws_discovery_settings(self):
        """Test WS-Discovery multicast settings"""
        assert WS_DISCOVERY_MULTICAST_IP == "239.255.255.250"
        assert WS_DISCOVERY_MULTICAST_PORT == 3702


class TestMQTTConstants:
    """Test MQTT-related constants"""

    def test_mqtt_ports_valid(self):
        """Test that MQTT ports are valid"""
        assert 1 <= MQTT_DEFAULT_PORT <= 65535
        assert MQTT_DEFAULT_PORT == 1883
        assert 1 <= MQTT_TLS_PORT <= 65535
        assert MQTT_TLS_PORT == 8883

    def test_mqtt_topics_format(self):
        """Test that MQTT topics are properly formatted"""
        for topic in MQTT_IOT_TOPICS:
            assert isinstance(topic, str)
            assert len(topic) > 0


class TestVulnerabilityConstants:
    """Test vulnerability classification constants"""

    def test_cwe_mappings_format(self):
        """Test CWE mappings format"""
        for vuln_type, cwe_id in CWE_MAPPINGS.items():
            assert isinstance(vuln_type, str)
            assert isinstance(cwe_id, str)
            assert cwe_id.startswith("CWE-")

    def test_common_vulnerabilities_mapped(self):
        """Test that common vulnerability types are mapped"""
        common_vulns = ["xss", "sqli", "csrf", "ssrf", "idor", "xxe"]
        for vuln in common_vulns:
            assert vuln in CWE_MAPPINGS

    def test_priority_to_cvss_values(self):
        """Test priority to CVSS score mappings"""
        for priority, cvss in PRIORITY_TO_CVSS.items():
            assert 1 <= priority <= 5
            assert 0.0 <= cvss <= 10.0

    def test_priority_to_cvss_ordering(self):
        """Test that higher priority (lower number) means higher CVSS"""
        assert PRIORITY_TO_CVSS[1] > PRIORITY_TO_CVSS[2]
        assert PRIORITY_TO_CVSS[2] > PRIORITY_TO_CVSS[3]
        assert PRIORITY_TO_CVSS[3] > PRIORITY_TO_CVSS[4]
        assert PRIORITY_TO_CVSS[4] > PRIORITY_TO_CVSS[5]


class TestFileTypeConstants:
    """Test file type detection constants"""

    def test_artifact_mime_types_format(self):
        """Test artifact MIME types format"""
        for mime_type in ARTIFACT_MIME_TYPES:
            assert isinstance(mime_type, str)
            assert "/" in mime_type  # MIME types have format type/subtype

    def test_artifact_extensions_format(self):
        """Test artifact extensions format"""
        for ext in ARTIFACT_EXTENSIONS:
            assert isinstance(ext, str)
            assert ext.startswith(".")

    def test_extractable_mime_types_format(self):
        """Test extractable MIME types format"""
        for mime_type in EXTRACTABLE_MIME_TYPES:
            assert isinstance(mime_type, str)
            assert "/" in mime_type


class TestAttackTypeConstants:
    """Test attack type constants"""

    def test_allowed_attack_types_format(self):
        """Test allowed attack types format"""
        for attack_type in DEFAULT_ALLOWED_ATTACK_TYPES:
            assert isinstance(attack_type, str)
            assert len(attack_type) > 0

    def test_forbidden_attack_types_format(self):
        """Test forbidden attack types format"""
        for attack_type in DEFAULT_FORBIDDEN_ATTACK_TYPES:
            assert isinstance(attack_type, str)
            assert len(attack_type) > 0

    def test_no_overlap_between_allowed_and_forbidden(self):
        """Test that allowed and forbidden sets don't overlap"""
        overlap = DEFAULT_ALLOWED_ATTACK_TYPES & DEFAULT_FORBIDDEN_ATTACK_TYPES
        assert len(overlap) == 0

    def test_dos_is_forbidden(self):
        """Test that DoS attacks are forbidden by default"""
        assert "dos" in DEFAULT_FORBIDDEN_ATTACK_TYPES

    def test_xss_and_sqli_allowed(self):
        """Test that common web vulns are allowed by default"""
        assert "xss" in DEFAULT_ALLOWED_ATTACK_TYPES
        assert "sqli" in DEFAULT_ALLOWED_ATTACK_TYPES


class TestBruteForceConstants:
    """Test brute force related constants"""

    def test_brute_force_limits_reasonable(self):
        """Test that brute force limits are reasonable"""
        assert MAX_BRUTE_FORCE_ATTEMPTS > 0
        assert MAX_BRUTE_FORCE_ATTEMPTS <= 1000  # Sanity check

    def test_brute_force_delay_positive(self):
        """Test that brute force delay is positive"""
        assert BRUTE_FORCE_ATTEMPT_DELAY > 0


class TestOutputConstants:
    """Test output formatting constants"""

    def test_colors_defined(self):
        """Test that essential colors are defined"""
        essential_colors = ["RED", "GREEN", "YELLOW", "BLUE", "RESET"]
        for color in essential_colors:
            assert color in COLORS
            assert isinstance(COLORS[color], str)

    def test_colors_are_ansi_codes(self):
        """Test that colors are ANSI escape codes"""
        for color_name, code in COLORS.items():
            assert code.startswith("\033[")

    def test_severity_colors_mapped(self):
        """Test that severity levels are mapped to colors"""
        severity_levels = ["critical", "high", "medium", "low", "informational"]
        for level in severity_levels:
            assert level in SEVERITY_COLORS
            assert SEVERITY_COLORS[level] in COLORS


class TestFrozenSets:
    """Test that constants that should be immutable are frozen"""

    def test_ports_are_frozensets(self):
        """Test that port sets are immutable"""
        assert isinstance(COMMON_IOT_PORTS, frozenset)
        assert isinstance(ONVIF_PORTS, frozenset)

    def test_attack_types_are_frozensets(self):
        """Test that attack type sets are immutable"""
        assert isinstance(DEFAULT_ALLOWED_ATTACK_TYPES, frozenset)
        assert isinstance(DEFAULT_FORBIDDEN_ATTACK_TYPES, frozenset)

    def test_file_types_are_frozensets(self):
        """Test that file type sets are immutable"""
        assert isinstance(ARTIFACT_MIME_TYPES, frozenset)
        assert isinstance(ARTIFACT_EXTENSIONS, frozenset)
        assert isinstance(EXTRACTABLE_MIME_TYPES, frozenset)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
