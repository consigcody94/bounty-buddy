"""
Constants and configuration values for Bounty Buddy tools.

Centralizes hardcoded values for maintainability and configurability.

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

from typing import Dict, Set, FrozenSet

# =============================================================================
# Network Scanning Constants
# =============================================================================

# Default timeouts (in seconds)
DEFAULT_CONNECT_TIMEOUT: float = 1.0
DEFAULT_UDP_TIMEOUT: float = 2.0
DEFAULT_HTTP_TIMEOUT: float = 10.0
DEFAULT_BRUTE_FORCE_DELAY: float = 0.5

# Concurrency limits
DEFAULT_MAX_CONCURRENT_CONNECTIONS: int = 100
DEFAULT_MAX_CONCURRENT_UDP: int = 50
DEFAULT_CHUNK_SIZE: int = 1000

# Port scanning
COMMON_IOT_PORTS: FrozenSet[int] = frozenset({
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    80,    # HTTP
    443,   # HTTPS
    554,   # RTSP
    1883,  # MQTT
    8080,  # HTTP Alt
    8443,  # HTTPS Alt
    8883,  # MQTT TLS
    8554,  # RTSP Alt
    37777, # Dahua DVR
    34567, # XMEye DVR
    5000,  # ONVIF Discovery
})

# ONVIF default ports
ONVIF_PORTS: FrozenSet[int] = frozenset({80, 8080, 8899, 554, 8554})

# WS-Discovery multicast settings
WS_DISCOVERY_MULTICAST_IP: str = "239.255.255.250"
WS_DISCOVERY_MULTICAST_PORT: int = 3702

# =============================================================================
# MQTT Protocol Constants
# =============================================================================

MQTT_DEFAULT_PORT: int = 1883
MQTT_TLS_PORT: int = 8883
MQTT_WEBSOCKET_PORT: int = 9001

# Common MQTT topics for IoT devices
MQTT_IOT_TOPICS: FrozenSet[str] = frozenset({
    "$SYS/#",
    "devices/#",
    "sensors/#",
    "home/#",
    "iot/#",
    "telemetry/#",
    "commands/#",
    "status/#",
})

# =============================================================================
# Vulnerability Classification Constants
# =============================================================================

# CWE ID mappings for common vulnerability types
CWE_MAPPINGS: Dict[str, str] = {
    "xss": "CWE-79",
    "reflected_xss": "CWE-79",
    "stored_xss": "CWE-79",
    "dom_xss": "CWE-79",
    "sqli": "CWE-89",
    "sql_injection": "CWE-89",
    "csrf": "CWE-352",
    "ssrf": "CWE-918",
    "idor": "CWE-639",
    "insecure_direct_object_reference": "CWE-639",
    "lfi": "CWE-22",
    "local_file_inclusion": "CWE-22",
    "rfi": "CWE-98",
    "remote_file_inclusion": "CWE-98",
    "xxe": "CWE-611",
    "xml_external_entity": "CWE-611",
    "ssti": "CWE-94",
    "server_side_template_injection": "CWE-94",
    "rce": "CWE-78",
    "remote_code_execution": "CWE-78",
    "command_injection": "CWE-78",
    "path_traversal": "CWE-22",
    "open_redirect": "CWE-601",
    "broken_auth": "CWE-287",
    "weak_password": "CWE-521",
    "default_credentials": "CWE-798",
    "hardcoded_credentials": "CWE-798",
    "sensitive_data_exposure": "CWE-200",
    "insecure_deserialization": "CWE-502",
    "security_misconfiguration": "CWE-16",
    "insufficient_logging": "CWE-778",
}

# Bugcrowd priority to CVSS score mapping
PRIORITY_TO_CVSS: Dict[int, float] = {
    1: 9.5,   # Critical - CVSS 9.0-10.0
    2: 7.5,   # High - CVSS 7.0-8.9
    3: 5.5,   # Medium - CVSS 4.0-6.9
    4: 3.0,   # Low - CVSS 0.1-3.9
    5: 0.0,   # Informational - CVSS 0.0
}

# =============================================================================
# File Type Detection Constants
# =============================================================================

# MIME types for security-relevant artifacts
ARTIFACT_MIME_TYPES: FrozenSet[str] = frozenset({
    "text/x-ssl-private-key",
    "application/java-archive",
    "application/x-pem-file",
    "application/x-pkcs12",
    "application/pgp-keys",
})

# File extensions for security-relevant artifacts
ARTIFACT_EXTENSIONS: FrozenSet[str] = frozenset({
    ".key",
    ".pem",
    ".p12",
    ".pfx",
    ".jks",
    ".keystore",
    ".env",
    ".credentials",
    ".htpasswd",
    ".shadow",
    ".id_rsa",
    ".id_dsa",
    ".id_ecdsa",
    ".id_ed25519",
})

# Extractable MIME types
EXTRACTABLE_MIME_TYPES: FrozenSet[str] = frozenset({
    "application/java-archive",
    "application/zip",
    "application/x-tar",
    "application/gzip",
    "application/x-bzip2",
    "application/x-7z-compressed",
    "application/x-rar-compressed",
})

# =============================================================================
# Default Attack Types
# =============================================================================

# Standard allowed attack types for bug bounty
DEFAULT_ALLOWED_ATTACK_TYPES: FrozenSet[str] = frozenset({
    "xss",
    "sqli",
    "ssrf",
    "idor",
    "auth",
    "csrf",
    "xxe",
    "lfi",
    "rfi",
    "ssti",
    "rce",
    "path_traversal",
    "open_redirect",
})

# Typically forbidden attack types
DEFAULT_FORBIDDEN_ATTACK_TYPES: FrozenSet[str] = frozenset({
    "dos",
    "ddos",
    "social_engineering",
    "physical",
    "spam",
})

# =============================================================================
# Brute Force Limits
# =============================================================================

# Maximum attempts before rate limiting kicks in
MAX_BRUTE_FORCE_ATTEMPTS: int = 100
DEFAULT_BRUTE_FORCE_THREADS: int = 5
BRUTE_FORCE_ATTEMPT_DELAY: float = 0.5

# =============================================================================
# Output Formatting
# =============================================================================

# ANSI color codes (for non-colorama usage)
COLORS: Dict[str, str] = {
    "RED": "\033[91m",
    "GREEN": "\033[92m",
    "YELLOW": "\033[93m",
    "BLUE": "\033[94m",
    "MAGENTA": "\033[95m",
    "CYAN": "\033[96m",
    "WHITE": "\033[97m",
    "RESET": "\033[0m",
    "BOLD": "\033[1m",
}

# Severity color mapping
SEVERITY_COLORS: Dict[str, str] = {
    "critical": "RED",
    "high": "RED",
    "medium": "YELLOW",
    "low": "BLUE",
    "informational": "CYAN",
    "info": "CYAN",
}
