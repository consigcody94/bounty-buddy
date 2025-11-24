"""
Base Tool Wrapper Framework

Provides common functionality for all bug bounty tools:
- Automatic scope validation
- Severity rating using taxonomies
- Standardized output format
- Logging and audit trails
- Result caching
"""

import json
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import List, Dict, Optional, Any

from .scope import ScopeManager
from .logger import setup_tool_logger


class VulnerabilitySeverity(Enum):
    """Standardized severity levels"""
    CRITICAL = "critical"  # P1 / CVSS 9.0-10.0
    HIGH = "high"          # P2 / CVSS 7.0-8.9
    MEDIUM = "medium"      # P3 / CVSS 4.0-6.9
    LOW = "low"            # P4 / CVSS 0.1-3.9
    INFO = "informational" # P5 / CVSS 0.0


@dataclass
class VulnerabilityFinding:
    """Represents a vulnerability finding"""
    title: str
    description: str
    severity: VulnerabilitySeverity
    target: str
    vulnerability_type: str  # e.g., 'xss', 'sqli', 'ssrf'

    # Evidence
    proof_of_concept: str = ""
    request: str = ""
    response: str = ""
    steps_to_reproduce: List[str] = None

    # Severity ratings
    bugcrowd_priority: Optional[str] = None  # P1-P5
    cvss_score: Optional[float] = None       # 0.0-10.0
    cvss_vector: Optional[str] = None
    cwe_id: Optional[str] = None

    # Metadata
    discovered_at: str = None
    tool: str = ""
    confidence: str = "high"  # high, medium, low

    def __post_init__(self):
        if self.discovered_at is None:
            self.discovered_at = datetime.utcnow().isoformat()
        if self.steps_to_reproduce is None:
            self.steps_to_reproduce = []


class ToolWrapper(ABC):
    """
    Base class for all bug bounty tools

    Provides:
    - Scope validation
    - Severity rating
    - Result standardization
    - Logging
    """

    def __init__(self, scope_manager: Optional[ScopeManager] = None):
        self.scope_manager = scope_manager or ScopeManager()
        self.logger = setup_tool_logger(self.tool_name(), verbose=True)
        self.taxonomy = self._load_taxonomy()

    @abstractmethod
    def tool_name(self) -> str:
        """Return the tool name"""
        pass

    @abstractmethod
    def attack_type(self) -> str:
        """Return the attack type (xss, sqli, ssrf, etc.)"""
        pass

    @abstractmethod
    def run_scan(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """
        Run the security scan

        Args:
            target: Target URL/domain/IP
            **kwargs: Tool-specific arguments

        Returns:
            List of vulnerability findings
        """
        pass

    def execute(self, target: str, **kwargs) -> tuple[bool, List[VulnerabilityFinding], str]:
        """
        Execute tool with scope validation

        Returns:
            (success, findings, message)
        """
        # Validate target against scope
        is_valid, msg = self.validate_target(target)
        if not is_valid:
            self.logger.error(f"Scope validation failed: {msg}")
            return False, [], msg

        # Validate attack type
        attack_type = self.attack_type()
        if self.scope_manager.current_scope:
            can_attack, attack_msg = self.scope_manager.current_scope.can_perform_attack(attack_type)
            if not can_attack:
                self.logger.error(f"Attack type forbidden: {attack_msg}")
                return False, [], attack_msg

        self.logger.info(f"Starting {self.tool_name()} scan on {target}")

        try:
            # Run the actual scan
            findings = self.run_scan(target, **kwargs)

            # Rate findings using taxonomies
            findings = self._rate_findings(findings)

            self.logger.info(f"Scan complete. Found {len(findings)} potential vulnerabilities.")
            return True, findings, f"Scan completed successfully"

        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return False, [], f"Error: {str(e)}"

    def validate_target(self, target: str) -> tuple[bool, str]:
        """Validate target against scope"""
        if not self.scope_manager.current_scope:
            self.logger.warning("No scope loaded - skipping validation")
            return True, "No scope validation (no scope loaded)"

        return self.scope_manager.validate_target(target, self.attack_type())

    def _load_taxonomy(self) -> Dict:
        """Load Bugcrowd VRT taxonomy"""
        taxonomy_path = Path(__file__).parent.parent / "taxonomies" / "bugcrowd-vrt.json"

        if not taxonomy_path.exists():
            self.logger.warning(f"Taxonomy not found: {taxonomy_path}")
            return {}

        with open(taxonomy_path, 'r') as f:
            data = json.load(f)

        return data

    def _rate_findings(self, findings: List[VulnerabilityFinding]) -> List[VulnerabilityFinding]:
        """Apply severity ratings to findings using taxonomy"""
        for finding in findings:
            # Map vulnerability type to Bugcrowd VRT
            vrt_entry = self._find_vrt_entry(finding.vulnerability_type)

            if vrt_entry:
                # Set Bugcrowd priority (P1-P5)
                priority = vrt_entry.get('priority')
                if priority:
                    finding.bugcrowd_priority = f"P{priority}"

                # Map priority to CVSS score (approximate)
                finding.cvss_score = self._priority_to_cvss(priority)

                # Get CWE mapping if available
                finding.cwe_id = self._get_cwe_mapping(finding.vulnerability_type)

        return findings

    def _find_vrt_entry(self, vuln_type: str) -> Optional[Dict]:
        """Find vulnerability in Bugcrowd VRT"""
        if not self.taxonomy or 'content' not in self.taxonomy:
            return None

        # Simple search through taxonomy
        # TODO: Implement more sophisticated matching
        vuln_type_lower = vuln_type.lower().replace('_', ' ')

        for category in self.taxonomy['content']:
            if self._search_category(category, vuln_type_lower):
                return self._search_category(category, vuln_type_lower)

        return None

    def _search_category(self, category: Dict, search_term: str) -> Optional[Dict]:
        """Recursively search category for vulnerability type"""
        name = category.get('name', '').lower()

        if search_term in name:
            return category

        # Search children
        for child in category.get('children', []):
            result = self._search_category(child, search_term)
            if result:
                return result

        return None

    @staticmethod
    def _priority_to_cvss(priority: int) -> float:
        """Convert Bugcrowd priority to approximate CVSS score"""
        mapping = {
            1: 9.5,  # Critical
            2: 7.5,  # High
            3: 5.5,  # Medium
            4: 3.0,  # Low
            5: 0.0,  # Informational
        }
        return mapping.get(priority, 0.0)

    def _get_cwe_mapping(self, vuln_type: str) -> Optional[str]:
        """Get CWE ID for vulnerability type"""
        # Load CWE mapping
        cwe_path = Path(__file__).parent.parent / "taxonomies" / "bugcrowd-cwe-mapping.json"

        if not cwe_path.exists():
            return None

        # TODO: Implement CWE lookup
        # For now, return common CWE IDs based on type
        cwe_mappings = {
            'xss': 'CWE-79',
            'sqli': 'CWE-89',
            'csrf': 'CWE-352',
            'ssrf': 'CWE-918',
            'idor': 'CWE-639',
            'lfi': 'CWE-22',
            'rfi': 'CWE-98',
            'xxe': 'CWE-611',
            'ssti': 'CWE-94',
        }

        return cwe_mappings.get(vuln_type.lower())


class ExternalToolWrapper(ToolWrapper):
    """
    Wrapper for external command-line tools

    Handles subprocess execution and output parsing
    """

    @abstractmethod
    def get_command(self, target: str, **kwargs) -> List[str]:
        """
        Build command to execute

        Returns:
            List of command arguments
        """
        pass

    @abstractmethod
    def parse_output(self, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """
        Parse tool output into findings

        Args:
            stdout: Standard output
            stderr: Standard error

        Returns:
            List of vulnerability findings
        """
        pass

    def run_scan(self, target: str, **kwargs) -> List[VulnerabilityFinding]:
        """Execute external tool and parse results"""
        command = self.get_command(target, **kwargs)
        self.logger.debug(f"Executing command: {' '.join(command)}")

        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=kwargs.get('timeout', 300)  # 5 min default
            )

            findings = self.parse_output(result.stdout, result.stderr)

            if result.returncode != 0 and not findings:
                self.logger.warning(f"Tool exited with code {result.returncode}")
                self.logger.debug(f"STDERR: {result.stderr}")

            return findings

        except subprocess.TimeoutExpired:
            self.logger.error(f"Tool timeout after {kwargs.get('timeout', 300)} seconds")
            return []
        except FileNotFoundError:
            self.logger.error(f"Tool not found. Install '{command[0]}' first.")
            return []
        except Exception as e:
            self.logger.error(f"Tool execution failed: {str(e)}")
            return []


# Example usage
if __name__ == "__main__":
    # This would be implemented by specific tools
    pass
