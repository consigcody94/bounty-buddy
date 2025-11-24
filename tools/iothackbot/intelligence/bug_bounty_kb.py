"""
Bug Bounty Intelligence Knowledge Base

Based on research from:
- DEFCON 32 Bug Bounty Village (2024)
- Academic research on vulnerability discovery
- HackerOne/Bugcrowd Top 10 vulnerabilities
- Jason Haddix's Bug Hunter Methodology
- CVE database trends
- Real-world bug bounty success patterns

This module provides intelligence on:
1. High-value vulnerability patterns (signal)
2. Low-value noise patterns (to filter out)
3. Proven testing techniques
4. Context-aware vulnerability prioritization
"""

from dataclasses import dataclass
from enum import Enum
from typing import List, Dict, Set, Optional


class VulnCategory(Enum):
    """Vulnerability categories based on impact"""
    CRITICAL_HIGH_IMPACT = "critical_high_impact"  # SSRF, RCE, Auth Bypass
    HIGH_VALUE = "high_value"                       # IDOR, Privilege Escalation
    MEDIUM_VALUE = "medium_value"                   # XSS (stored), SQLi
    COMMON_LOW_NOISE = "common_low_noise"           # XSS (reflected), Info Disclosure
    LOW_VALUE_NOISE = "low_value_noise"             # Self-XSS, minor issues


@dataclass
class VulnerabilityPattern:
    """Represents a vulnerability pattern with testing intelligence"""
    name: str
    category: VulnCategory
    testing_priority: int  # 1-10, 10 being highest
    common_locations: List[str]
    detection_techniques: List[str]
    polyglot_payloads: List[str]
    false_positive_indicators: List[str]
    high_value_indicators: List[str]
    avg_bounty_range: str  # e.g., "$500-$5000"
    cvss_range: str  # e.g., "7.0-9.0"


class BugBountyIntelligence:
    """
    Intelligence system for bug bounty hunting

    Based on research findings:
    1. Top 20% of researchers find 80% of critical vulnerabilities
    2. High-impact programs work with 56 researchers vs 97 for low-impact
    3. Hackers use automated tools + deep domain knowledge
    4. Success comes from knowing WHERE to look, not just HOW
    """

    def __init__(self):
        self.vulnerability_patterns = self._load_patterns()
        self.noise_filters = self._load_noise_filters()
        self.high_value_contexts = self._load_high_value_contexts()

    def _load_patterns(self) -> Dict[str, VulnerabilityPattern]:
        """
        Load vulnerability patterns based on research

        Research Source: HackerOne Top 10 Most Impactful Vulnerabilities
        - SSRF, IDOR, and Privilege Escalation are hardest to find but most valuable
        - XSS is #1 reported but often low-impact
        - Information Disclosure is common but usually medium severity
        """

        patterns = {}

        # === CRITICAL HIGH-IMPACT (Research-Backed) ===

        patterns['ssrf'] = VulnerabilityPattern(
            name="Server-Side Request Forgery (SSRF)",
            category=VulnCategory.CRITICAL_HIGH_IMPACT,
            testing_priority=10,
            common_locations=[
                "URL parameters (url=, path=, redirect=)",
                "File upload processing (image conversion, PDF generation)",
                "Webhook/callback URLs",
                "Import from URL functions",
                "XML parsers (XXE → SSRF)",
                "API endpoints accepting external URLs",
                "Cloud metadata services (169.254.169.254)"
            ],
            detection_techniques=[
                "Out-of-band detection (Burp Collaborator, interactsh)",
                "Time-based detection (DNS lookups)",
                "Error-based detection (different responses for internal vs external)",
                "Blind SSRF via webhooks"
            ],
            polyglot_payloads=[
                "http://169.254.169.254/latest/meta-data/",  # AWS metadata
                "http://metadata.google.internal/computeMetadata/v1/",  # GCP
                "http://[::]:80/",  # IPv6 localhost bypass
                "http://127.1:80/",  # Decimal bypass
                "http://0177.0.0.1:80/",  # Octal bypass
            ],
            false_positive_indicators=[
                "Only works on public URLs",
                "Strict URL validation blocks internal IPs",
                "No access to cloud metadata"
            ],
            high_value_indicators=[
                "Access to AWS/GCP metadata",
                "Read internal services",
                "Port scanning internal network",
                "Bypass firewall/WAF",
                "Chain with RCE"
            ],
            avg_bounty_range="$2000-$10000+",
            cvss_range="8.0-9.5"
        )

        patterns['idor'] = VulnerabilityPattern(
            name="Insecure Direct Object Reference (IDOR)",
            category=VulnCategory.HIGH_VALUE,
            testing_priority=9,
            common_locations=[
                "User profile endpoints (/user/{id})",
                "Document/file access (/ file/{id}, /download/{uuid})",
                "Payment/order endpoints (/order/{id})",
                "Private messages (/message/{id})",
                "Administrative functions",
                "API endpoints with numeric IDs",
                "UUID-based resources (test for prediction)"
            ],
            detection_techniques=[
                "Increment/decrement ID parameters",
                "Test with negative values",
                "Test with other users' IDs (horizontal priv esc)",
                "Test admin functions with user IDs (vertical priv esc)",
                "Check for UUID/hash predictability",
                "Autorize Burp plugin for automation"
            ],
            polyglot_payloads=[
                "?id=1, ?id=2, ?id=999999",
                "?id=-1, ?id=0",
                "?user=victim@example.com",
                "?uuid=00000000-0000-0000-0000-000000000001",
            ],
            false_positive_indicators=[
                "Same data returned for all IDs",
                "Proper authorization checks",
                "Returns 403 Forbidden"
            ],
            high_value_indicators=[
                "Access to other users' PII",
                "Change other users' passwords",
                "Delete other users' data",
                "Access admin-only resources",
                "Financial data access"
            ],
            avg_bounty_range="$500-$5000",
            cvss_range="6.0-8.5"
        )

        patterns['privilege_escalation'] = VulnerabilityPattern(
            name="Privilege Escalation (Horizontal & Vertical)",
            category=VulnCategory.HIGH_VALUE,
            testing_priority=9,
            common_locations=[
                "User management endpoints",
                "Role assignment functions",
                "Permission checks in APIs",
                "Admin panels",
                "Settings/configuration pages",
                "Billing/subscription changes"
            ],
            detection_techniques=[
                "Test admin functions as regular user",
                "Manipulate role parameters",
                "Test cross-account operations",
                "Bypass client-side restrictions",
                "Parameter pollution (role=admin&role=user)"
            ],
            polyglot_payloads=[
                "role=admin",
                "is_admin=true",
                "privilege=administrator",
                "user_type=super_user"
            ],
            false_positive_indicators=[
                "Server-side role validation",
                "Session-based permission checks",
                "Returns proper error messages"
            ],
            high_value_indicators=[
                "Regular user can access admin panel",
                "User can elevate own privileges",
                "Cross-account data modification",
                "Bypass payment restrictions"
            ],
            avg_bounty_range="$1000-$7000",
            cvss_range="7.0-9.0"
        )

        # === MEDIUM-HIGH VALUE (Common but impactful) ===

        patterns['xss_stored'] = VulnerabilityPattern(
            name="Cross-Site Scripting (Stored/Persistent)",
            category=VulnCategory.HIGH_VALUE,
            testing_priority=8,
            common_locations=[
                "Comment/review sections",
                "User profiles (bio, name, location)",
                "Forum posts",
                "File upload names",
                "Custom themes/CSS",
                "Event/calendar names",
                "Support tickets",
                "JSON POST values",
                "Error pages"
            ],
            detection_techniques=[
                "Test with polyglot payloads",
                "Test in different contexts (HTML, JS, CSS, attribute)",
                "Test with WAF bypass techniques",
                "Check content-type headers",
                "Test in admin panels (higher impact)"
            ],
            polyglot_payloads=[
                # Jason Haddix's polyglots from TBHM
                "';alert(String.fromCharCode(88,83,83))//",
                '"><marquee><img src=x onerror=confirm(1)></marquee>',
                '" onclick=alert(1)//<button \' onclick=alert(1)//> */ alert(1)//',
                "<svg/onload=alert(1)>",
                "javascript:alert(1)",
                # Context-specific
                "'-alert(1)-'",  # JS context
                "\"><script>alert(1)</script>",  # HTML context
            ],
            false_positive_indicators=[
                "Payload encoded but not executed",
                "CSP blocks execution",
                "Self-XSS only (no other users affected)"
            ],
            high_value_indicators=[
                "Executes for all users",
                "Stored in admin panel",
                "Can steal session tokens",
                "Bypasses CSP",
                "Affects authentication flow"
            ],
            avg_bounty_range="$500-$3000",
            cvss_range="6.0-8.0"
        )

        patterns['sqli'] = VulnerabilityPattern(
            name="SQL Injection",
            category=VulnCategory.MEDIUM_VALUE,
            testing_priority=7,
            common_locations=[
                "Search functions",
                "Login forms (username parameter)",
                "Sorting/filtering parameters (ORDER BY)",
                "API endpoints with database queries",
                "Admin panels",
                "Report generation",
                "Data export functions"
            ],
            detection_techniques=[
                "SQLMap (king of SQLi)",
                "Time-based blind detection",
                "Error-based detection",
                "Boolean-based blind",
                "Union-based injection",
                "Tamper scripts for WAF bypass"
            ],
            polyglot_payloads=[
                # Mathias Karlsson's polyglot
                "SLEEP(1) /*' or SLEEP(1) or '\" or SLEEP(1) or \"*/",
                "'+BENCHMARK(40000000,SHA1(1337))+'",
                "' OR '1'='1",
                "1' AND SLEEP(5)--",
                "' UNION SELECT NULL--",
            ],
            false_positive_indicators=[
                "Prepared statements used",
                "Parameterized queries",
                "No database errors returned"
            ],
            high_value_indicators=[
                "Full database extraction",
                "Authentication bypass",
                "RCE via xp_cmdshell (MSSQL)",
                "Read/write files",
                "Time-based works (confirms DB interaction)"
            ],
            avg_bounty_range="$300-$5000",
            cvss_range="7.0-9.0"
        )

        # === COMMON (Often reported but lower value) ===

        patterns['xss_reflected'] = VulnerabilityPattern(
            name="Cross-Site Scripting (Reflected)",
            category=VulnCategory.COMMON_LOW_NOISE,
            testing_priority=5,
            common_locations=[
                "Search parameters",
                "Error messages",
                "URL parameters reflected in page",
                "Fake parameters (?foo=)",
                "Referer header",
                "User-Agent header"
            ],
            detection_techniques=[
                "Same as stored XSS",
                "Focus on user interaction required",
                "Check if URL can be social engineered"
            ],
            polyglot_payloads=[
                # Same as stored XSS
            ],
            false_positive_indicators=[
                "Requires user interaction (lower severity)",
                "No sensitive actions possible",
                "Self-XSS equivalent"
            ],
            high_value_indicators=[
                "Can be chained with CSRF",
                "Targets admin users",
                "Bypasses anti-CSRF tokens",
                "DOM-based (harder to fix)"
            ],
            avg_bounty_range="$100-$1000",
            cvss_range="4.0-6.5"
        )

        patterns['info_disclosure'] = VulnerabilityPattern(
            name="Information Disclosure",
            category=VulnCategory.COMMON_LOW_NOISE,
            testing_priority=4,
            common_locations=[
                "API responses with extra data",
                "Source code comments",
                "Stack traces",
                ".git directory exposure",
                "Backup files (.bak, .old)",
                "Directory listings",
                "Verbose error messages"
            ],
            detection_techniques=[
                "Check response for PII",
                "Look for internal IPs",
                "Search for API keys in source",
                "Test for path traversal to config files"
            ],
            polyglot_payloads=[
                "/../../../etc/passwd",
                "/.git/config",
                "/backup.sql",
                "/.env"
            ],
            false_positive_indicators=[
                "Public information only",
                "No sensitive data exposed",
                "Already documented behavior"
            ],
            high_value_indicators=[
                "PII of other users",
                "API keys/credentials",
                "Internal system details",
                "Can be chained for further exploitation"
            ],
            avg_bounty_range="$50-$500",
            cvss_range="3.0-6.0"
        )

        return patterns

    def _load_noise_filters(self) -> Dict[str, List[str]]:
        """
        Patterns that indicate low-value noise

        Research: High-impact programs focus on fewer, skilled researchers
        Noise reduction is critical for success
        """
        return {
            'self_xss': [
                "Only affects user who inputs payload",
                "No other users can trigger",
                "Requires victim to paste malicious code",
                "Browser console warnings"
            ],
            'no_impact_info_disclosure': [
                "Public information",
                "Already documented",
                "No sensitive data",
                "Common behavior"
            ],
            'minor_ui_issues': [
                "Cosmetic issues",
                "UI rendering bugs",
                "Missing alt text (unless accessibility program)",
                "Typos in error messages"
            ],
            'known_issues': [
                "Already reported",
                "In program's known issues list",
                "Duplicate of existing finding"
            ],
            'out_of_scope': [
                "Testing forbidden attack types",
                "Targeting out-of-scope assets",
                "Violating program rules"
            ]
        }

    def _load_high_value_contexts(self) -> Dict[str, List[str]]:
        """
        Contexts where vulnerabilities are higher value

        Research: Context matters more than vulnerability type
        """
        return {
            'admin_panels': [
                "Admin-only functionality",
                "User management",
                "System configuration",
                "Elevated privileges"
            ],
            'authentication_flows': [
                "Login/logout",
                "Password reset",
                "2FA",
                "OAuth flows",
                "SSO"
            ],
            'payment_processing': [
                "Checkout",
                "Billing",
                "Invoices",
                "Subscriptions",
                "Refunds"
            ],
            'pii_access': [
                "User profiles",
                "Personal information",
                "Financial data",
                "Health records",
                "Private messages"
            ],
            'api_endpoints': [
                "REST/GraphQL APIs",
                "Internal APIs",
                "Mobile app APIs",
                "Undocumented endpoints"
            ]
        }

    def prioritize_target(self, target_url: str, context: Optional[str] = None) -> Dict:
        """
        Prioritize testing based on target and context

        Args:
            target_url: URL to test
            context: Optional context (admin, api, payment, etc.)

        Returns:
            Dict with testing priorities and recommended focus areas
        """
        priorities = {
            'high_priority_vulns': [],
            'medium_priority_vulns': [],
            'avoid_noise': [],
            'testing_recommendations': []
        }

        # Analyze URL patterns
        url_lower = target_url.lower()

        # High-value contexts
        if any(ctx in url_lower for ctx in ['admin', 'manage', 'dashboard']):
            priorities['high_priority_vulns'].extend([
                'privilege_escalation',
                'idor',
                'xss_stored'
            ])
            priorities['testing_recommendations'].append(
                "ADMIN PANEL: Focus on privilege escalation and IDOR. "
                "Test with different user roles."
            )

        if any(ctx in url_lower for ctx in ['api', '/v1/', '/v2/', 'graphql']):
            priorities['high_priority_vulns'].extend([
                'idor',
                'ssrf',
                'sqli'
            ])
            priorities['testing_recommendations'].append(
                "API ENDPOINT: Test for IDOR in all parameters. "
                "Check for SSRF in URL/callback parameters."
            )

        if any(ctx in url_lower for ctx in ['payment', 'checkout', 'billing', 'subscribe']):
            priorities['high_priority_vulns'].extend([
                'idor',
                'privilege_escalation',
                'sqli'
            ])
            priorities['testing_recommendations'].append(
                "PAYMENT FLOW: Critical area. Test for price manipulation, "
                "subscription bypasses, and access control."
            )

        if any(ctx in url_lower for ctx in ['webhook', 'callback', 'import', 'fetch']):
            priorities['high_priority_vulns'].append('ssrf')
            priorities['testing_recommendations'].append(
                "WEBHOOK/CALLBACK: High SSRF potential. Test with Burp Collaborator."
            )

        # Avoid noise
        if 'search' in url_lower and 'q=' in url_lower:
            priorities['avoid_noise'].append(
                "Search parameter: Likely reflected XSS (low value unless admin panel)"
            )

        return priorities

    def get_testing_checklist(self, vulnerability_type: str) -> Dict:
        """
        Get comprehensive testing checklist for a vulnerability type

        Returns methodology from Jason Haddix's TBHM and academic research
        """
        pattern = self.vulnerability_patterns.get(vulnerability_type)

        if not pattern:
            return {"error": f"Unknown vulnerability type: {vulnerability_type}"}

        return {
            'vulnerability': pattern.name,
            'priority': pattern.testing_priority,
            'expected_bounty': pattern.avg_bounty_range,
            'cvss_range': pattern.cvss_range,
            'where_to_look': pattern.common_locations,
            'how_to_test': pattern.detection_techniques,
            'payloads': pattern.polyglot_payloads,
            'false_positives': pattern.false_positive_indicators,
            'high_value_signs': pattern.high_value_indicators
        }


# CLI interface for testing
def main():
    """Demo the intelligence system"""
    intel = BugBountyIntelligence()

    # Example: Prioritize an admin API endpoint
    result = intel.prioritize_target("https://example.com/api/admin/users/123")

    print("Bug Bounty Intelligence Analysis")
    print("=" * 60)
    print(f"\nHigh Priority Vulnerabilities:")
    for vuln in result['high_priority_vulns']:
        print(f"  - {vuln}")

    print(f"\nTesting Recommendations:")
    for rec in result['testing_recommendations']:
        print(f"  • {rec}")

    print("\n" + "=" * 60)

    # Show SSRF testing guide
    print("\nSSRF Testing Checklist:")
    checklist = intel.get_testing_checklist('ssrf')
    print(f"Priority: {checklist['priority']}/10")
    print(f"Expected Bounty: {checklist['expected_bounty']}")
    print(f"\nWhere to look:")
    for loc in checklist['where_to_look'][:3]:
        print(f"  • {loc}")


if __name__ == "__main__":
    main()
