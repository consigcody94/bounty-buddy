"""
XSS Scanner - Dalfox Integration

Advanced XSS vulnerability scanner with scope validation and severity rating.
"""

import json
import re
from typing import List

from ..core.tool_wrapper import ExternalToolWrapper, VulnerabilityFinding, VulnerabilitySeverity


class DalfoxScanner(ExternalToolWrapper):
    """
    Dalfox XSS Scanner Wrapper

    Dalfox is a powerful XSS scanning tool that:
    - Tests GET/POST parameters
    - Finds reflected parameters
    - Tests various XSS contexts
    - Bypasses WAF filters
    """

    def tool_name(self) -> str:
        return "dalfox-xss-scanner"

    def attack_type(self) -> str:
        return "xss"

    def get_command(self, target: str, **kwargs) -> List[str]:
        """Build dalfox command"""
        cmd = ['dalfox', 'url', target]

        # Output format
        cmd.extend(['--format', 'json'])

        # Additional options
        if kwargs.get('blind', False):
            cmd.append('--blind')

        if kwargs.get('worker', 100):
            cmd.extend(['--worker', str(kwargs['worker'])])

        if kwargs.get('silence', False):
            cmd.append('--silence')

        return cmd

    def parse_output(self, stdout: str, stderr: str) -> List[VulnerabilityFinding]:
        """Parse dalfox JSON output"""
        findings = []

        try:
            # Dalfox outputs JSON
            results = json.loads(stdout) if stdout.strip() else []

            for result in results:
                finding = VulnerabilityFinding(
                    title=f"Cross-Site Scripting (XSS) - {result.get('type', 'Reflected')}",
                    description=(
                        f"XSS vulnerability found in parameter '{result.get('param', 'unknown')}'. "
                        f"The application reflects user input without proper sanitization, "
                        f"allowing execution of arbitrary JavaScript code."
                    ),
                    severity=VulnerabilitySeverity.HIGH,  # Default severity
                    target=result.get('url', 'unknown'),
                    vulnerability_type='xss',
                    proof_of_concept=result.get('poc', ''),
                    request=result.get('data', ''),
                    confidence=result.get('confidence', 'medium'),
                    tool='dalfox'
                )

                # Adjust severity based on context
                if 'dom' in result.get('type', '').lower():
                    finding.severity = VulnerabilitySeverity.HIGH
                elif 'stored' in result.get('type', '').lower():
                    finding.severity = VulnerabilitySeverity.CRITICAL
                else:
                    finding.severity = VulnerabilitySeverity.MEDIUM

                findings.append(finding)

        except json.JSONDecodeError:
            # Fallback: parse text output
            xss_pattern = r'Found XSS.*?URL:\s*(\S+).*?Param:\s*(\S+)'
            matches = re.findall(xss_pattern, stdout, re.DOTALL)

            for url, param in matches:
                finding = VulnerabilityFinding(
                    title=f"Cross-Site Scripting (XSS) in parameter '{param}'",
                    description="Potential XSS vulnerability detected",
                    severity=VulnerabilitySeverity.MEDIUM,
                    target=url,
                    vulnerability_type='xss',
                    proof_of_concept=f"Parameter '{param}' is vulnerable",
                    tool='dalfox'
                )
                findings.append(finding)

        return findings


# CLI interface
def main():
    """CLI entry point"""
    import argparse
    from ..core.scope import ScopeManager

    parser = argparse.ArgumentParser(description='XSS Scanner with scope validation')
    parser.add_argument('url', help='Target URL to scan')
    parser.add_argument('--scope', help='Load scope configuration')
    parser.add_argument('--blind', action='store_true', help='Enable blind XSS testing')
    parser.add_argument('--worker', type=int, default=100, help='Number of workers')
    parser.add_argument('-o', '--output', help='Output file for results (JSON)')

    args = parser.parse_args()

    # Load scope if provided
    scope_manager = ScopeManager()
    if args.scope:
        scope_manager.load_scope(args.scope)

    # Run scanner
    scanner = DalfoxScanner(scope_manager=scope_manager)
    success, findings, message = scanner.execute(
        args.url,
        blind=args.blind,
        worker=args.worker
    )

    # Output results
    print(f"\n{message}")
    print(f"Found {len(findings)} potential XSS vulnerabilities\n")

    for idx, finding in enumerate(findings, 1):
        print(f"{idx}. {finding.title}")
        print(f"   Severity: {finding.severity.value.upper()} ({finding.bugcrowd_priority or 'N/A'})")
        print(f"   Target: {finding.target}")
        print(f"   CWE: {finding.cwe_id or 'N/A'}")
        print()

    # Save to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump([finding.__dict__ for finding in findings], f, indent=2, default=str)
        print(f"Results saved to {args.output}")


if __name__ == "__main__":
    main()
