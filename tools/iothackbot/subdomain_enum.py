#!/usr/bin/env python3
"""
Subdomain Enumeration Tool - CLI Interface
Multi-source subdomain discovery for bug bounty hunting
"""

import argparse
from colorama import init, Fore, Style
from .core.subdomain_core import SubdomainEnumTool
from .core.interfaces import ConfigBuilder, OutputFormatter, ToolResult


class SubdomainOutputFormatter(OutputFormatter):
    """Custom output formatter for subdomain enumeration"""

    def _format_text(self, result: ToolResult) -> str:
        """Format subdomain results as human-readable text"""
        if not result.success:
            return f"{Fore.RED}Subdomain Enumeration Failed:{Style.RESET_ALL}\n" + "\n".join(result.errors)

        if not result.data:
            return "No enumeration data available."

        data = result.data
        lines = []

        lines.append(f"\n{Fore.BLUE}╔══════════════════════════════════════════════════════════════╗{Style.RESET_ALL}")
        lines.append(f"{Fore.BLUE}║{Style.RESET_ALL}          {Fore.CYAN}SUBDOMAIN ENUMERATION RESULTS{Style.RESET_ALL}                    {Fore.BLUE}║{Style.RESET_ALL}")
        lines.append(f"{Fore.BLUE}╚══════════════════════════════════════════════════════════════╝{Style.RESET_ALL}\n")

        lines.append(f"{Fore.CYAN}Target Domain:{Style.RESET_ALL} {data['domain']}")
        lines.append(f"{Fore.GREEN}Total Subdomains Found:{Style.RESET_ALL} {data['total_subdomains']}")

        if data.get('active_recon'):
            lines.append(f"{Fore.YELLOW}Reconnaissance Mode:{Style.RESET_ALL} Active")
        else:
            lines.append(f"{Fore.CYAN}Reconnaissance Mode:{Style.RESET_ALL} Passive")

        lines.append(f"\n{Fore.BLUE}Sources Used:{Style.RESET_ALL}")
        for source, count in data.get('sources', {}).items():
            lines.append(f"  {Fore.GREEN}•{Style.RESET_ALL} {source}: {count} subdomains")

        lines.append(f"\n{Fore.BLUE}Discovered Subdomains:{Style.RESET_ALL}")
        lines.append("=" * 60)

        for idx, subdomain in enumerate(data.get('subdomains', []), 1):
            lines.append(f"{Fore.CYAN}{idx:4d}.{Style.RESET_ALL} {subdomain}")

        lines.append(f"\n{Fore.GREEN}✓ Enumeration complete!{Style.RESET_ALL}")

        return "\n".join(lines)


def subdomain_enum():
    """Main CLI entry point for subdomain enumeration"""
    parser = argparse.ArgumentParser(
        description="Multi-Source Subdomain Enumeration Tool",
        epilog="Example: subdomain-enum target.com -o subdomains.txt"
    )
    parser.add_argument(
        "domain",
        help="Target domain to enumerate"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output file for subdomain list"
    )
    parser.add_argument(
        "--no-subfinder",
        action="store_true",
        help="Disable subfinder"
    )
    parser.add_argument(
        "--no-amass",
        action="store_true",
        help="Disable amass"
    )
    parser.add_argument(
        "--no-assetfinder",
        action="store_true",
        help="Disable assetfinder"
    )
    parser.add_argument(
        "--no-crtsh",
        action="store_true",
        help="Disable crt.sh queries"
    )
    parser.add_argument(
        "--active",
        action="store_true",
        help="Enable active reconnaissance (amass active mode)"
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output"
    )
    parser.add_argument(
        "--format",
        choices=['text', 'json', 'quiet'],
        default='text',
        help="Output format (default: text)"
    )

    args = parser.parse_args()
    init()  # Initialize colorama

    # Build configuration
    config = ConfigBuilder.from_args(args, 'subdomain_enum')
    config.custom_args['use_subfinder'] = not args.no_subfinder
    config.custom_args['use_amass'] = not args.no_amass
    config.custom_args['use_assetfinder'] = not args.no_assetfinder
    config.custom_args['use_crtsh'] = not args.no_crtsh
    config.custom_args['active_recon'] = args.active

    # Execute tool
    tool = SubdomainEnumTool()
    result = tool.run(config)

    # Format and output result
    formatter = SubdomainOutputFormatter()
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    # Write to file if specified
    if args.output and result.success:
        with open(args.output, 'w') as f:
            f.write('\n'.join(result.data.get('subdomains', [])))
        print(f"\n{Fore.GREEN}✓ Subdomains written to {args.output}{Style.RESET_ALL}")

    # Exit with appropriate code
    return 0 if result.success else 1


if __name__ == "__main__":
    import sys
    sys.exit(subdomain_enum())
