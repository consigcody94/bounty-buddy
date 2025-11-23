#!/usr/bin/env python3
"""
MQTT Scanner - Command Line Interface
MQTT broker discovery and security testing
"""

import argparse
from colorama import init, Fore, Style
from .core.mqttscan_core import MQTTScanTool
from .core.interfaces import ConfigBuilder, OutputFormatter, ToolResult


class MQTTScanOutputFormatter(OutputFormatter):
    """Custom output formatter for MQTT scan results"""

    def _format_text(self, result: ToolResult) -> str:
        """Format MQTT scan results as human-readable text"""
        if not result.success:
            return f"{Fore.RED}MQTT Scan Failed:{Style.RESET_ALL}\n" + "\n".join(result.errors)

        if not result.data:
            return "No scan data available."

        data = result.data
        lines = []

        # Single host result
        if 'host' in data:
            lines.append(f"\n{Fore.BLUE}MQTT BROKER SCAN RESULTS{Style.RESET_ALL}")
            lines.append("=" * 60)
            lines.append(f"{Fore.CYAN}Target:{Style.RESET_ALL} {data['host']}:{data['port']}")

            if not data['reachable']:
                lines.append(f"{Fore.YELLOW}Status:{Style.RESET_ALL} Host unreachable")
                if data.get('error'):
                    lines.append(f"{Fore.RED}Error:{Style.RESET_ALL} {data['error']}")
            elif not data['mqtt_service']:
                lines.append(f"{Fore.YELLOW}Status:{Style.RESET_ALL} No MQTT service detected")
            else:
                lines.append(f"{Fore.GREEN}Status:{Style.RESET_ALL} MQTT broker found")

                if 'latency' in data:
                    lines.append(f"{Fore.CYAN}Latency:{Style.RESET_ALL} {data['latency']*1000:.2f}ms")

                # Authentication status
                if not data.get('auth_required'):
                    lines.append(
                        f"{Fore.RED}Authentication:{Style.RESET_ALL} "
                        f"NOT REQUIRED (SECURITY ISSUE)"
                    )
                    if data.get('security_issue'):
                        lines.append(f"{Fore.RED}  {data['security_issue']}{Style.RESET_ALL}")
                else:
                    lines.append(f"{Fore.GREEN}Authentication:{Style.RESET_ALL} Required")

                if data.get('return_message'):
                    lines.append(f"{Fore.CYAN}Response:{Style.RESET_ALL} {data['return_message']}")

                if data.get('found_credentials'):
                    creds = data['found_credentials']
                    lines.append(
                        f"{Fore.RED}Found Credentials:{Style.RESET_ALL} "
                        f"{creds['username']}:{creds['password']}"
                    )

        # Network scan results
        elif 'brokers_found' in data:
            lines.append(f"\n{Fore.BLUE}MQTT NETWORK SCAN RESULTS{Style.RESET_ALL}")
            lines.append("=" * 60)
            lines.append(f"{Fore.CYAN}Hosts Scanned:{Style.RESET_ALL} {data['total_hosts_scanned']}")
            lines.append(f"{Fore.GREEN}Brokers Found:{Style.RESET_ALL} {data['brokers_found']}")

            if data['anonymous_access_count'] > 0:
                lines.append(
                    f"{Fore.RED}Anonymous Access:{Style.RESET_ALL} "
                    f"{data['anonymous_access_count']} hosts"
                )
                for host in data['anonymous_access_hosts']:
                    lines.append(f"  {Fore.RED}• {host}{Style.RESET_ALL}")

            lines.append(f"\n{Fore.BLUE}Detailed Results:{Style.RESET_ALL}")
            for broker in data['results']:
                lines.append(f"\n{Fore.CYAN}Host: {broker['host']}{Style.RESET_ALL}")
                lines.append(f"  Port: {broker['port']}")
                lines.append(f"  Auth Required: {'Yes' if broker.get('auth_required') else 'No'}")
                if broker.get('return_message'):
                    lines.append(f"  Response: {broker['return_message']}")

        return "\n".join(lines)


def mqttscan():
    """Main CLI entry point for MQTT scanner"""
    parser = argparse.ArgumentParser(
        description="MQTT Broker Discovery and Security Testing",
        epilog="Example: mqttscan 192.168.1.100"
    )
    parser.add_argument(
        "target",
        help="Target hostname, IP address, or CIDR range"
    )
    parser.add_argument(
        "-p", "--port",
        type=int,
        default=1883,
        help="MQTT port (default: 1883)"
    )
    parser.add_argument(
        "--timeout",
        type=float,
        default=5.0,
        help="Connection timeout in seconds (default: 5.0)"
    )
    parser.add_argument(
        "--no-auth-test",
        action="store_true",
        help="Disable authentication testing"
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
    config = ConfigBuilder.from_args(args, 'mqttscan')
    config.custom_args['port'] = args.port
    config.custom_args['test_auth'] = not args.no_auth_test

    # Execute tool
    tool = MQTTScanTool()
    result = tool.run(config)

    # Format and output result
    formatter = MQTTScanOutputFormatter()
    output = formatter.format_result(result, config.output_format)
    if output:
        print(output)

    # Exit with appropriate code
    return 0 if result.success else 1


if __name__ == "__main__":
    import sys
    sys.exit(mqttscan())
