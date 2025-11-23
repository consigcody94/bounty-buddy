"""
Core subdomain enumeration functionality
Multi-source subdomain discovery and validation
"""

import subprocess
import json
import requests
import time
from typing import List, Dict, Any, Set
from .interfaces import ToolInterface, ToolConfig, ToolResult


def run_subfinder(domain: str) -> Set[str]:
    """Run subfinder for subdomain enumeration"""
    try:
        cmd = ['subfinder', '-d', domain, '-silent']
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            return set(result.stdout.strip().split('\n'))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return set()


def run_amass(domain: str, active: bool = False) -> Set[str]:
    """Run amass for subdomain enumeration"""
    try:
        cmd = ['amass', 'enum']
        if not active:
            cmd.append('-passive')
        cmd.extend(['-d', domain])

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        if result.returncode == 0:
            return set(result.stdout.strip().split('\n'))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return set()


def run_assetfinder(domain: str) -> Set[str]:
    """Run assetfinder for subdomain enumeration"""
    try:
        cmd = ['assetfinder', '--subs-only', domain]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        if result.returncode == 0:
            return set(result.stdout.strip().split('\n'))
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return set()


def query_crtsh(domain: str) -> Set[str]:
    """Query crt.sh for certificate transparency logs"""
    subdomains = set()
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        response = requests.get(url, timeout=30)

        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value', '')
                for subdomain in name_value.split('\n'):
                    subdomain = subdomain.strip()
                    if subdomain and subdomain.endswith(domain):
                        # Remove wildcards
                        if subdomain.startswith('*.'):
                            subdomain = subdomain[2:]
                        subdomains.add(subdomain)
    except Exception:
        pass
    return subdomains


def enumerate_subdomains(
    domain: str,
    use_subfinder: bool = True,
    use_amass: bool = True,
    use_assetfinder: bool = True,
    use_crtsh: bool = True,
    active_recon: bool = False
) -> Dict[str, Any]:
    """
    Enumerate subdomains using multiple sources.

    Args:
        domain: Target domain
        use_subfinder: Use subfinder tool
        use_amass: Use amass tool
        use_assetfinder: Use assetfinder tool
        use_crtsh: Query crt.sh
        active_recon: Enable active reconnaissance (amass active mode)

    Returns:
        Dictionary with enumeration results
    """
    all_subdomains = set()
    sources = {}

    # Subfinder
    if use_subfinder:
        subs = run_subfinder(domain)
        if subs and '' not in subs:
            sources['subfinder'] = len(subs)
            all_subdomains.update(subs)

    # Amass
    if use_amass:
        subs = run_amass(domain, active=active_recon)
        if subs and '' not in subs:
            sources['amass'] = len(subs)
            all_subdomains.update(subs)

    # Assetfinder
    if use_assetfinder:
        subs = run_assetfinder(domain)
        if subs and '' not in subs:
            sources['assetfinder'] = len(subs)
            all_subdomains.update(subs)

    # crt.sh
    if use_crtsh:
        subs = query_crtsh(domain)
        if subs:
            sources['crtsh'] = len(subs)
            all_subdomains.update(subs)

    # Remove empty strings and clean up
    all_subdomains.discard('')
    all_subdomains = {s.strip().lower() for s in all_subdomains if s and s.strip()}

    return {
        'domain': domain,
        'total_subdomains': len(all_subdomains),
        'subdomains': sorted(list(all_subdomains)),
        'sources': sources,
        'active_recon': active_recon
    }


class SubdomainEnumTool(ToolInterface):
    """Subdomain enumeration tool"""

    @property
    def name(self) -> str:
        return "subdomain_enum"

    @property
    def description(self) -> str:
        return "Multi-source subdomain enumeration and discovery"

    def run(self, config: ToolConfig) -> ToolResult:
        """Execute subdomain enumeration"""
        start_time = time.time()

        try:
            domain = config.input_path

            # Get configuration
            use_subfinder = config.custom_args.get('use_subfinder', True)
            use_amass = config.custom_args.get('use_amass', True)
            use_assetfinder = config.custom_args.get('use_assetfinder', True)
            use_crtsh = config.custom_args.get('use_crtsh', True)
            active_recon = config.custom_args.get('active_recon', False)

            # Run enumeration
            result_data = enumerate_subdomains(
                domain,
                use_subfinder=use_subfinder,
                use_amass=use_amass,
                use_assetfinder=use_assetfinder,
                use_crtsh=use_crtsh,
                active_recon=active_recon
            )

            execution_time = time.time() - start_time

            return ToolResult(
                success=True,
                data=result_data,
                metadata={
                    'domain': domain,
                    'total_subdomains': result_data['total_subdomains'],
                    'sources_used': list(result_data['sources'].keys())
                },
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                errors=[str(e)],
                metadata={'domain': config.input_path},
                execution_time=execution_time
            )
