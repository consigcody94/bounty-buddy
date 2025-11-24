#!/usr/bin/env python3
"""
Bounty Buddy - Dependency Checker and Installer

Checks for required external tools and offers to install missing ones.
"""

import os
import subprocess
import sys
import platform
from dataclasses import dataclass
from typing import List, Optional


@dataclass
class Dependency:
    """External tool dependency"""
    name: str
    command: str  # Command to check if installed
    install_cmd: dict  # Platform-specific install commands
    category: str
    description: str
    required: bool = False  # If False, tool is optional


# Complete list of external dependencies
DEPENDENCIES = [
    # === WEB APPLICATION TESTING ===
    Dependency(
        name="dalfox",
        command="dalfox version",
        install_cmd={
            "linux": "go install github.com/hahwul/dalfox/v2@latest",
            "darwin": "brew install dalfox",
        },
        category="Web Security",
        description="Advanced XSS scanner"
    ),
    Dependency(
        name="sqlmap",
        command="sqlmap --version",
        install_cmd={
            "linux": "sudo apt-get install -y sqlmap || pip3 install sqlmap",
            "darwin": "brew install sqlmap",
        },
        category="Web Security",
        description="SQL injection scanner"
    ),
    Dependency(
        name="nuclei",
        command="nuclei -version",
        install_cmd={
            "linux": "go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
            "darwin": "brew install nuclei",
        },
        category="Web Security",
        description="Template-based vulnerability scanner",
        required=True
    ),
    Dependency(
        name="ffuf",
        command="ffuf -V",
        install_cmd={
            "linux": "go install github.com/ffuf/ffuf@latest",
            "darwin": "brew install ffuf",
        },
        category="Web Security",
        description="Fast web fuzzer"
    ),
    Dependency(
        name="httpx",
        command="httpx -version",
        install_cmd={
            "linux": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
            "darwin": "brew install httpx",
        },
        category="Web Security",
        description="HTTP toolkit"
    ),

    # === SUBDOMAIN ENUMERATION ===
    Dependency(
        name="subfinder",
        command="subfinder -version",
        install_cmd={
            "linux": "go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest",
            "darwin": "brew install subfinder",
        },
        category="Reconnaissance",
        description="Subdomain discovery tool",
        required=True
    ),
    Dependency(
        name="amass",
        command="amass -version",
        install_cmd={
            "linux": "go install -v github.com/owasp-amass/amass/v4/...@master",
            "darwin": "brew install amass",
        },
        category="Reconnaissance",
        description="In-depth DNS enumeration"
    ),
    Dependency(
        name="assetfinder",
        command="assetfinder --help",
        install_cmd={
            "linux": "go install github.com/tomnomnom/assetfinder@latest",
            "darwin": "brew install assetfinder",
        },
        category="Reconnaissance",
        description="Find related domains and subdomains"
    ),

    # === CLOUD SECURITY ===
    Dependency(
        name="subjack",
        command="subjack -h",
        install_cmd={
            "linux": "go install github.com/haccer/subjack@latest",
            "darwin": "go install github.com/haccer/subjack@latest",
        },
        category="Cloud Security",
        description="Subdomain takeover scanner"
    ),
    Dependency(
        name="s3scanner",
        command="s3scanner --version",
        install_cmd={
            "linux": "pip3 install s3scanner",
            "darwin": "pip3 install s3scanner",
        },
        category="Cloud Security",
        description="S3 bucket enumeration"
    ),

    # === MOBILE SECURITY ===
    Dependency(
        name="apktool",
        command="apktool --version",
        install_cmd={
            "linux": "sudo apt-get install -y apktool",
            "darwin": "brew install apktool",
        },
        category="Mobile Security",
        description="APK decompiler"
    ),
    Dependency(
        name="jadx",
        command="jadx --version",
        install_cmd={
            "linux": "sudo apt-get install -y jadx",
            "darwin": "brew install jadx",
        },
        category="Mobile Security",
        description="Dex to Java decompiler"
    ),

    # === NETWORK & UTILITIES ===
    Dependency(
        name="nmap",
        command="nmap --version",
        install_cmd={
            "linux": "sudo apt-get install -y nmap",
            "darwin": "brew install nmap",
        },
        category="Network Security",
        description="Network scanner",
        required=True
    ),
    Dependency(
        name="masscan",
        command="masscan --version",
        install_cmd={
            "linux": "sudo apt-get install -y masscan",
            "darwin": "brew install masscan",
        },
        category="Network Security",
        description="Fast port scanner"
    ),
    Dependency(
        name="testssl.sh",
        command="testssl.sh --version",
        install_cmd={
            "linux": "git clone --depth 1 https://github.com/drwetter/testssl.sh.git ~/testssl && sudo ln -s ~/testssl/testssl.sh /usr/local/bin/testssl.sh",
            "darwin": "brew install testssl",
        },
        category="SSL/TLS",
        description="SSL/TLS scanner"
    ),

    # === GOLANG (required for many tools) ===
    Dependency(
        name="go",
        command="go version",
        install_cmd={
            "linux": "wget https://go.dev/dl/go1.21.0.linux-amd64.tar.gz && sudo tar -C /usr/local -xzf go1.21.0.linux-amd64.tar.gz && echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc",
            "darwin": "brew install go",
        },
        category="Prerequisites",
        description="Go programming language",
        required=True
    ),
]


def check_command_exists(command: str) -> bool:
    """Check if a command exists in PATH"""
    try:
        result = subprocess.run(
            command.split()[0:2],  # Run just the command, not full args
            capture_output=True,
            timeout=5
        )
        return True
    except (subprocess.TimeoutExpired, FileNotFoundError, subprocess.CalledProcessError):
        return False


def get_platform() -> str:
    """Get current platform"""
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "darwin":
        return "darwin"
    else:
        return "unsupported"


def install_dependency(dep: Dependency, platform_name: str) -> bool:
    """Install a dependency"""
    install_cmd = dep.install_cmd.get(platform_name)

    if not install_cmd:
        print(f"  ⚠️  No installation command for {platform_name}")
        return False

    print(f"  📥 Installing {dep.name}...")
    print(f"     Running: {install_cmd}")

    try:
        result = subprocess.run(
            install_cmd,
            shell=True,
            capture_output=True,
            text=True,
            timeout=300  # 5 min timeout
        )

        if result.returncode == 0:
            print(f"  ✅ {dep.name} installed successfully")
            return True
        else:
            print(f"  ❌ Installation failed: {result.stderr}")
            return False

    except subprocess.TimeoutExpired:
        print(f"  ❌ Installation timeout")
        return False
    except Exception as e:
        print(f"  ❌ Installation error: {str(e)}")
        return False


def main():
    """Main dependency checker"""
    print("="*70)
    print("🔍 Bounty Buddy - Dependency Checker")
    print("="*70)
    print()

    platform_name = get_platform()
    if platform_name == "unsupported":
        print("❌ Unsupported platform. This script supports Linux and macOS only.")
        sys.exit(1)

    print(f"Platform: {platform_name}")
    print()

    # Check all dependencies
    missing = []
    installed = []
    optional_missing = []

    for dep in DEPENDENCIES:
        exists = check_command_exists(dep.command)

        if exists:
            installed.append(dep)
        else:
            if dep.required:
                missing.append(dep)
            else:
                optional_missing.append(dep)

    # Report
    print(f"✅ Installed tools: {len(installed)}")
    print(f"❌ Missing required tools: {len(missing)}")
    print(f"⚠️  Missing optional tools: {len(optional_missing)}")
    print()

    if installed:
        print("=" * 70)
        print("✅ INSTALLED TOOLS")
        print("=" * 70)
        for dep in installed:
            print(f"  ✓ {dep.name:20s} - {dep.description}")
        print()

    if missing:
        print("=" * 70)
        print("❌ MISSING REQUIRED TOOLS")
        print("=" * 70)
        for dep in missing:
            print(f"  ✗ {dep.name:20s} - {dep.description}")
        print()

        # Offer to install
        response = input("Install missing required tools? (y/N): ").strip().lower()
        if response == 'y':
            print()
            for dep in missing:
                install_dependency(dep, platform_name)
            print()

    if optional_missing:
        print("=" * 70)
        print("⚠️  MISSING OPTIONAL TOOLS")
        print("=" * 70)
        for dep in optional_missing:
            print(f"  ○ {dep.name:20s} - {dep.description}")
        print()

        response = input("Install optional tools? (y/N): ").strip().lower()
        if response == 'y':
            print()
            for dep in optional_missing:
                install_dependency(dep, platform_name)
            print()

    # Summary
    print("=" * 70)
    print("📋 INSTALLATION SUMMARY")
    print("=" * 70)
    print()
    print("To manually install any tool, use:")
    print()
    for dep in DEPENDENCIES[:5]:  # Show first 5 as examples
        install_cmd = dep.install_cmd.get(platform_name, "N/A")
        print(f"  {dep.name}:")
        print(f"    {install_cmd}")
        print()

    print("For complete installation guide, see: INSTALL.md")
    print()


if __name__ == "__main__":
    main()
