"""
Scope Management System for Bug Bounty Programs

Handles:
- Interactive scope intake (platform, targets, rules)
- Scope validation before tool execution
- Multi-platform support (HackerOne, Bugcrowd, Intigriti, YesWeHack, Custom)
- Persistent scope storage

SPDX-License-Identifier: MIT
"""

from __future__ import annotations

import json
import logging
import os
import re
from dataclasses import dataclass, field, asdict
from datetime import datetime
from ipaddress import ip_address, ip_network, AddressValueError, NetmaskValueError
from pathlib import Path
from typing import List, Dict, Optional, Set, Any, Tuple, Callable
from enum import Enum

logger = logging.getLogger(__name__)


class BugBountyPlatform(Enum):
    """Supported bug bounty platforms"""
    HACKERONE = "hackerone"
    BUGCROWD = "bugcrowd"
    INTIGRITI = "intigriti"
    YESWEHACK = "yeswehack"
    CUSTOM = "custom"
    OTHER = "other"


class AssetType(Enum):
    """Types of assets in scope"""
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    IP_RANGE = "ip_range"
    MOBILE_APP = "mobile_app"
    API_ENDPOINT = "api_endpoint"
    SOURCE_CODE = "source_code"
    HARDWARE = "hardware"
    OTHER = "other"


@dataclass
class ScopeAsset:
    """Represents an in-scope or out-of-scope asset"""
    value: str
    asset_type: AssetType
    description: str = ""
    notes: str = ""

    def matches(self, target: str) -> bool:
        """Check if a target matches this scope asset"""
        if self.asset_type == AssetType.DOMAIN:
            # Exact domain match or subdomain
            return target == self.value or target.endswith(f".{self.value}")

        elif self.asset_type == AssetType.SUBDOMAIN:
            # Wildcard subdomain matching
            pattern = self.value.replace("*", ".*")
            return bool(re.match(f"^{pattern}$", target))

        elif self.asset_type == AssetType.IP_ADDRESS:
            return target == self.value

        elif self.asset_type == AssetType.IP_RANGE:
            # Simple CIDR or range matching
            return self._ip_in_range(target, self.value)

        elif self.asset_type == AssetType.API_ENDPOINT:
            # URL prefix matching
            return target.startswith(self.value)

        else:
            # Default: exact match
            return target == self.value

    @staticmethod
    def _ip_in_range(ip_str: str, ip_range: str) -> bool:
        """
        Check if IP is in range using proper CIDR matching.

        Args:
            ip_str: The IP address to check
            ip_range: CIDR notation (e.g., 192.168.1.0/24) or dash notation (e.g., 192.168.1.1-192.168.1.255)

        Returns:
            True if IP is in range, False otherwise
        """
        try:
            target_ip = ip_address(ip_str)
        except (AddressValueError, ValueError) as e:
            logger.debug(f"Invalid IP address '{ip_str}': {e}")
            return False

        if "/" in ip_range:
            # CIDR notation
            try:
                network = ip_network(ip_range, strict=False)
                return target_ip in network
            except (AddressValueError, NetmaskValueError, ValueError) as e:
                logger.debug(f"Invalid CIDR range '{ip_range}': {e}")
                return False
        elif "-" in ip_range:
            # Range notation (e.g., 192.168.1.1-192.168.1.255)
            try:
                parts = ip_range.split("-")
                if len(parts) != 2:
                    return False
                start_ip = ip_address(parts[0].strip())
                end_ip = ip_address(parts[1].strip())
                return start_ip <= target_ip <= end_ip
            except (AddressValueError, ValueError) as e:
                logger.debug(f"Invalid IP range '{ip_range}': {e}")
                return False
        return False


@dataclass
class ProgramScope:
    """Bug bounty program scope configuration"""
    program_name: str
    platform: BugBountyPlatform
    in_scope: List[ScopeAsset] = field(default_factory=list)
    out_of_scope: List[ScopeAsset] = field(default_factory=list)

    # Program rules and restrictions
    rules: Dict[str, Any] = field(default_factory=dict)

    # Testing restrictions
    allowed_attack_types: Set[str] = field(default_factory=set)
    forbidden_attack_types: Set[str] = field(default_factory=set)

    # Metadata
    created_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    updated_at: str = field(default_factory=lambda: datetime.utcnow().isoformat())
    notes: str = ""

    def is_in_scope(self, target: str) -> Tuple[bool, Optional[str]]:
        """
        Check if a target is in scope

        Returns:
            (is_valid, reason)
        """
        # First check if explicitly out of scope
        for asset in self.out_of_scope:
            if asset.matches(target):
                return False, f"Target '{target}' matches out-of-scope asset: {asset.value}"

        # Then check if in scope
        for asset in self.in_scope:
            if asset.matches(target):
                return True, f"Target '{target}' matches in-scope asset: {asset.value}"

        # Not found in either list
        return False, f"Target '{target}' not found in scope definition"

    def can_perform_attack(self, attack_type: str) -> Tuple[bool, Optional[str]]:
        """Check if an attack type is allowed"""
        if attack_type in self.forbidden_attack_types:
            return False, f"Attack type '{attack_type}' is explicitly forbidden"

        if self.allowed_attack_types and attack_type not in self.allowed_attack_types:
            return False, f"Attack type '{attack_type}' not in allowed list"

        return True, None


class ScopeManager:
    """Manages bug bounty program scopes"""

    def __init__(self, config_dir: Optional[Path] = None):
        self.config_dir = config_dir or Path.home() / ".bountybuddy" / "scopes"
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.current_scope: Optional[ProgramScope] = None

    @staticmethod
    def _get_validated_input(prompt: str, validator: Optional[Callable[[str], bool]] = None,
                              error_msg: str = "Invalid input, please try again.") -> str:
        """
        Get validated input from user with retry logic.

        Args:
            prompt: The prompt to display
            validator: Optional validation function returning True if valid
            error_msg: Message to display on validation failure

        Returns:
            Validated user input
        """
        while True:
            user_input = input(prompt).strip()
            if validator is None or validator(user_input):
                return user_input
            print(f"  {error_msg}")

    @staticmethod
    def _get_validated_int(prompt: str, min_val: int, max_val: int,
                           error_msg: str = "Invalid number, please try again.") -> int:
        """
        Get validated integer input from user with retry logic.

        Args:
            prompt: The prompt to display
            min_val: Minimum valid value (inclusive)
            max_val: Maximum valid value (inclusive)
            error_msg: Message to display on validation failure

        Returns:
            Validated integer
        """
        while True:
            try:
                user_input = input(prompt).strip()
                value = int(user_input)
                if min_val <= value <= max_val:
                    return value
                print(f"  {error_msg} (must be between {min_val} and {max_val})")
            except ValueError:
                print(f"  {error_msg} (must be a number)")

    def interactive_scope_setup(self) -> ProgramScope:
        """
        Interactive CLI to set up a new bug bounty program scope

        Returns:
            Configured ProgramScope object
        """
        print("\n" + "="*60)
        print("Bug Bounty Program Scope Configuration")
        print("="*60 + "\n")

        # Program name with validation
        program_name = self._get_validated_input(
            "Program name (e.g., 'Acme Corp Bug Bounty'): ",
            validator=lambda x: len(x) >= 2,
            error_msg="Program name must be at least 2 characters."
        )

        # Platform with validation
        print("\nSelect platform:")
        platforms = list(BugBountyPlatform)
        for i, platform in enumerate(platforms, 1):
            print(f"  {i}. {platform.value}")

        platform_choice = self._get_validated_int(
            f"Enter number (1-{len(platforms)}): ",
            min_val=1,
            max_val=len(platforms),
            error_msg="Invalid platform number."
        )
        platform = platforms[platform_choice - 1]

        # In-scope assets
        print("\n📌 IN-SCOPE ASSETS")
        print("Enter assets (one per line). Type 'done' when finished.")
        in_scope = self._collect_assets("IN-SCOPE")

        # Out-of-scope assets
        print("\n🚫 OUT-OF-SCOPE ASSETS")
        print("Enter assets to EXCLUDE (one per line). Type 'done' when finished.")
        out_of_scope = self._collect_assets("OUT-OF-SCOPE")

        # Attack type restrictions
        print("\n⚙️  TESTING RESTRICTIONS")
        allow_dos = input("Allow Denial of Service (DoS) testing? (y/N): ").lower() == 'y'
        allow_social = input("Allow Social Engineering? (y/N): ").lower() == 'y'
        allow_physical = input("Allow Physical testing? (y/N): ").lower() == 'y'

        allowed_types = {"xss", "sqli", "ssrf", "idor", "auth", "csrf", "xxe", "lfi", "rfi", "ssti"}
        forbidden_types = set()

        if not allow_dos:
            forbidden_types.add("dos")
        if not allow_social:
            forbidden_types.add("social_engineering")
        if not allow_physical:
            forbidden_types.add("physical")

        # Additional notes
        print("\n📝 ADDITIONAL NOTES")
        notes = input("Program notes (optional): ").strip()

        # Create scope
        scope = ProgramScope(
            program_name=program_name,
            platform=platform,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            allowed_attack_types=allowed_types,
            forbidden_attack_types=forbidden_types,
            notes=notes
        )

        # Save scope
        self.save_scope(scope)
        self.current_scope = scope

        print("\n✅ Scope configuration saved!")
        print(f"   In-scope assets: {len(in_scope)}")
        print(f"   Out-of-scope assets: {len(out_of_scope)}")
        print(f"   Config saved to: {self._get_scope_path(program_name)}\n")

        return scope

    def _collect_assets(self, scope_type: str) -> List[ScopeAsset]:
        """Helper to collect assets interactively"""
        assets = []

        while True:
            asset_value = input(f"{scope_type} asset (or 'done'): ").strip()
            if asset_value.lower() == 'done':
                break

            # Auto-detect asset type
            asset_type = self._detect_asset_type(asset_value)

            description = input(f"  Description (optional): ").strip()

            assets.append(ScopeAsset(
                value=asset_value,
                asset_type=asset_type,
                description=description
            ))
            print(f"  ✓ Added {asset_type.value}: {asset_value}")

        return assets

    @staticmethod
    def _detect_asset_type(value: str) -> AssetType:
        """Auto-detect asset type from value"""
        # IP address
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return AssetType.IP_ADDRESS

        # IP range (CIDR)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', value):
            return AssetType.IP_RANGE

        # IP range (dash notation)
        if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}-\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
            return AssetType.IP_RANGE

        # API endpoint
        if value.startswith(('http://', 'https://', 'api.')):
            return AssetType.API_ENDPOINT

        # Wildcard subdomain
        if '*' in value:
            return AssetType.SUBDOMAIN

        # Mobile app
        if value.startswith(('app.', 'mobile.')) or value.endswith(('.apk', '.ipa')):
            return AssetType.MOBILE_APP

        # Domain (default)
        if '.' in value:
            return AssetType.DOMAIN

        return AssetType.OTHER

    def save_scope(self, scope: ProgramScope) -> Path:
        """Save scope configuration to disk"""
        scope.updated_at = datetime.utcnow().isoformat()

        file_path = self._get_scope_path(scope.program_name)

        # Convert to dict for JSON serialization
        scope_dict = {
            "program_name": scope.program_name,
            "platform": scope.platform.value,
            "in_scope": [
                {
                    "value": asset.value,
                    "asset_type": asset.asset_type.value,
                    "description": asset.description,
                    "notes": asset.notes
                }
                for asset in scope.in_scope
            ],
            "out_of_scope": [
                {
                    "value": asset.value,
                    "asset_type": asset.asset_type.value,
                    "description": asset.description,
                    "notes": asset.notes
                }
                for asset in scope.out_of_scope
            ],
            "allowed_attack_types": list(scope.allowed_attack_types),
            "forbidden_attack_types": list(scope.forbidden_attack_types),
            "rules": scope.rules,
            "created_at": scope.created_at,
            "updated_at": scope.updated_at,
            "notes": scope.notes
        }

        with open(file_path, 'w') as f:
            json.dump(scope_dict, f, indent=2)

        return file_path

    def load_scope(self, program_name: str) -> Optional[ProgramScope]:
        """Load scope configuration from disk"""
        file_path = self._get_scope_path(program_name)

        if not file_path.exists():
            return None

        with open(file_path, 'r') as f:
            data = json.load(f)

        # Reconstruct scope object
        scope = ProgramScope(
            program_name=data["program_name"],
            platform=BugBountyPlatform(data["platform"]),
            in_scope=[
                ScopeAsset(
                    value=asset["value"],
                    asset_type=AssetType(asset["asset_type"]),
                    description=asset.get("description", ""),
                    notes=asset.get("notes", "")
                )
                for asset in data["in_scope"]
            ],
            out_of_scope=[
                ScopeAsset(
                    value=asset["value"],
                    asset_type=AssetType(asset["asset_type"]),
                    description=asset.get("description", ""),
                    notes=asset.get("notes", "")
                )
                for asset in data["out_of_scope"]
            ],
            allowed_attack_types=set(data.get("allowed_attack_types", [])),
            forbidden_attack_types=set(data.get("forbidden_attack_types", [])),
            rules=data.get("rules", {}),
            created_at=data["created_at"],
            updated_at=data["updated_at"],
            notes=data.get("notes", "")
        )

        self.current_scope = scope
        return scope

    def list_scopes(self) -> List[str]:
        """List all saved scope configurations"""
        return [
            f.stem for f in self.config_dir.glob("*.json")
        ]

    def _get_scope_path(self, program_name: str) -> Path:
        """Get file path for a scope configuration"""
        # Sanitize program name for filename
        safe_name = re.sub(r'[^\w\s-]', '', program_name).strip().replace(' ', '_')
        return self.config_dir / f"{safe_name}.json"

    def validate_target(self, target: str, attack_type: Optional[str] = None) -> Tuple[bool, str]:
        """
        Validate a target against current scope

        Returns:
            (is_valid, message)
        """
        if not self.current_scope:
            return False, "No scope loaded. Run scope setup first."

        # Check target scope
        is_in_scope, scope_msg = self.current_scope.is_in_scope(target)
        if not is_in_scope:
            return False, f"⚠️  SCOPE VIOLATION: {scope_msg}"

        # Check attack type if provided
        if attack_type:
            can_attack, attack_msg = self.current_scope.can_perform_attack(attack_type)
            if not can_attack:
                return False, f"⚠️  FORBIDDEN ATTACK TYPE: {attack_msg}"

        return True, f"✅ Target '{target}' is in scope"


# CLI interface
def main():
    """CLI entry point for scope management"""
    import sys

    manager = ScopeManager()

    if len(sys.argv) > 1 and sys.argv[1] == "setup":
        # Interactive setup
        scope = manager.interactive_scope_setup()

    elif len(sys.argv) > 2 and sys.argv[1] == "load":
        # Load existing scope
        program_name = sys.argv[2]
        scope = manager.load_scope(program_name)
        if scope:
            print(f"✅ Loaded scope: {program_name}")
        else:
            print(f"❌ Scope not found: {program_name}")

    elif len(sys.argv) > 1 and sys.argv[1] == "list":
        # List all scopes
        scopes = manager.list_scopes()
        print("\n📋 Saved scopes:")
        for name in scopes:
            print(f"  - {name}")
        print()

    else:
        print("Usage:")
        print("  bountybuddy-scope setup         # Interactive scope setup")
        print("  bountybuddy-scope load <name>   # Load saved scope")
        print("  bountybuddy-scope list          # List all scopes")


if __name__ == "__main__":
    main()
