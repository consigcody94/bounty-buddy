"""
Unit tests for scope management functionality.

SPDX-License-Identifier: MIT
"""
import sys
import os
import tempfile
import json
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))

import pytest
from iothackbot.core.scope.scope_manager import (
    ScopeAsset,
    AssetType,
    ProgramScope,
    BugBountyPlatform,
    ScopeManager,
)


class TestScopeAsset:
    """Test ScopeAsset class"""

    def test_domain_exact_match(self):
        """Test exact domain matching"""
        asset = ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
        assert asset.matches("example.com") is True
        assert asset.matches("other.com") is False

    def test_domain_subdomain_match(self):
        """Test subdomain matching for domain assets"""
        asset = ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
        assert asset.matches("sub.example.com") is True
        assert asset.matches("deep.sub.example.com") is True
        assert asset.matches("notexample.com") is False

    def test_subdomain_wildcard_match(self):
        """Test wildcard subdomain matching"""
        asset = ScopeAsset(value="*.example.com", asset_type=AssetType.SUBDOMAIN)
        assert asset.matches("api.example.com") is True
        assert asset.matches("www.example.com") is True
        assert asset.matches("example.com") is False

    def test_ip_address_exact_match(self):
        """Test exact IP address matching"""
        asset = ScopeAsset(value="192.168.1.100", asset_type=AssetType.IP_ADDRESS)
        assert asset.matches("192.168.1.100") is True
        assert asset.matches("192.168.1.101") is False

    def test_ip_range_cidr_match(self):
        """Test CIDR range matching"""
        asset = ScopeAsset(value="192.168.1.0/24", asset_type=AssetType.IP_RANGE)
        assert asset.matches("192.168.1.1") is True
        assert asset.matches("192.168.1.254") is True
        assert asset.matches("192.168.2.1") is False

    def test_ip_range_dash_notation(self):
        """Test dash notation IP range matching"""
        asset = ScopeAsset(value="192.168.1.1-192.168.1.10", asset_type=AssetType.IP_RANGE)
        assert asset.matches("192.168.1.5") is True
        assert asset.matches("192.168.1.1") is True
        assert asset.matches("192.168.1.10") is True
        assert asset.matches("192.168.1.11") is False

    def test_api_endpoint_prefix_match(self):
        """Test API endpoint prefix matching"""
        asset = ScopeAsset(value="https://api.example.com/v1", asset_type=AssetType.API_ENDPOINT)
        assert asset.matches("https://api.example.com/v1/users") is True
        assert asset.matches("https://api.example.com/v1") is True
        assert asset.matches("https://api.example.com/v2") is False

    def test_invalid_ip_returns_false(self):
        """Test that invalid IPs return False for range matching"""
        asset = ScopeAsset(value="192.168.1.0/24", asset_type=AssetType.IP_RANGE)
        assert asset.matches("not-an-ip") is False
        assert asset.matches("") is False

    def test_invalid_cidr_returns_false(self):
        """Test that invalid CIDR ranges return False"""
        asset = ScopeAsset(value="invalid/cidr", asset_type=AssetType.IP_RANGE)
        assert asset.matches("192.168.1.1") is False


class TestProgramScope:
    """Test ProgramScope class"""

    def test_in_scope_check(self):
        """Test in-scope target validation"""
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            in_scope=[
                ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
            ]
        )
        is_valid, _ = scope.is_in_scope("example.com")
        assert is_valid is True

        is_valid, msg = scope.is_in_scope("other.com")
        assert is_valid is False
        assert "not found in scope" in msg

    def test_out_of_scope_check(self):
        """Test out-of-scope exclusion"""
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            in_scope=[
                ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
            ],
            out_of_scope=[
                ScopeAsset(value="admin.example.com", asset_type=AssetType.DOMAIN)
            ]
        )
        is_valid, _ = scope.is_in_scope("api.example.com")
        assert is_valid is True

        is_valid, msg = scope.is_in_scope("admin.example.com")
        assert is_valid is False
        assert "out-of-scope" in msg

    def test_can_perform_attack_allowed(self):
        """Test allowed attack type validation"""
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            allowed_attack_types={"xss", "sqli"}
        )
        can_attack, _ = scope.can_perform_attack("xss")
        assert can_attack is True

    def test_can_perform_attack_forbidden(self):
        """Test forbidden attack type validation"""
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            forbidden_attack_types={"dos", "physical"}
        )
        can_attack, msg = scope.can_perform_attack("dos")
        assert can_attack is False
        assert "forbidden" in msg

    def test_can_perform_attack_not_in_allowed_list(self):
        """Test attack type not in allowed list"""
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            allowed_attack_types={"xss", "sqli"}
        )
        can_attack, msg = scope.can_perform_attack("rce")
        assert can_attack is False
        assert "not in allowed list" in msg


class TestScopeManager:
    """Test ScopeManager class"""

    @pytest.fixture
    def temp_config_dir(self):
        """Create a temporary directory for scope configurations"""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_scope_manager_creation(self, temp_config_dir):
        """Test ScopeManager initialization"""
        manager = ScopeManager(config_dir=temp_config_dir)
        assert manager.config_dir == temp_config_dir
        assert manager.current_scope is None

    def test_save_and_load_scope(self, temp_config_dir):
        """Test saving and loading scope configurations"""
        manager = ScopeManager(config_dir=temp_config_dir)

        # Create a scope
        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.BUGCROWD,
            in_scope=[
                ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
            ],
            allowed_attack_types={"xss", "sqli"},
            notes="Test notes"
        )

        # Save it
        file_path = manager.save_scope(scope)
        assert file_path.exists()

        # Load it back
        loaded_scope = manager.load_scope("Test Program")
        assert loaded_scope is not None
        assert loaded_scope.program_name == "Test Program"
        assert loaded_scope.platform == BugBountyPlatform.BUGCROWD
        assert len(loaded_scope.in_scope) == 1
        assert loaded_scope.notes == "Test notes"

    def test_list_scopes(self, temp_config_dir):
        """Test listing saved scopes"""
        manager = ScopeManager(config_dir=temp_config_dir)

        # Create multiple scopes
        scope1 = ProgramScope(
            program_name="Program One",
            platform=BugBountyPlatform.HACKERONE
        )
        scope2 = ProgramScope(
            program_name="Program Two",
            platform=BugBountyPlatform.BUGCROWD
        )

        manager.save_scope(scope1)
        manager.save_scope(scope2)

        scopes = manager.list_scopes()
        assert len(scopes) == 2
        assert "Program_One" in scopes
        assert "Program_Two" in scopes

    def test_validate_target(self, temp_config_dir):
        """Test target validation against loaded scope"""
        manager = ScopeManager(config_dir=temp_config_dir)

        scope = ProgramScope(
            program_name="Test Program",
            platform=BugBountyPlatform.HACKERONE,
            in_scope=[
                ScopeAsset(value="example.com", asset_type=AssetType.DOMAIN)
            ],
            forbidden_attack_types={"dos"}
        )
        manager.current_scope = scope

        # Test valid target and attack
        is_valid, _ = manager.validate_target("api.example.com", "xss")
        assert is_valid is True

        # Test invalid target
        is_valid, msg = manager.validate_target("other.com")
        assert is_valid is False
        assert "SCOPE VIOLATION" in msg

        # Test forbidden attack
        is_valid, msg = manager.validate_target("example.com", "dos")
        assert is_valid is False
        assert "FORBIDDEN" in msg

    def test_validate_target_no_scope_loaded(self, temp_config_dir):
        """Test validation when no scope is loaded"""
        manager = ScopeManager(config_dir=temp_config_dir)
        is_valid, msg = manager.validate_target("example.com")
        assert is_valid is False
        assert "No scope loaded" in msg

    def test_detect_asset_type(self):
        """Test automatic asset type detection"""
        manager = ScopeManager()

        # IP address
        assert manager._detect_asset_type("192.168.1.1") == AssetType.IP_ADDRESS

        # CIDR range
        assert manager._detect_asset_type("192.168.1.0/24") == AssetType.IP_RANGE

        # Dash range
        assert manager._detect_asset_type("192.168.1.1-192.168.1.100") == AssetType.IP_RANGE

        # API endpoint
        assert manager._detect_asset_type("https://api.example.com") == AssetType.API_ENDPOINT

        # Wildcard subdomain
        assert manager._detect_asset_type("*.example.com") == AssetType.SUBDOMAIN

        # Mobile app
        assert manager._detect_asset_type("app.apk") == AssetType.MOBILE_APP

        # Domain
        assert manager._detect_asset_type("example.com") == AssetType.DOMAIN

    def test_load_nonexistent_scope(self, temp_config_dir):
        """Test loading a scope that doesn't exist"""
        manager = ScopeManager(config_dir=temp_config_dir)
        scope = manager.load_scope("Nonexistent Program")
        assert scope is None


class TestIPRangeMatching:
    """Additional tests for IP range matching edge cases"""

    def test_ipv4_cidr_boundary(self):
        """Test CIDR boundary conditions"""
        asset = ScopeAsset(value="10.0.0.0/8", asset_type=AssetType.IP_RANGE)
        assert asset.matches("10.0.0.1") is True
        assert asset.matches("10.255.255.255") is True
        assert asset.matches("11.0.0.0") is False

    def test_single_host_cidr(self):
        """Test /32 CIDR (single host)"""
        asset = ScopeAsset(value="192.168.1.1/32", asset_type=AssetType.IP_RANGE)
        assert asset.matches("192.168.1.1") is True
        assert asset.matches("192.168.1.2") is False

    def test_malformed_cidr(self):
        """Test handling of malformed CIDR notation"""
        asset = ScopeAsset(value="192.168.1.1/33", asset_type=AssetType.IP_RANGE)
        assert asset.matches("192.168.1.1") is False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
