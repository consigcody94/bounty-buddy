"""
Unit tests for async network scanner functionality.

SPDX-License-Identifier: MIT
"""
import sys
import os
import asyncio

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))

import pytest
from iothackbot.core.async_scanner import (
    ScanResult,
    AsyncPortScanner,
    AsyncUDPScanner,
    AsyncUDPProtocol,
    quick_port_scan,
    quick_host_discovery,
)


class TestScanResult:
    """Test ScanResult dataclass"""

    def test_scan_result_creation(self):
        """Test creating a ScanResult instance"""
        result = ScanResult(
            target="192.168.1.1",
            port=80,
            success=True,
            data={"banner": "nginx"},
            latency=0.05
        )
        assert result.target == "192.168.1.1"
        assert result.port == 80
        assert result.success is True
        assert result.data == {"banner": "nginx"}
        assert result.latency == 0.05
        assert result.error is None

    def test_scan_result_with_error(self):
        """Test ScanResult with error"""
        result = ScanResult(
            target="192.168.1.1",
            port=443,
            success=False,
            error="Connection refused"
        )
        assert result.success is False
        assert result.error == "Connection refused"

    def test_scan_result_defaults(self):
        """Test ScanResult default values"""
        result = ScanResult(target="host", port=22, success=True)
        assert result.data is None
        assert result.error is None
        assert result.latency == 0.0


class TestAsyncPortScanner:
    """Test AsyncPortScanner class"""

    def test_scanner_initialization(self):
        """Test scanner initialization with custom parameters"""
        scanner = AsyncPortScanner(timeout=2.0, max_concurrent=50)
        assert scanner.timeout == 2.0
        assert scanner.semaphore._value == 50

    def test_scanner_default_initialization(self):
        """Test scanner initialization with defaults"""
        scanner = AsyncPortScanner()
        assert scanner.timeout == 1.0
        assert scanner.semaphore._value == 100

    @pytest.mark.asyncio
    async def test_scan_port_timeout(self):
        """Test scanning a port that times out"""
        scanner = AsyncPortScanner(timeout=0.1)
        # Use a non-routable IP to ensure timeout
        result = await scanner.scan_port("10.255.255.1", 80)
        assert result.success is False
        assert result.target == "10.255.255.1"
        assert result.port == 80

    @pytest.mark.asyncio
    async def test_scan_ports_multiple(self):
        """Test scanning multiple ports on a host"""
        scanner = AsyncPortScanner(timeout=0.1)
        # Use localhost with unlikely ports to ensure quick failure
        results = await scanner.scan_ports("127.0.0.1", [59999, 59998, 59997])
        assert len(results) == 3
        for result in results:
            assert result.target == "127.0.0.1"

    @pytest.mark.asyncio
    async def test_scan_ports_with_callback(self):
        """Test scan with callback function"""
        scanner = AsyncPortScanner(timeout=0.1)
        callback_results = []

        def callback(result):
            callback_results.append(result)

        await scanner.scan_ports("127.0.0.1", [59999, 59998], callback=callback)
        assert len(callback_results) == 2

    @pytest.mark.asyncio
    async def test_scan_hosts_multiple(self):
        """Test scanning a port on multiple hosts"""
        scanner = AsyncPortScanner(timeout=0.1)
        # Use non-routable IPs
        hosts = ["10.255.255.1", "10.255.255.2"]
        results = await scanner.scan_hosts(hosts, 80)
        assert len(results) == 2
        for result in results:
            assert result.port == 80

    @pytest.mark.asyncio
    async def test_scan_network_small(self):
        """Test small network scan (under chunk size)"""
        scanner = AsyncPortScanner(timeout=0.1)
        hosts = ["10.255.255.1", "10.255.255.2"]
        ports = [80, 443]
        results = await scanner.scan_network(hosts, ports)
        assert len(results) == 4  # 2 hosts * 2 ports

    @pytest.mark.asyncio
    async def test_scan_network_chunked(self):
        """Test large network scan with chunking"""
        scanner = AsyncPortScanner(timeout=0.01)
        # Create enough combinations to trigger chunking
        hosts = [f"10.255.255.{i}" for i in range(5)]
        ports = list(range(50000, 50050))  # 50 ports
        results = await scanner.scan_network(hosts, ports, chunk_size=100)
        assert len(results) == 250  # 5 hosts * 50 ports

    @pytest.mark.asyncio
    async def test_scan_network_streaming(self):
        """Test streaming network scan"""
        scanner = AsyncPortScanner(timeout=0.01)
        hosts = ["10.255.255.1", "10.255.255.2"]
        ports = [59999, 59998]
        results = []
        async for result in scanner.scan_network_streaming(hosts, ports, chunk_size=2):
            results.append(result)
        assert len(results) == 4


class TestAsyncUDPProtocol:
    """Test AsyncUDPProtocol class"""

    def test_protocol_initialization(self):
        """Test protocol initialization"""
        protocol = AsyncUDPProtocol()
        assert protocol.transport is None
        assert not protocol.response_future.done()

    def test_datagram_received(self):
        """Test handling received datagram"""
        protocol = AsyncUDPProtocol()
        protocol.datagram_received(b"test data", ("192.168.1.1", 1234))
        assert protocol.response_future.done()
        result = protocol.response_future.result()
        assert result[0] == b"test data"
        assert result[1] == ("192.168.1.1", 1234)

    def test_error_received(self):
        """Test handling received error"""
        protocol = AsyncUDPProtocol()
        exc = ConnectionError("Test error")
        protocol.error_received(exc)
        assert protocol.response_future.done()
        with pytest.raises(ConnectionError):
            protocol.response_future.result()

    def test_connection_lost_with_exception(self):
        """Test connection lost with exception"""
        protocol = AsyncUDPProtocol()
        exc = ConnectionError("Connection lost")
        protocol.connection_lost(exc)
        assert protocol.response_future.done()
        with pytest.raises(ConnectionError):
            protocol.response_future.result()

    def test_connection_lost_without_exception(self):
        """Test connection lost without exception"""
        protocol = AsyncUDPProtocol()
        protocol.connection_lost(None)
        assert protocol.response_future.done()
        with pytest.raises(ConnectionError):
            protocol.response_future.result()


class TestAsyncUDPScanner:
    """Test AsyncUDPScanner class"""

    def test_udp_scanner_initialization(self):
        """Test UDP scanner initialization"""
        scanner = AsyncUDPScanner(timeout=3.0, max_concurrent=25)
        assert scanner.timeout == 3.0
        assert scanner.semaphore._value == 25

    def test_udp_scanner_default_initialization(self):
        """Test UDP scanner default initialization"""
        scanner = AsyncUDPScanner()
        assert scanner.timeout == 2.0
        assert scanner.semaphore._value == 50


class TestUtilityFunctions:
    """Test utility functions"""

    @pytest.mark.asyncio
    async def test_quick_port_scan(self):
        """Test quick_port_scan utility"""
        # Use unlikely ports on localhost
        open_ports = await quick_port_scan(
            "127.0.0.1",
            [59999, 59998],
            timeout=0.1
        )
        # We expect no open ports (unless something is listening)
        assert isinstance(open_ports, list)

    @pytest.mark.asyncio
    async def test_quick_host_discovery(self):
        """Test quick_host_discovery utility"""
        # Use non-routable IPs
        responsive_hosts = await quick_host_discovery(
            ["10.255.255.1", "10.255.255.2"],
            port=80,
            timeout=0.1
        )
        assert isinstance(responsive_hosts, list)


class TestEdgeCases:
    """Test edge cases and error handling"""

    @pytest.mark.asyncio
    async def test_empty_host_list(self):
        """Test scanning with empty host list"""
        scanner = AsyncPortScanner(timeout=0.1)
        results = await scanner.scan_hosts([], 80)
        assert results == []

    @pytest.mark.asyncio
    async def test_empty_port_list(self):
        """Test scanning with empty port list"""
        scanner = AsyncPortScanner(timeout=0.1)
        results = await scanner.scan_ports("127.0.0.1", [])
        assert results == []

    @pytest.mark.asyncio
    async def test_scan_network_empty_inputs(self):
        """Test network scan with empty inputs"""
        scanner = AsyncPortScanner(timeout=0.1)
        results = await scanner.scan_network([], [80])
        assert results == []

        results = await scanner.scan_network(["127.0.0.1"], [])
        assert results == []


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
