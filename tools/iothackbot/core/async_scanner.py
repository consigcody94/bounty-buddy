"""
Async network scanner utilities for IoTHackBot
Provides high-performance asynchronous scanning capabilities
"""

import asyncio
import socket
from typing import List, Tuple, Optional, Callable, Any
from dataclasses import dataclass


@dataclass
class ScanResult:
    """Result from an async scan operation"""
    target: str
    port: int
    success: bool
    data: Any = None
    error: Optional[str] = None
    latency: float = 0.0


class AsyncPortScanner:
    """Asynchronous port scanner for fast network reconnaissance"""

    def __init__(self, timeout: float = 1.0, max_concurrent: int = 100):
        """
        Initialize async port scanner.

        Args:
            timeout: Connection timeout in seconds
            max_concurrent: Maximum concurrent connections
        """
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def scan_port(self, host: str, port: int) -> ScanResult:
        """
        Scan a single port asynchronously.

        Args:
            host: Target hostname or IP
            port: Port number to scan

        Returns:
            ScanResult with scan details
        """
        import time

        async with self.semaphore:
            start_time = time.time()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port),
                    timeout=self.timeout
                )
                writer.close()
                await writer.wait_closed()
                latency = time.time() - start_time

                return ScanResult(
                    target=host,
                    port=port,
                    success=True,
                    latency=latency
                )

            except asyncio.TimeoutError:
                return ScanResult(
                    target=host,
                    port=port,
                    success=False,
                    error="Connection timeout"
                )
            except ConnectionRefusedError:
                return ScanResult(
                    target=host,
                    port=port,
                    success=False,
                    error="Connection refused"
                )
            except Exception as e:
                return ScanResult(
                    target=host,
                    port=port,
                    success=False,
                    error=str(e)
                )

    async def scan_ports(
        self,
        host: str,
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Scan multiple ports on a host asynchronously.

        Args:
            host: Target hostname or IP
            ports: List of ports to scan
            callback: Optional callback function called for each result

        Returns:
            List of ScanResults
        """
        tasks = [self.scan_port(host, port) for port in ports]
        results = await asyncio.gather(*tasks)

        if callback:
            for result in results:
                callback(result)

        return results

    async def scan_hosts(
        self,
        hosts: List[str],
        port: int,
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Scan a single port on multiple hosts asynchronously.

        Args:
            hosts: List of target hosts
            port: Port number to scan
            callback: Optional callback function called for each result

        Returns:
            List of ScanResults
        """
        tasks = [self.scan_port(host, port) for host in hosts]
        results = await asyncio.gather(*tasks)

        if callback:
            for result in results:
                callback(result)

        return results

    async def scan_network(
        self,
        hosts: List[str],
        ports: List[int],
        callback: Optional[Callable[[ScanResult], None]] = None
    ) -> List[ScanResult]:
        """
        Scan multiple ports on multiple hosts asynchronously.

        Args:
            hosts: List of target hosts
            ports: List of ports to scan
            callback: Optional callback function called for each result

        Returns:
            List of ScanResults
        """
        tasks = []
        for host in hosts:
            for port in ports:
                tasks.append(self.scan_port(host, port))

        results = await asyncio.gather(*tasks)

        if callback:
            for result in results:
                callback(result)

        return results


class AsyncUDPScanner:
    """Asynchronous UDP scanner for IoT protocols"""

    def __init__(self, timeout: float = 2.0, max_concurrent: int = 50):
        """
        Initialize async UDP scanner.

        Args:
            timeout: Response timeout in seconds
            max_concurrent: Maximum concurrent operations
        """
        self.timeout = timeout
        self.semaphore = asyncio.Semaphore(max_concurrent)

    async def send_udp(
        self,
        host: str,
        port: int,
        message: bytes,
        expect_response: bool = True
    ) -> ScanResult:
        """
        Send UDP packet and optionally wait for response.

        Args:
            host: Target hostname or IP
            port: Target port
            message: Message bytes to send
            expect_response: Whether to wait for a response

        Returns:
            ScanResult with response data if available
        """
        import time

        async with self.semaphore:
            start_time = time.time()
            try:
                # Create UDP endpoint
                loop = asyncio.get_event_loop()
                transport, protocol = await loop.create_datagram_endpoint(
                    lambda: AsyncUDPProtocol(),
                    remote_addr=(host, port)
                )

                # Send message
                transport.sendto(message)

                if expect_response:
                    # Wait for response
                    try:
                        response = await asyncio.wait_for(
                            protocol.get_response(),
                            timeout=self.timeout
                        )
                        latency = time.time() - start_time

                        transport.close()
                        return ScanResult(
                            target=host,
                            port=port,
                            success=True,
                            data=response,
                            latency=latency
                        )
                    except asyncio.TimeoutError:
                        transport.close()
                        return ScanResult(
                            target=host,
                            port=port,
                            success=False,
                            error="No response received"
                        )
                else:
                    transport.close()
                    return ScanResult(
                        target=host,
                        port=port,
                        success=True
                    )

            except Exception as e:
                return ScanResult(
                    target=host,
                    port=port,
                    success=False,
                    error=str(e)
                )


class AsyncUDPProtocol(asyncio.DatagramProtocol):
    """Protocol for handling UDP responses"""

    def __init__(self):
        self.response_future = asyncio.Future()
        self.transport = None

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if not self.response_future.done():
            self.response_future.set_result((data, addr))

    def error_received(self, exc):
        if not self.response_future.done():
            self.response_future.set_exception(exc)

    def connection_lost(self, exc):
        if not self.response_future.done():
            if exc:
                self.response_future.set_exception(exc)
            else:
                self.response_future.set_exception(
                    ConnectionError("Connection closed without response")
                )

    async def get_response(self):
        return await self.response_future


# Utility functions for common use cases
async def quick_port_scan(
    host: str,
    ports: List[int],
    timeout: float = 1.0,
    max_concurrent: int = 100
) -> List[int]:
    """
    Quick port scan returning only open ports.

    Args:
        host: Target host
        ports: Ports to scan
        timeout: Connection timeout
        max_concurrent: Max concurrent connections

    Returns:
        List of open port numbers
    """
    scanner = AsyncPortScanner(timeout=timeout, max_concurrent=max_concurrent)
    results = await scanner.scan_ports(host, ports)
    return [r.port for r in results if r.success]


async def quick_host_discovery(
    hosts: List[str],
    port: int = 80,
    timeout: float = 1.0,
    max_concurrent: int = 100
) -> List[str]:
    """
    Quick host discovery returning only responsive hosts.

    Args:
        hosts: List of hosts to check
        port: Port to probe
        timeout: Connection timeout
        max_concurrent: Max concurrent connections

    Returns:
        List of responsive hosts
    """
    scanner = AsyncPortScanner(timeout=timeout, max_concurrent=max_concurrent)
    results = await scanner.scan_hosts(hosts, port)
    return [r.target for r in results if r.success]
