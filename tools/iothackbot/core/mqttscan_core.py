"""
Core MQTT scanner functionality - MQTT broker discovery and testing.
Separated from CLI logic for automation and chaining.
"""

import socket
import struct
import time
from typing import List, Dict, Any, Optional, Tuple
from .interfaces import ToolInterface, ToolConfig, ToolResult


# MQTT Protocol Constants
MQTT_CONNECT = 0x10
MQTT_CONNACK = 0x20
MQTT_PUBLISH = 0x30
MQTT_SUBSCRIBE = 0x80
MQTT_SUBACK = 0x90

# MQTT Connect Flags
CLEAN_SESSION = 0x02
WILL_FLAG = 0x04
WILL_QOS_0 = 0x00
WILL_QOS_1 = 0x08
WILL_QOS_2 = 0x10
WILL_RETAIN = 0x20
PASSWORD_FLAG = 0x40
USERNAME_FLAG = 0x80


class MQTTPacket:
    """Helper class for building MQTT packets"""

    @staticmethod
    def encode_string(s: str) -> bytes:
        """Encode a UTF-8 string with length prefix"""
        data = s.encode('utf-8')
        return struct.pack('!H', len(data)) + data

    @staticmethod
    def build_connect_packet(
        client_id: str = "iothackbot",
        username: Optional[str] = None,
        password: Optional[str] = None,
        clean_session: bool = True,
        keep_alive: int = 60,
        protocol_name: str = "MQTT",
        protocol_level: int = 4  # MQTT 3.1.1
    ) -> bytes:
        """Build MQTT CONNECT packet"""

        # Variable header
        variable_header = MQTTPacket.encode_string(protocol_name)
        variable_header += struct.pack('!B', protocol_level)

        # Connect flags
        connect_flags = 0
        if clean_session:
            connect_flags |= CLEAN_SESSION
        if username:
            connect_flags |= USERNAME_FLAG
        if password:
            connect_flags |= PASSWORD_FLAG

        variable_header += struct.pack('!B', connect_flags)
        variable_header += struct.pack('!H', keep_alive)

        # Payload
        payload = MQTTPacket.encode_string(client_id)
        if username:
            payload += MQTTPacket.encode_string(username)
        if password:
            payload += MQTTPacket.encode_string(password)

        # Fixed header
        remaining_length = len(variable_header) + len(payload)
        fixed_header = struct.pack('!B', MQTT_CONNECT)
        fixed_header += MQTTPacket.encode_remaining_length(remaining_length)

        return fixed_header + variable_header + payload

    @staticmethod
    def encode_remaining_length(length: int) -> bytes:
        """Encode remaining length using MQTT variable byte integer"""
        result = bytearray()
        while True:
            byte = length % 128
            length = length // 128
            if length > 0:
                byte |= 0x80
            result.append(byte)
            if length == 0:
                break
        return bytes(result)

    @staticmethod
    def decode_remaining_length(data: bytes, offset: int = 0) -> Tuple[int, int]:
        """Decode remaining length from MQTT packet"""
        multiplier = 1
        value = 0
        index = offset

        while True:
            if index >= len(data):
                return 0, index
            byte = data[index]
            index += 1
            value += (byte & 0x7F) * multiplier
            if (byte & 0x80) == 0:
                break
            multiplier *= 128

        return value, index

    @staticmethod
    def parse_connack(data: bytes) -> Dict[str, Any]:
        """Parse MQTT CONNACK packet"""
        if len(data) < 4:
            return {'error': 'Packet too short'}

        packet_type = data[0] & 0xF0
        if packet_type != MQTT_CONNACK:
            return {'error': f'Not a CONNACK packet: {hex(packet_type)}'}

        remaining_length, offset = MQTTPacket.decode_remaining_length(data, 1)

        if len(data) < offset + remaining_length:
            return {'error': 'Incomplete packet'}

        session_present = data[offset] & 0x01
        return_code = data[offset + 1]

        return_codes = {
            0x00: "Connection Accepted",
            0x01: "Connection Refused: Unacceptable Protocol Version",
            0x02: "Connection Refused: Identifier Rejected",
            0x03: "Connection Refused: Server Unavailable",
            0x04: "Connection Refused: Bad Username or Password",
            0x05: "Connection Refused: Not Authorized"
        }

        return {
            'session_present': bool(session_present),
            'return_code': return_code,
            'return_message': return_codes.get(return_code, f"Unknown: {return_code}"),
            'accepted': return_code == 0x00
        }


def test_mqtt_connection(
    host: str,
    port: int = 1883,
    timeout: float = 5.0,
    username: Optional[str] = None,
    password: Optional[str] = None
) -> Dict[str, Any]:
    """
    Test MQTT broker connectivity and authentication.

    Args:
        host: Target hostname or IP
        port: MQTT port (default 1883)
        timeout: Connection timeout
        username: Optional username for authentication
        password: Optional password for authentication

    Returns:
        Dictionary with connection test results
    """
    result = {
        'host': host,
        'port': port,
        'reachable': False,
        'mqtt_service': False,
        'auth_required': False,
        'auth_success': False,
        'error': None
    }

    try:
        # Create socket connection
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)

        start_time = time.time()
        sock.connect((host, port))
        result['reachable'] = True
        result['latency'] = time.time() - start_time

        # Build and send CONNECT packet
        connect_packet = MQTTPacket.build_connect_packet(
            username=username,
            password=password
        )
        sock.sendall(connect_packet)

        # Receive CONNACK
        response = sock.recv(4096)
        sock.close()

        if len(response) > 0:
            result['mqtt_service'] = True
            connack = MQTTPacket.parse_connack(response)

            result['return_code'] = connack.get('return_code')
            result['return_message'] = connack.get('return_message')
            result['session_present'] = connack.get('session_present')

            # Analyze authentication requirements
            if connack.get('accepted'):
                result['auth_success'] = True
                if username is None and password is None:
                    result['auth_required'] = False
                    result['security_issue'] = "Anonymous access allowed"
                else:
                    result['auth_required'] = True
            elif connack.get('return_code') in [0x04, 0x05]:
                result['auth_required'] = True
            else:
                result['error'] = connack.get('return_message')

        return result

    except socket.timeout:
        result['error'] = 'Connection timeout'
        return result
    except ConnectionRefusedError:
        result['error'] = 'Connection refused'
        return result
    except Exception as e:
        result['error'] = str(e)
        return result


def scan_mqtt_brokers(
    hosts: List[str],
    port: int = 1883,
    timeout: float = 5.0,
    test_auth: bool = True,
    wordlist_users: Optional[List[str]] = None,
    wordlist_passwords: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Scan multiple hosts for MQTT brokers.

    Args:
        hosts: List of target hosts
        port: MQTT port to scan
        timeout: Connection timeout
        test_auth: Whether to test authentication
        wordlist_users: List of usernames to test
        wordlist_passwords: List of passwords to test

    Returns:
        Dictionary with scan results
    """
    results = []
    found_brokers = 0
    anonymous_access = []

    for host in hosts:
        # Test anonymous access
        broker_result = test_mqtt_connection(host, port, timeout)

        if broker_result['mqtt_service']:
            found_brokers += 1

            if not broker_result.get('auth_required'):
                anonymous_access.append(host)

            results.append(broker_result)

            # Test authentication if enabled
            if test_auth and broker_result.get('auth_required'):
                if wordlist_users and wordlist_passwords:
                    # Simple brute force (for demonstration - use responsibly!)
                    for username in wordlist_users[:5]:  # Limit attempts
                        for password in wordlist_passwords[:5]:
                            auth_result = test_mqtt_connection(
                                host, port, timeout, username, password
                            )
                            if auth_result.get('auth_success'):
                                broker_result['found_credentials'] = {
                                    'username': username,
                                    'password': password
                                }
                                break
                        if broker_result.get('found_credentials'):
                            break

    return {
        'total_hosts_scanned': len(hosts),
        'brokers_found': found_brokers,
        'anonymous_access_count': len(anonymous_access),
        'anonymous_access_hosts': anonymous_access,
        'results': results
    }


class MQTTScanTool(ToolInterface):
    """MQTT broker scanner implementation"""

    @property
    def name(self) -> str:
        return "mqttscan"

    @property
    def description(self) -> str:
        return "MQTT broker discovery and security testing"

    def run(self, config: ToolConfig) -> ToolResult:
        """Execute MQTT broker scan"""
        start_time = time.time()

        try:
            target = config.input_path
            port = config.custom_args.get('port', 1883)
            timeout = config.timeout or 5.0
            test_auth = config.custom_args.get('test_auth', True)

            # Single host test
            if '/' not in target:  # Not a CIDR range
                result_data = test_mqtt_connection(
                    target,
                    port=port,
                    timeout=timeout
                )

                execution_time = time.time() - start_time

                return ToolResult(
                    success=True,
                    data=result_data,
                    metadata={
                        'target': target,
                        'port': port,
                        'mqtt_service': result_data.get('mqtt_service', False)
                    },
                    execution_time=execution_time
                )

            # Network scan (simplified - would need IP range parser)
            hosts = [target]  # Placeholder
            result_data = scan_mqtt_brokers(
                hosts,
                port=port,
                timeout=timeout,
                test_auth=test_auth
            )

            execution_time = time.time() - start_time

            return ToolResult(
                success=True,
                data=result_data,
                metadata={
                    'brokers_found': result_data['brokers_found'],
                    'anonymous_access': result_data['anonymous_access_count']
                },
                execution_time=execution_time
            )

        except Exception as e:
            execution_time = time.time() - start_time
            return ToolResult(
                success=False,
                errors=[str(e)],
                metadata={'target': config.input_path},
                execution_time=execution_time
            )
