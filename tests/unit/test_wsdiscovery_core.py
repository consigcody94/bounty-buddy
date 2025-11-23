"""
Unit tests for WS-Discovery core functionality
"""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../tools'))

import pytest
from unittest.mock import Mock, patch, MagicMock
from iothackbot.core.wsdiscovery_core import (
    parse_ws_discovery_response,
    discover_devices,
    WSDiscoveryTool
)
from iothackbot.core.interfaces import ToolConfig


class TestParseWSDiscoveryResponse:
    """Test WS-Discovery response parsing"""

    def test_parse_valid_probe_match(self):
        """Test parsing valid ProbeMatch response"""
        response = b'''<?xml version="1.0" encoding="UTF-8"?>
<soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope">
    <soap-env:Body>
        <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <d:ProbeMatch>
                <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
                    <wsa:Address>urn:uuid:test-device</wsa:Address>
                </wsa:EndpointReference>
                <d:Types>dn:NetworkVideoTransmitter</d:Types>
                <d:Scopes>onvif://www.onvif.org/name/TestCamera</d:Scopes>
                <d:XAddrs>http://192.168.1.100/onvif/device_service</d:XAddrs>
                <d:MetadataVersion>1</d:MetadataVersion>
            </d:ProbeMatch>
        </d:ProbeMatches>
    </soap-env:Body>
</soap-env:Envelope>'''

        result = parse_ws_discovery_response(response)
        assert result.get('endpoint_reference') == 'urn:uuid:test-device'
        assert result.get('types') == 'dn:NetworkVideoTransmitter'
        assert 'TestCamera' in result.get('scopes', '')
        assert 'http://192.168.1.100' in result.get('xaddrs', '')
        assert result.get('metadata_version') == '1'

    def test_parse_invalid_xml(self):
        """Test parsing invalid XML returns empty dict"""
        response = b'Not valid XML'
        result = parse_ws_discovery_response(response)
        assert result == {}

    def test_parse_empty_response(self):
        """Test parsing empty response"""
        response = b''
        result = parse_ws_discovery_response(response)
        assert result == {}

    def test_parse_response_with_unicode_errors(self):
        """Test parsing response with unicode decode errors"""
        response = b'\xff\xfe Invalid unicode'
        result = parse_ws_discovery_response(response)
        # Should not raise exception
        assert isinstance(result, dict)


class TestWSDiscoveryTool:
    """Test WSDiscoveryTool class"""

    def test_tool_properties(self):
        """Test tool name and description properties"""
        tool = WSDiscoveryTool()
        assert tool.name == "wsdiscovery"
        assert "WS-Discovery" in tool.description

    @patch('iothackbot.core.wsdiscovery_core.discover_devices')
    def test_tool_run_success(self, mock_discover):
        """Test successful tool execution"""
        mock_discover.return_value = {
            'devices_found': 1,
            'devices': [{'ip': '192.168.1.100', 'port': 3702}],
            'total_responses': 1,
            'target_ip': '239.255.255.250'
        }

        tool = WSDiscoveryTool()
        config = ToolConfig(input_paths=['239.255.255.250'])
        result = tool.run(config)

        assert result.success is True
        assert result.data['devices_found'] == 1
        assert result.metadata['devices_found'] == 1

    @patch('iothackbot.core.wsdiscovery_core.discover_devices')
    def test_tool_run_with_timeout(self, mock_discover):
        """Test tool execution with custom timeout"""
        mock_discover.return_value = {
            'devices_found': 0,
            'devices': [],
            'total_responses': 0,
            'target_ip': '239.255.255.250'
        }

        tool = WSDiscoveryTool()
        config = ToolConfig(
            input_paths=['239.255.255.250'],
            timeout=10.0,
            verbose=True
        )
        result = tool.run(config)

        assert result.success is True
        mock_discover.assert_called_once()
        call_args = mock_discover.call_args
        assert call_args[1]['timeout'] == 10.0
        assert call_args[1]['verbose'] is True

    @patch('iothackbot.core.wsdiscovery_core.discover_devices')
    def test_tool_run_exception_handling(self, mock_discover):
        """Test tool exception handling"""
        mock_discover.side_effect = Exception("Network error")

        tool = WSDiscoveryTool()
        config = ToolConfig(input_paths=['239.255.255.250'])
        result = tool.run(config)

        assert result.success is False
        assert len(result.errors) > 0
        assert "Network error" in result.errors[0]

    @patch('iothackbot.core.wsdiscovery_core.fuzz_ws_discovery')
    def test_discover_devices_deduplication(self, mock_fuzz):
        """Test device deduplication in discover_devices"""
        # Mock responses with duplicate devices
        mock_fuzz.return_value = [
            (('192.168.1.100', 3702), b'''<?xml version="1.0"?>
<soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope">
    <soap-env:Body>
        <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <d:ProbeMatch>
                <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
                    <wsa:Address>urn:uuid:device1</wsa:Address>
                </wsa:EndpointReference>
            </d:ProbeMatch>
        </d:ProbeMatches>
    </soap-env:Body>
</soap-env:Envelope>'''),
            (('192.168.1.100', 3702), b'''<?xml version="1.0"?>
<soap-env:Envelope xmlns:soap-env="http://www.w3.org/2003/05/soap-envelope">
    <soap-env:Body>
        <d:ProbeMatches xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery">
            <d:ProbeMatch>
                <wsa:EndpointReference xmlns:wsa="http://www.w3.org/2005/08/addressing">
                    <wsa:Address>urn:uuid:device1</wsa:Address>
                </wsa:EndpointReference>
            </d:ProbeMatch>
        </d:ProbeMatches>
    </soap-env:Body>
</soap-env:Envelope>''')
        ]

        result = discover_devices('239.255.255.250')
        # Should deduplicate to 1 device
        assert result['devices_found'] == 1
        assert len(result['devices']) == 1


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
