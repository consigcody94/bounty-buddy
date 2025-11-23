## IoTHackBot - Usage Examples

This document provides comprehensive examples for using IoTHackBot tools.

## Table of Contents

- [WS-Discovery Scanner](#ws-discovery-scanner)
- [ONVIF Scanner](#onvif-scanner)
- [IoT Network Analyzer](#iot-network-analyzer)
- [Firmware File Finder](#firmware-file-finder)
- [Chaining Tools](#chaining-tools)
- [Report Generation](#report-generation)

---

## WS-Discovery Scanner

### Basic Discovery

Discover ONVIF cameras on local network:

```bash
wsdiscovery 239.255.255.250
```

### Discovery with Verbose Output

```bash
wsdiscovery 239.255.255.250 -v
```

### JSON Output for Automation

```bash
wsdiscovery 239.255.255.250 --format json > devices.json
```

### Example Output

```
DISCOVERY SUMMARY:
============================================================
Device 1:
  IP Address: 192.168.1.100:3702
  Endpoint Reference: urn:uuid:4d454930-0050-0000-b49a-00b09d42fc4e
  Device Types: dn:NetworkVideoTransmitter
  Device Information:
    Manufacturer: Hikvision
    Name: IPCamera
    Hardware: IPC-HDW5831R-ZE
  Service Endpoints:
    • http://192.168.1.100/onvif/device_service

Total unique devices discovered: 1
WS-Discovery scan completed.
```

---

## ONVIF Scanner

### Authentication Bypass Testing

Test for unauthenticated access to ONVIF endpoints:

```bash
onvifscan auth http://192.168.1.100
```

### Comprehensive Authentication Test

```bash
onvifscan auth http://192.168.1.100 --all
```

### Credential Brute Force

```bash
onvifscan brute http://192.168.1.100
```

### Custom Wordlists

```bash
onvifscan brute http://192.168.1.100 \
    --usernames custom_users.txt \
    --passwords custom_pass.txt
```

### JSON Output

```bash
onvifscan auth http://192.168.1.100 --format json > onvif_results.json
```

### Example Security Finding

```
SECURITY ISSUES FOUND: 3
  - GetDeviceInformation: Accessible without authentication (SECURITY ISSUE)
  - GetNetworkInterfaces: Accessible without authentication (SECURITY ISSUE)
  - GetUsers: Accessible without authentication (CRITICAL)
```

---

## IoT Network Analyzer

### Analyze PCAP File

```bash
iotnet capture.pcap
```

### Live Capture

```bash
sudo iotnet -i eth0 -d 60
```

### Filter by Protocol

```bash
iotnet capture.pcap --protocol mqtt
```

### JSON Output

```bash
iotnet capture.pcap --format json > network_analysis.json
```

---

## Firmware File Finder

### Identify File Types

```bash
ffind firmware.bin
```

### Extract Filesystems

```bash
sudo ffind firmware.bin -e
```

### Extract to Specific Directory

```bash
sudo ffind firmware.bin -e -d /path/to/output
```

### Search Multiple Files

```bash
ffind *.bin
```

### Example Output

```
File: firmware.bin
  ext4 filesystem found at offset 0x20000
  F2FS filesystem found at offset 0x500000

Extraction complete:
  /tmp/ffind_firmware/ext4_0x20000/
  /tmp/ffind_firmware/f2fs_0x500000/
```

---

## Chaining Tools

### Discover and Test Workflow

```bash
# Step 1: Discover devices
wsdiscovery 239.255.255.250 --format json > devices.json

# Step 2: Extract IP addresses
cat devices.json | jq -r '.devices[].xaddrs' | grep -oP 'http://\K[^/]+' > targets.txt

# Step 3: Test each target
while read target; do
    echo "Testing $target"
    onvifscan auth "http://$target" --format json >> results.json
done < targets.txt
```

### Automated Vulnerability Assessment

```bash
#!/bin/bash

# Discover ONVIF devices
echo "[+] Discovering ONVIF devices..."
wsdiscovery 239.255.255.250 --format json > discovery.json

# Parse and test each device
echo "[+] Testing discovered devices..."
jq -r '.devices[].xaddrs' discovery.json | \
    grep -oP 'http://\K[^/]+' | \
    while read ip; do
        echo "[*] Testing $ip"

        # Test for auth bypass
        onvifscan auth "http://$ip" --all --format json > "scan_${ip}.json"

        # Attempt credential brute force if auth required
        if grep -q '"security_issues": \[\]' "scan_${ip}.json"; then
            echo "[*] No auth bypass found, trying brute force..."
            onvifscan brute "http://$ip" --format json > "brute_${ip}.json"
        fi
    done

echo "[+] Assessment complete!"
```

---

## Report Generation

### Using Python API

```python
from iothackbot.core.report_generator import ReportGenerator
from iothackbot.core.wsdiscovery_core import WSDiscoveryTool
from iothackbot.core.onvifscan_core import OnvifScanTool
from iothackbot.core.interfaces import ToolConfig

# Create report generator
report = ReportGenerator(title="IoT Security Assessment - Network 192.168.1.0/24")

# Run WS-Discovery
wsd_tool = WSDiscoveryTool()
wsd_config = ToolConfig(input_paths=['239.255.255.250'])
wsd_result = wsd_tool.run(wsd_config)
report.add_result('WS-Discovery', wsd_result)

# Run ONVIF scan
onvif_tool = OnvifScanTool()
onvif_config = ToolConfig(
    input_paths=['http://192.168.1.100'],
    custom_args={'mode': 'auth', 'test_all': True}
)
onvif_result = onvif_tool.run(onvif_config)
report.add_result('ONVIF Security Scan', onvif_result)

# Generate HTML report
report.generate_html('assessment_report.html')

# Generate JSON report
report.generate_json('assessment_report.json')

# Generate Markdown report
report.generate_markdown('assessment_report.md')
```

---

## Advanced Examples

### Parallel Scanning

```bash
#!/bin/bash

# Generate IP range
for i in {1..254}; do
    echo "192.168.1.$i"
done > targets.txt

# Parallel scanning with GNU parallel
cat targets.txt | parallel -j 50 "onvifscan auth http://{} --format json > scan_{}.json"
```

### Integration with Other Tools

```bash
# Find ONVIF devices with nmap
sudo nmap -p 80,8080,8000 192.168.1.0/24 -oG - | \
    grep "80/open" | \
    awk '{print $2}' | \
    while read ip; do
        echo "[*] Testing $ip with onvifscan"
        onvifscan auth "http://$ip"
    done
```

### Logging and Monitoring

```python
from iothackbot.core.logger import setup_tool_logger
from iothackbot.core.wsdiscovery_core import WSDiscoveryTool
from iothackbot.core.interfaces import ToolConfig

# Setup logging
logger = setup_tool_logger('wsdiscovery', verbose=True, log_file='scan.log')

# Run scan with logging
tool = WSDiscoveryTool()
config = ToolConfig(input_paths=['239.255.255.250'], verbose=True)

logger.info("Starting WS-Discovery scan")
result = tool.run(config)
logger.info(f"Scan complete: {result.metadata.get('devices_found', 0)} devices found")
```

---

## Claude Code Skills

IoTHackBot includes Claude Code skills for interactive testing:

### Using nmap-scan skill

```
/nmap-scan 192.168.1.0/24
```

### Using picocom skill for UART

```
/picocom /dev/ttyUSB0
```

### Using telnetshell skill

```
/telnetshell 192.168.1.100
```

---

## Best Practices

1. **Always get authorization** before testing any systems
2. **Start with passive reconnaissance** (WS-Discovery, network capture)
3. **Use rate limiting** for brute force attempts
4. **Log all activities** for documentation
5. **Generate reports** for findings
6. **Verify findings manually** before reporting

---

## Troubleshooting

### Permission Denied

```bash
# FFindmay need sudo for filesystem extraction
sudo ffind firmware.bin -e

# Network capture requires sudo
sudo iotnet -i eth0 -d 60
```

### No Devices Found

```bash
# Ensure multicast is enabled
ip maddress show

# Check firewall rules
sudo iptables -L

# Try broadcast instead of multicast
wsdiscovery 255.255.255.255
```

### Connection Timeouts

```bash
# Increase timeout
onvifscan auth http://192.168.1.100 --timeout 30
```

---

For more information, see:
- [README.md](../README.md)
- [TOOL_DEVELOPMENT_GUIDE.md](../TOOL_DEVELOPMENT_GUIDE.md)
- [CONTRIBUTING.md](../CONTRIBUTING.md)
