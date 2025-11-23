# IoTHackBot - Quick Start Guide

Get started with IoTHackBot in 5 minutes!

## Installation

### Method 1: Using pip (Recommended)

```bash
# Clone the repository
git clone https://github.com/BrownFineSecurity/iothackbot.git
cd iothackbot

# Install as package
pip install -e .

# Verify installation
mqttscan --help
wsdiscovery --help
onvifscan --help
```

### Method 2: Manual Setup

```bash
# Clone the repository
git clone https://github.com/BrownFineSecurity/iothackbot.git
cd iothackbot

# Install dependencies
pip install -r requirements.txt

# Add to PATH
export PATH="$PATH:$(pwd)/bin"

# For permanent setup
echo 'export PATH="$PATH:'$(pwd)'/bin"' >> ~/.bashrc
source ~/.bashrc
```

## First Scan

### Discover IoT Devices

```bash
# Discover ONVIF cameras on your network
wsdiscovery 239.255.255.250

# Output:
# Device 1:
#   IP Address: 192.168.1.100:3702
#   Manufacturer: Hikvision
#   Name: IPCamera
```

### Test MQTT Broker

```bash
# Scan for MQTT broker and check security
mqttscan 192.168.1.100

# Output:
# Target: 192.168.1.100:1883
# Status: MQTT broker found
# Authentication: NOT REQUIRED (SECURITY ISSUE)
```

### Test ONVIF Security

```bash
# Test for authentication bypass
onvifscan auth http://192.168.1.100

# Comprehensive test
onvifscan auth http://192.168.1.100 --all
```

### Analyze Firmware

```bash
# Identify filesystems in firmware
ffind firmware.bin

# Extract filesystems (requires sudo)
sudo ffind firmware.bin -e
```

## Generate Reports

### Python API

```python
from iothackbot.core.report_generator import ReportGenerator
from iothackbot.core.wsdiscovery_core import WSDiscoveryTool
from iothackbot.core.interfaces import ToolConfig

# Create report
report = ReportGenerator(title="My IoT Security Scan")

# Run scan
tool = WSDiscoveryTool()
config = ToolConfig(input_paths=['239.255.255.250'])
result = tool.run(config)

# Add to report
report.add_result('WS-Discovery', result)

# Generate HTML report
report.generate_html('my_report.html')
```

### Command Line

```bash
# JSON output for chaining
wsdiscovery 239.255.255.250 --format json > discovery.json
mqttscan 192.168.1.100 --format json > mqtt_scan.json
onvifscan auth http://192.168.1.100 --format json > onvif_scan.json

# Process with jq or other tools
cat discovery.json | jq '.devices[] | .ip'
```

## Development Setup

### For Contributors

```bash
# Clone and setup
git clone https://github.com/BrownFineSecurity/iothackbot.git
cd iothackbot

# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/ -v

# Format code
black tools/ tests/
isort tools/ tests/

# Run linters
flake8 tools/ tests/
mypy tools/iothackbot
```

## Common Workflows

### Full Network Assessment

```bash
#!/bin/bash

# Discover devices
echo "[+] Discovering devices..."
wsdiscovery 239.255.255.250 --format json > devices.json

# Extract IPs and test each
echo "[+] Testing discovered devices..."
jq -r '.devices[].xaddrs' devices.json | \
    grep -oP 'http://\K[^/]+' | \
    while read ip; do
        echo "[*] Testing $ip"
        onvifscan auth "http://$ip" --all --format json > "scan_${ip}.json"
    done

echo "[+] Done! Check scan_*.json files for results"
```

### MQTT Security Audit

```bash
# Scan common IoT ports for MQTT
for port in 1883 8883; do
    echo "Scanning port $port..."
    mqttscan 192.168.1.100 -p $port --format json > "mqtt_${port}.json"
done
```

### Firmware Analysis

```bash
# Extract and analyze firmware
sudo ffind firmware.bin -e -d /tmp/firmware_extracted

# Search for sensitive data
grep -r "password" /tmp/firmware_extracted/
grep -r "api_key" /tmp/firmware_extracted/
grep -r "SECRET" /tmp/firmware_extracted/
```

## Claude Code Integration

IoTHackBot includes Claude Code skills:

```
# In Claude Code
/wsdiscovery
/onvifscan http://192.168.1.100
/ffind firmware.bin
```

## Logging

### Enable Debug Logging

```python
from iothackbot.core.logger import setup_tool_logger

# Setup with file logging
logger = setup_tool_logger(
    'my_scan',
    verbose=True,
    log_file='scan.log'
)

# Use logger
logger.info("Starting scan")
logger.debug("Detailed debug info")
```

## Troubleshooting

### Permission Issues

```bash
# FFind needs sudo for filesystem operations
sudo ffind firmware.bin -e

# Network capture needs sudo
sudo iotnet -i eth0 -d 60

# Add user to dialout group for serial access
sudo usermod -a -G dialout $USER
```

### No Devices Found

```bash
# Check multicast
ip maddress show

# Check firewall
sudo iptables -L | grep 3702

# Try broadcast
wsdiscovery 255.255.255.255
```

### Connection Timeout

```bash
# Increase timeout
mqttscan 192.168.1.100 --timeout 30
onvifscan auth http://192.168.1.100 --timeout 30
```

## Best Practices

1. ✅ **Always get authorization** before scanning
2. ✅ **Start with discovery** tools (passive)
3. ✅ **Use rate limiting** for active scans
4. ✅ **Log all activities** for documentation
5. ✅ **Generate reports** for stakeholders
6. ✅ **Verify findings** manually

## Next Steps

- Read [EXAMPLES.md](docs/EXAMPLES.md) for detailed usage
- Check [CONTRIBUTING.md](CONTRIBUTING.md) for development
- See [TOOL_DEVELOPMENT_GUIDE.md](TOOL_DEVELOPMENT_GUIDE.md) for creating new tools
- Review [IMPROVEMENTS.md](IMPROVEMENTS.md) for new features

## Support

- 📝 [Open an issue](https://github.com/BrownFineSecurity/iothackbot/issues)
- 📖 [Read the docs](README.md)
- 💬 [Join discussions](https://github.com/BrownFineSecurity/iothackbot/discussions)

## Legal Disclaimer

**IMPORTANT**: This toolkit is for authorized security testing only.

- Only test systems you own or have explicit permission to test
- Respect scope and rules of engagement
- Document all activities
- Follow responsible disclosure

---

Happy Hacking (Responsibly)! 🔐
