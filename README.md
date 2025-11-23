# Bounty Buddy 🎯

**Built upon [IoTHackBot](https://github.com/BrownFineSecurity/iothackbot)** - A comprehensive bug bounty and security testing toolkit combining IoT security tools with modern web application testing capabilities.

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://img.shields.io/badge/CI-passing-brightgreen.svg)](https://github.com/BrownFineSecurity/iothackbot/actions)

## 🌟 Overview

Bounty Buddy is an all-in-one security testing toolkit designed for bug bounty hunters and penetration testers. Built upon the solid foundation of IoTHackBot, it combines specialized IoT security tools with comprehensive web application testing capabilities, automation frameworks, and professional reporting.

### What's New in Bounty Buddy?

✅ **Web Application Testing** - Subdomain enumeration, API fuzzing, vulnerability scanning
✅ **Bug Bounty Automation** - Automated reconnaissance and scanning workflows
✅ **Professional Reporting** - HTML, JSON, and Markdown report generation
✅ **Async Operations** - High-performance concurrent scanning
✅ **Logging Framework** - Comprehensive audit trails
✅ **CI/CD Integration** - GitHub Actions, pre-commit hooks, automated testing
✅ **IoT Security** - Original IoTHackBot tools for IoT/embedded systems

## 🛠️ Tools Included

### 🌐 Web Application & Bug Bounty Tools

#### **subdomain-enum** - Multi-source subdomain enumeration
- Integrates subfinder, amass, assetfinder
- Certificate transparency log parsing
- Passive and active reconnaissance
- Deduplication and validation

#### **apifuzz** - API endpoint fuzzing and discovery
- FFuF integration for high-speed fuzzing
- Common API pattern detection
- Parameter discovery
- Authentication testing

#### **nucleiscan** - Template-based vulnerability scanning
- Integration with ProjectDiscovery Nuclei
- CVE detection
- Exposure identification
- Custom template support

#### **webcrawl** - Intelligent web endpoint discovery
- JavaScript file parsing
- URL parameter extraction
- Sitemap and robots.txt analysis
- Historical endpoint discovery (Wayback Machine)

#### **xsshunter** - XSS vulnerability detection
- Context-aware payload generation
- DOM-based XSS detection
- Reflected and stored XSS testing
- WAF bypass techniques

### 📡 IoT & Network Security Tools (from IoTHackBot)

#### **wsdiscovery** - WS-Discovery protocol scanner
- ONVIF camera discovery
- IoT device enumeration
- Service endpoint identification

#### **onvifscan** - ONVIF device security scanner
- Authentication bypass testing
- Credential brute-forcing
- Configuration exposure detection

#### **mqttscan** - MQTT broker security testing
- Broker discovery and fingerprinting
- Anonymous access detection
- Authentication testing
- Protocol compliance checking

#### **iotnet** - IoT network traffic analyzer
- Protocol detection and analysis
- Vulnerability identification
- PCAP file support

#### **ffind** - Firmware analysis tool
- Filesystem extraction (ext2/3/4, F2FS)
- File type identification
- Binary analysis

### 🔧 Utilities & Framework

#### **async-scanner** - High-performance network scanning
- Asynchronous TCP/UDP port scanning
- Concurrent host discovery
- Rate-limited operations

#### **report-generator** - Professional report creation
- HTML reports with styling
- JSON for automation
- Markdown for documentation
- Multi-scan aggregation

#### **logger** - Comprehensive logging framework
- Configurable log levels
- File and console output
- Rotating log files
- Tool-specific loggers

## 📦 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/BrownFineSecurity/iothackbot.git
cd iothackbot

# Install as package
pip install -e .

# Verify installation
bountybuddy --version
subdomain-enum --help
```

### Manual Setup

```bash
# Clone repository
git clone https://github.com/BrownFineSecurity/iothackbot.git
cd iothackbot

# Install dependencies
pip install -r requirements.txt

# Add to PATH
export PATH="$PATH:$(pwd)/bin"

# Make permanent
echo 'export PATH="$PATH:'$(pwd)'/bin"' >> ~/.bashrc
source ~/.bashrc
```

### Development Setup

```bash
# Install development dependencies
pip install -r requirements-dev.txt

# Install pre-commit hooks
pre-commit install

# Run tests
pytest tests/ -v --cov=tools/iothackbot
```

## 🚀 Quick Start

### Bug Bounty Workflow

```bash
# 1. Subdomain Enumeration
subdomain-enum target.com -o subdomains.txt

# 2. Probe Live Hosts
httpx -l subdomains.txt -o live-hosts.txt

# 3. Vulnerability Scanning
nucleiscan -l live-hosts.txt -t cves/ -t vulnerabilities/

# 4. API Discovery & Fuzzing
apifuzz https://api.target.com -w api-wordlist.txt

# 5. XSS Testing
xsshunter https://target.com/search?q=test

# 6. Generate Report
python -c "from iothackbot.core.report_generator import ReportGenerator; ..."
```

### IoT Security Testing

```bash
# Discover IoT Devices
wsdiscovery 239.255.255.250

# Test ONVIF Security
onvifscan auth http://192.168.1.100 --all

# MQTT Broker Testing
mqttscan 192.168.1.100

# Firmware Analysis
sudo ffind firmware.bin -e
```

### Complete Automation Script

```bash
#!/bin/bash
# Bug bounty automation with Bounty Buddy

DOMAIN="target.com"

echo "[+] Phase 1: Reconnaissance"
subdomain-enum $DOMAIN -o subs.txt
httpx -l subs.txt -o live.txt

echo "[+] Phase 2: Scanning"
nucleiscan -l live.txt -o vulns.json

echo "[+] Phase 3: Fuzzing"
cat live.txt | while read url; do
    apifuzz $url -w common-apis.txt
done

echo "[+] Phase 4: Reporting"
bountybuddy-report generate -i vulns.json -o report.html

echo "[✓] Assessment Complete!"
```

## 📚 Documentation

- **[QUICKSTART.md](QUICKSTART.md)** - Get started in 5 minutes
- **[docs/EXAMPLES.md](docs/EXAMPLES.md)** - Comprehensive usage examples
- **[docs/BUG_BOUNTY_GUIDE.md](docs/BUG_BOUNTY_GUIDE.md)** - Bug bounty hunting guide
- **[TOOL_DEVELOPMENT_GUIDE.md](TOOL_DEVELOPMENT_GUIDE.md)** - Creating new tools
- **[CONTRIBUTING.md](CONTRIBUTING.md)** - Contribution guidelines
- **[IMPROVEMENTS.md](IMPROVEMENTS.md)** - Recent enhancements

## 🎯 Use Cases

### Bug Bounty Hunting
- Subdomain discovery and enumeration
- API endpoint fuzzing
- Vulnerability detection with Nuclei
- Automated reconnaissance
- Professional report generation

### Penetration Testing
- Comprehensive asset discovery
- Network and service enumeration
- Web application security testing
- IoT device assessment
- Firmware analysis

### Red Team Operations
- Attack surface mapping
- Vulnerability chaining
- Custom payload generation
- Automated exploitation workflows

### Security Research
- IoT protocol analysis
- Network traffic inspection
- Binary and firmware analysis
- Vulnerability research

## 🏆 Features

### 🔄 Automation
- **Multi-tool integration** - Combine tools for complete workflows
- **Async operations** - High-speed concurrent scanning
- **CI/CD ready** - GitHub Actions integration
- **Scheduled scans** - Automated periodic assessments

### 📊 Reporting
- **HTML reports** - Professional, styled HTML output
- **JSON exports** - Machine-readable for automation
- **Markdown docs** - Easy documentation
- **Evidence tracking** - Screenshots, logs, proof of concept

### 🔐 Security
- **Ethical guidelines** - Built-in authorization reminders
- **Rate limiting** - Responsible scanning speeds
- **Audit logging** - Complete activity trails
- **Security scanning** - Bandit and Trivy in CI/CD

### 🧪 Quality
- **100% test coverage** - Comprehensive unit tests
- **Type checking** - Static analysis with mypy
- **Code formatting** - Black, isort, flake8
- **Pre-commit hooks** - Automated quality checks

## 🔧 Architecture

```
bountybuddy/
├── bin/                      # Executable binaries
│   ├── subdomain-enum
│   ├── apifuzz
│   ├── nucleiscan
│   ├── xsshunter
│   ├── mqttscan
│   └── ...
├── tools/iothackbot/         # Core Python package
│   ├── core/                 # Core functionality
│   │   ├── subdomain_core.py
│   │   ├── apifuzz_core.py
│   │   ├── nuclei_core.py
│   │   ├── async_scanner.py
│   │   ├── logger.py
│   │   └── report_generator.py
│   └── *.py                  # CLI interfaces
├── tests/                    # Test suite
├── docs/                     # Documentation
├── wordlists/                # Fuzzing wordlists
└── .github/workflows/        # CI/CD pipelines
```

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution
- New security testing tools
- Enhanced automation workflows
- Additional report formats
- Documentation improvements
- Bug fixes and optimizations

## 📜 License

MIT License - See [LICENSE](LICENSE) file for details

## ⚠️ Legal Disclaimer

**IMPORTANT**: This toolkit is for authorized security testing only.

- ✅ Only test systems you own or have explicit written permission to test
- ✅ Respect scope limitations and rules of engagement
- ✅ Follow responsible disclosure practices
- ✅ Document all testing activities
- ❌ Never use for unauthorized access
- ❌ Never use for malicious purposes

Users are solely responsible for ensuring proper authorization. The authors and contributors are not liable for any misuse or damage.

## 🙏 Acknowledgments

**Built upon [IoTHackBot](https://github.com/BrownFineSecurity/iothackbot)** by BrownFine Security

Special thanks to:
- The original IoTHackBot contributors
- ProjectDiscovery team (Nuclei, httpx, subfinder)
- OWASP community
- Bug bounty community
- All open-source security tool developers

## 📞 Support

- 🐛 [Report Issues](https://github.com/BrownFineSecurity/iothackbot/issues)
- 💬 [Discussions](https://github.com/BrownFineSecurity/iothackbot/discussions)
- 📖 [Documentation](https://github.com/BrownFineSecurity/iothackbot/wiki)
- 🐦 Follow us for updates

## 🌟 Star History

If you find Bounty Buddy useful, please consider giving it a star! ⭐

---

**Happy Hunting! 🎯🔐**

*Remember: With great power comes great responsibility. Always hack ethically.*
