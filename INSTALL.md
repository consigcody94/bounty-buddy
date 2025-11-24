# Bounty Buddy - Installation Guide

Complete installation guide for Bounty Buddy and all external dependencies.

---

## Table of Contents

1. [Quick Start](#quick-start)
2. [Prerequisites](#prerequisites)
3. [Core Installation](#core-installation)
4. [External Tools](#external-tools)
5. [Dependency Checker](#dependency-checker)
6. [Platform-Specific Instructions](#platform-specific-instructions)
7. [Verification](#verification)
8. [Troubleshooting](#troubleshooting)

---

## Quick Start

```bash
# 1. Clone repository
git clone https://github.com/consigcody94/bounty-buddy.git
cd bounty-buddy

# 2. Install Python dependencies
pip install -r requirements.txt
pip install -e .

# 3. Check and install external tools
python3 scripts/check_dependencies.py

# 4. Verify installation
bountybuddy-scope --help
subdomain-enum --help
```

---

## Prerequisites

### Required

- **Python 3.8+**
- **Go 1.19+** (for many security tools)
- **Git**
- **pip** (Python package manager)

### Recommended

- **Docker** (for MobSF and other containerized tools)
- **Node.js 16+** (for some web security tools)
- **Rust** (for fast scanners like RustScan)

---

## Core Installation

### 1. Install Bounty Buddy

```bash
# Clone the repository
git clone https://github.com/consigcody94/bounty-buddy.git
cd bounty-buddy

# Install Python dependencies
pip install -r requirements.txt

# Install in development mode
pip install -e .

# Or install in production mode
pip install .
```

### 2. Add to PATH

Add bounty-buddy binaries to your PATH:

```bash
# For bash/zsh
echo 'export PATH="$PATH:'$(pwd)'/bin"' >> ~/.bashrc
source ~/.bashrc

# For fish
echo 'set -gx PATH $PATH '$(pwd)'/bin' >> ~/.config/fish/config.fish
```

---

## External Tools

Bounty Buddy integrates with 30+ external security tools. Install as needed:

### Web Application Security

```bash
# Nuclei - Template-based scanner (REQUIRED)
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Dalfox - XSS scanner
go install github.com/hahwul/dalfox/v2@latest

# SQLMap - SQL injection
sudo apt-get install sqlmap  # Linux
brew install sqlmap          # macOS

# FFuf - Web fuzzer
go install github.com/ffuf/ffuf@latest

# HTTPx - HTTP toolkit
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
```

### Reconnaissance

```bash
# Subfinder - Subdomain discovery (REQUIRED)
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass - DNS enumeration
go install -v github.com/owasp-amass/amass/v4/...@master

# Assetfinder
go install github.com/tomnomnom/assetfinder@latest

# Findomain
curl -LO https://github.com/findomain/findomain/releases/latest/download/findomain-linux.zip
unzip findomain-linux.zip
chmod +x findomain
sudo mv findomain /usr/local/bin/
```

### Cloud Security

```bash
# Subjack - Subdomain takeover
go install github.com/haccer/subjack@latest

# S3Scanner - S3 bucket enumeration
pip3 install s3scanner

# CloudSploit
npm install -g cloudsploit

# Prowler - AWS security
pip3 install prowler
```

### Mobile Security

```bash
# APKTool
sudo apt-get install apktool  # Linux
brew install apktool           # macOS

# JADX
sudo apt-get install jadx      # Linux
brew install jadx              # macOS

# MobSF (Docker)
docker pull opensecurity/mobile-security-framework-mobsf
```

### Network & SSL/TLS

```bash
# Nmap (REQUIRED)
sudo apt-get install nmap  # Linux
brew install nmap          # macOS

# Masscan
sudo apt-get install masscan  # Linux
brew install masscan          # macOS

# TestSSL.sh
git clone --depth 1 https://github.com/drwetter/testssl.sh.git
cd testssl.sh
chmod +x testssl.sh
sudo ln -s $(pwd)/testssl.sh /usr/local/bin/testssl.sh
```

---

## Dependency Checker

Use the automated dependency checker to install all tools:

```bash
# Check what's installed and missing
python3 scripts/check_dependencies.py

# Auto-install missing tools
python3 scripts/check_dependencies.py
# Follow prompts to install required and optional tools
```

The script will:
- ✅ Check which tools are installed
- ❌ List missing required tools
- ⚠️ List missing optional tools
- 📥 Offer to install missing tools automatically

---

## Platform-Specific Instructions

### Ubuntu/Debian

```bash
# Update package list
sudo apt-get update

# Install prerequisites
sudo apt-get install -y python3 python3-pip golang-go git nmap

# Install Bounty Buddy
pip3 install -r requirements.txt
pip3 install -e .

# Install external tools
python3 scripts/check_dependencies.py
```

### macOS

```bash
# Install Homebrew if not already installed
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Install prerequisites
brew install python go git nmap

# Install Bounty Buddy
pip3 install -r requirements.txt
pip3 install -e .

# Install external tools
python3 scripts/check_dependencies.py
```

### Arch Linux

```bash
# Install prerequisites
sudo pacman -S python python-pip go git nmap

# Install Bounty Buddy
pip install -r requirements.txt
pip install -e .

# Install external tools (many available in AUR)
yay -S subfinder nuclei ffuf amass
```

### Kali Linux

```bash
# Many tools pre-installed on Kali
# Install Bounty Buddy
pip3 install -r requirements.txt
pip3 install -e .

# Check for missing tools
python3 scripts/check_dependencies.py
```

---

## Verification

### Test Core Installation

```bash
# Test Python package
python3 -c "from iothackbot.core.scope import ScopeManager; print('✅ Core installed')"

# Test CLI tools
bountybuddy-scope --help
subdomain-enum --help
mqttscan --help
```

### Test External Tools

```bash
# Test Go tools
nuclei -version
subfinder -version
dalfox version
ffuf -V

# Test Python tools
sqlmap --version
s3scanner --version

# Test system tools
nmap --version
```

### Run Example Scan

```bash
# Setup a test scope
bountybuddy-scope setup
# Follow prompts to configure scope for example.com

# Run subdomain enumeration
subdomain-enum example.com -o test-results.txt

# View results
cat test-results.txt
```

---

## Troubleshooting

### Go Tools Not Found

If Go tools aren't in PATH after installation:

```bash
# Add Go bin to PATH
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc
```

### Permission Denied

```bash
# Make binaries executable
chmod +x bin/*

# Or for specific tool
chmod +x bin/bountybuddy-scope
```

### Python Module Not Found

```bash
# Ensure you're using the right Python
which python3
which pip3

# Reinstall in development mode
pip3 install -e .
```

### Tool Installation Fails

```bash
# Update package manager
sudo apt-get update        # Linux
brew update                # macOS

# Try manual installation
# See tool-specific sections above
```

### Docker Issues (MobSF)

```bash
# Start Docker service
sudo systemctl start docker  # Linux
open -a Docker              # macOS

# Pull image again
docker pull opensecurity/mobile-security-framework-mobsf

# Run container
docker run -it --rm -p 8000:8000 opensecurity/mobile-security-framework-mobsf:latest
```

---

## Minimal Installation

For a minimal working installation (required tools only):

```bash
# Core
pip install -r requirements.txt
pip install -e .

# Required external tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
sudo apt-get install nmap  # or brew install nmap
```

---

## Updating

```bash
# Update Bounty Buddy
cd bounty-buddy
git pull origin main
pip install -e . --upgrade

# Update external tools
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
# ... repeat for other Go tools

# Update Nuclei templates
nuclei -update-templates
```

---

## Next Steps

After installation:

1. **Configure Scope**: `bountybuddy-scope setup`
2. **Read Documentation**: See [README.md](README.md) and [QUICKSTART.md](QUICKSTART.md)
3. **Run Tests**: `pytest tests/ -v`
4. **Try Examples**: See [docs/EXAMPLES.md](docs/EXAMPLES.md)

---

## Support

- 🐛 [Report Issues](https://github.com/consigcody94/bounty-buddy/issues)
- 💬 [Discussions](https://github.com/consigcody94/bounty-buddy/discussions)
- 📖 [Documentation](https://github.com/consigcody94/bounty-buddy/wiki)

---

**Remember**: Only test systems you own or have explicit written permission to test!
