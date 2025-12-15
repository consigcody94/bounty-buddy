<div align="center">

<!-- Animated Header -->
<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=18,20,22&height=200&section=header&text=🎯%20BOUNTY%20BUDDY&fontSize=70&fontColor=fff&animation=twinkling&fontAlignY=35&desc=All-In-One%20Bug%20Bounty%20%26%20Security%20Testing%20Toolkit&descAlignY=55&descSize=18"/>

<br/>

<!-- Badges Row 1 -->
<p>
<a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge" alt="License"/></a>
<a href="#"><img src="https://img.shields.io/badge/Python-3.8+-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python"/></a>
<a href="#"><img src="https://img.shields.io/badge/Security-Testing-ff6b6b?style=for-the-badge" alt="Security"/></a>
</p>

<!-- Badges Row 2 -->
<p>
<img src="https://img.shields.io/badge/Subdomain_Enum-✓-00d4aa?style=flat-square" alt="Subdomain"/>
<img src="https://img.shields.io/badge/API_Fuzzing-✓-3178c6?style=flat-square" alt="API"/>
<img src="https://img.shields.io/badge/Nuclei_Scan-✓-F7931E?style=flat-square" alt="Nuclei"/>
<img src="https://img.shields.io/badge/XSS_Hunter-✓-9b59b6?style=flat-square" alt="XSS"/>
<img src="https://img.shields.io/badge/IoT_Security-✓-e74c3c?style=flat-square" alt="IoT"/>
</p>

<br/>

<!-- Tagline Box -->
<table>
<tr>
<td>

```
╔══════════════════════════════════════════════════════════════════════════════╗
║                                                                              ║
║   🎯  BOUNTY BUDDY: Hunt bugs like a pro                                    ║
║                                                                              ║
║       🌐  Web App Testing - Subdomain, API fuzzing, XSS detection           ║
║       📡  IoT Security - MQTT, ONVIF, firmware analysis                      ║
║       🔒  Nuclei Integration - CVE detection, vulnerability scanning         ║
║       📊  Professional Reports - HTML, JSON, Markdown output                 ║
║                                                                              ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

</td>
</tr>
</table>

<br/>

<!-- Quick Links -->
[**🚀 Quick Start**](#-quick-start) · [**🛠 Tools**](#-tools-included) · [**📚 Docs**](#-documentation) · [**⚠️ Legal**](#-legal-disclaimer)

<br/>

</div>

---

<br/>

## 🎯 The Problem vs Solution

<table>
<tr>
<td width="50%">

### ❌ The Problem
```
Manual reconnaissance:
├── Run subfinder
├── Run amass
├── Deduplicate results
├── Probe live hosts
├── Run vulnerability scans
├── Generate report
└── Hours of context switching
```

</td>
<td width="50%">

### ✅ The Solution
```bash
$ bountybuddy target.com

✓ Subdomains: 847 found
✓ Live hosts: 234 active
✓ Vulnerabilities: 12 found
  - 2 Critical (SQLi, RCE)
  - 4 High (XSS, SSRF)
  - 6 Medium
✓ Report: bounty-report.html

🎯 Happy hunting!
```

</td>
</tr>
</table>

<br/>

---

<br/>

## 🛠 Tools Included

```
┌─────────────────────────────────────────────────────────────────┐
│                    WEB APPLICATION TOOLS                        │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  🔍  SUBDOMAIN-ENUM                                             │
│      Multi-source enumeration (subfinder, amass, assetfinder)  │
│                                                                 │
│  🔧  APIFUZZ                                                    │
│      API endpoint discovery and fuzzing with FFuF               │
│                                                                 │
│  🎯  NUCLEISCAN                                                 │
│      Template-based vulnerability detection                     │
│                                                                 │
│  🕷️  WEBCRAWL                                                   │
│      JavaScript parsing, URL extraction, Wayback Machine        │
│                                                                 │
│  💉  XSSHUNTER                                                  │
│      Context-aware XSS detection with WAF bypass               │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                    IoT SECURITY TOOLS                           │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  📡  WSDISCOVERY                                                │
│      ONVIF camera and IoT device enumeration                    │
│                                                                 │
│  📹  ONVIFSCAN                                                  │
│      Authentication bypass and credential testing               │
│                                                                 │
│  📨  MQTTSCAN                                                   │
│      MQTT broker security and anonymous access testing          │
│                                                                 │
│  🔬  FFIND                                                      │
│      Firmware extraction and binary analysis                    │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

<br/>

---

<br/>

## 🚀 Quick Start

### Installation

```bash
# Clone and install
git clone https://github.com/consigcody94/bounty-buddy.git
cd bounty-buddy
pip install -e .

# Verify
bountybuddy --version
```

### Bug Bounty Workflow

```bash
# 1. Subdomain Enumeration
subdomain-enum target.com -o subdomains.txt

# 2. Probe Live Hosts
httpx -l subdomains.txt -o live-hosts.txt

# 3. Vulnerability Scanning
nucleiscan -l live-hosts.txt -t cves/ -t vulnerabilities/

# 4. API Fuzzing
apifuzz https://api.target.com -w api-wordlist.txt

# 5. XSS Testing
xsshunter https://target.com/search?q=test

# 6. Generate Report
bountybuddy-report generate -i vulns.json -o report.html
```

<br/>

---

<br/>

## 📊 Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                    BOUNTY BUDDY ARCHITECTURE                    │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  bountybuddy/                                                   │
│  ├── bin/                    # CLI executables                  │
│  │   ├── subdomain-enum                                        │
│  │   ├── apifuzz                                               │
│  │   ├── nucleiscan                                            │
│  │   ├── xsshunter                                             │
│  │   └── mqttscan                                              │
│  │                                                              │
│  ├── tools/iothackbot/       # Core package                    │
│  │   ├── core/               # Scanning engines                │
│  │   │   ├── subdomain_core.py                                 │
│  │   │   ├── async_scanner.py                                  │
│  │   │   └── report_generator.py                               │
│  │   └── *.py                # CLI interfaces                  │
│  │                                                              │
│  ├── tests/                  # Test suite                      │
│  ├── wordlists/              # Fuzzing dictionaries            │
│  └── .github/workflows/      # CI/CD pipelines                 │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

<br/>

---

<br/>

## 📚 Documentation

<div align="center">

| Document | Description |
|:---------|:------------|
| **[QUICKSTART.md](QUICKSTART.md)** | Get started in 5 minutes |
| **[BUG_BOUNTY_GUIDE.md](docs/BUG_BOUNTY_GUIDE.md)** | Complete hunting guide |
| **[TOOL_DEVELOPMENT_GUIDE.md](TOOL_DEVELOPMENT_GUIDE.md)** | Create custom tools |
| **[CONTRIBUTING.md](CONTRIBUTING.md)** | Contribution guidelines |

</div>

<br/>

---

<br/>

## ⚠️ Legal Disclaimer

```
┌─────────────────────────────────────────────────────────────────┐
│                    IMPORTANT NOTICE                             │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  This toolkit is for AUTHORIZED security testing ONLY.         │
│                                                                 │
│  ✅  Test systems you own or have written permission           │
│  ✅  Respect scope limitations and rules of engagement         │
│  ✅  Follow responsible disclosure practices                    │
│  ✅  Document all testing activities                            │
│                                                                 │
│  ❌  Never use for unauthorized access                          │
│  ❌  Never use for malicious purposes                           │
│                                                                 │
│  Users are solely responsible for proper authorization.         │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

<br/>

---

<br/>

## 🙏 Acknowledgments

**Built upon [IoTHackBot](https://github.com/BrownFineSecurity/iothackbot)** by BrownFine Security

Special thanks to ProjectDiscovery (Nuclei, httpx, subfinder), OWASP community, and all open-source security tool developers.

<br/>

---

<br/>

## 📄 License

<div align="center">

**MIT License** © Bounty Buddy

</div>

<br/>

---

<div align="center">

<img src="https://capsule-render.vercel.app/api?type=waving&color=gradient&customColorList=18,20,22&height=100&section=footer"/>

<br/>

**🎯 Bounty Buddy** — *Hunt bugs like a pro*

<br/>

*"With great power comes great responsibility. Always hack ethically."*

<br/>

[⬆ Back to Top](#-bounty-buddy)

</div>
