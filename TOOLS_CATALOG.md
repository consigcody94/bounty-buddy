# Bounty Buddy - Comprehensive Tools Catalog

**Last Updated**: 2025-11-23
**Total Tools**: 60+

This document catalogs all security testing tools included in Bounty Buddy, organized by category.

---

## Table of Contents

1. [Web Application Security](#1-web-application-security) (25 tools)
2. [Cloud & Infrastructure](#2-cloud--infrastructure) (15 tools)
3. [Mobile Application Security](#3-mobile-application-security) (10 tools)
4. [IoT & Network Security](#4-iot--network-security) (10 tools)
5. [Utilities & Framework](#5-utilities--framework) (8 tools)

---

## 1. Web Application Security

### Reconnaissance & Discovery

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **subdomain-enum** | Multi-source subdomain enumeration | ✅ Existing |
| **amass** | In-depth DNS enumeration | 🔄 Integration |
| **subfinder** | Fast passive subdomain discovery | 🔄 Integration |
| **assetfinder** | Find related domains/subdomains | 🔄 Integration |
| **findomain** | Cross-platform subdomain enumerator | 📋 Planned |
| **chaos** | Subdomain data from ProjectDiscovery | 📋 Planned |

### Web Crawling & Spidering

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **gospider** | Fast web spider | 📋 Planned |
| **hakrawler** | Simple fast web crawler | 📋 Planned |
| **katana** | Next-gen crawling framework | 📋 Planned |
| **paramspider** | Parameter discovery | 📋 Planned |

### Vulnerability Scanning

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **nucleiscan** | Template-based vulnerability scanner | ✅ Mentioned in docs |
| **nuclei-templates** | Community templates for Nuclei | 📋 Planned |
| **jaeles** | Powerful vulnerability scanner | 📋 Planned |

### XSS (Cross-Site Scripting)

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **xsshunter** | XSS vulnerability detection | ✅ Mentioned in docs |
| **dalfox** | Parameter analysis & XSS scanner | 📋 Planned |
| **xsstrike** | Advanced XSS detection suite | 📋 Planned |
| **kxss** | Find reflected parameters | 📋 Planned |

### SQL Injection

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **sqlmap** | Automatic SQL injection tool | 📋 Planned |
| **ghauri** | Advanced SQL injection tool | 📋 Planned |
| **nosqlmap** | NoSQL injection scanner | 📋 Planned |

### API Security

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **apifuzz** | API endpoint fuzzing | ✅ Mentioned in docs |
| **ffuf** | Fast web fuzzer | 📋 Integration |
| **arjun** | HTTP parameter discovery | 📋 Planned |
| **kiterunner** | API & content discovery | 📋 Planned |

### Authentication & Authorization

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **idor-scanner** | Insecure Direct Object Reference | 📋 Planned |
| **authz-scanner** | Authorization testing | 📋 Planned |

### Server-Side Request Forgery (SSRF)

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **ssrfmap** | SSRF exploitation | 📋 Planned |
| **interactsh** | OOB interaction detection | 📋 Planned |

### Content Security Policy (CSP)

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **csp-evaluator** | CSP header analysis | 📋 Planned |

---

## 2. Cloud & Infrastructure

### AWS Security

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **s3scanner** | S3 bucket enumeration | 📋 Planned |
| **cloud_enum** | Multi-cloud OSINT | 📋 Planned |
| **s3-bucket-finder** | Find open S3 buckets | 📋 Planned |
| **awscli-enum** | AWS enumeration | 📋 Planned |

### DNS & Subdomain Takeover

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **subjack** | Subdomain takeover detection | 📋 Planned |
| **subzy** | Subdomain takeover checker | 📋 Planned |
| **nuclei-takeover** | Takeover templates | 📋 Planned |
| **can-i-take-over-xyz** | Takeover database | 📋 Planned |

### Cloud Misconfigurations

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **cloudsploit** | Cloud security scanner | 📋 Planned |
| **prowler** | AWS security assessment | 📋 Planned |
| **scout suite** | Multi-cloud auditing | 📋 Planned |

### SSL/TLS Analysis

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **testssl.sh** | TLS/SSL scanner | 📋 Planned |
| **sslyze** | SSL/TLS scanner | 📋 Planned |
| **sslscan** | SSL/TLS cipher scanner | 📋 Planned |

---

## 3. Mobile Application Security

### Android Security

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **mobsf** | Mobile Security Framework | 📋 Planned |
| **apktool** | APK decompilation | 📋 Planned |
| **jadx** | Dex to Java decompiler | 📋 Planned |
| **androguard** | Android app analysis | 📋 Planned |
| **qark** | Android vulnerability scanner | 📋 Planned |

### iOS Security

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **mobsf-ios** | iOS app analysis | 📋 Planned |
| **frida** | Dynamic instrumentation | 📋 Planned |
| **objection** | Runtime mobile exploration | 📋 Planned |

### Mobile API Testing

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **mitmproxy** | Interactive HTTPS proxy | 📋 Planned |
| **burp-mobile** | Mobile-specific Burp config | 📋 Planned |

---

## 4. IoT & Network Security

### IoT Protocol Testing

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **wsdiscovery** | WS-Discovery protocol scanner | ✅ Existing |
| **onvifscan** | ONVIF device scanner | ✅ Existing |
| **mqttscan** | MQTT broker testing | ✅ Existing |
| **coap-scanner** | CoAP protocol testing | 📋 Planned |
| **modbus-scanner** | Modbus protocol testing | 📋 Planned |

### Network Analysis

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **iotnet** | IoT network traffic analyzer | ✅ Existing |
| **nmap-scripts** | Advanced Nmap NSE scripts | 📋 Planned |
| **masscan** | Fast port scanner | 📋 Planned |

### Firmware Analysis

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **ffind** | Firmware filesystem finder | ✅ Existing |
| **binwalk** | Firmware analysis tool | 📋 Planned |
| **firmware-mod-kit** | Firmware extraction/modification | 📋 Planned |

---

## 5. Utilities & Framework

### Reporting & Documentation

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **report-generator** | Professional report creation | ✅ Existing |
| **severity-rater** | Taxonomy-based severity rating | 📋 Planned |
| **template-engine** | Report template system | 📋 Planned |

### Scope Management

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **scope-manager** | Interactive scope intake | ✅ NEW |
| **scope-validator** | Target validation engine | 📋 Planned |

### Automation & Orchestration

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **workflow-engine** | Multi-tool orchestration | 📋 Planned |
| **async-scanner** | High-performance scanning | ✅ Existing |

### Logging & Monitoring

| Tool | Purpose | Implementation Status |
|------|---------|---------------------|
| **logger** | Comprehensive logging | ✅ Existing |
| **activity-tracker** | Audit trail system | 📋 Planned |

---

## Tool Integration Patterns

### Pattern 1: Wrapper Integration
Tools like `sqlmap`, `nuclei`, `ffuf` will be wrapped with:
- Scope validation before execution
- Automatic result parsing
- Report generation integration
- Logging and audit trails

### Pattern 2: Native Implementation
Tools implemented directly in Python:
- Full control over functionality
- Tight integration with scope manager
- Custom output formats
- Enhanced error handling

### Pattern 3: API Integration
Cloud tools and services:
- API-based enumeration
- Rate limiting and retry logic
- Result caching
- Credential management

---

## Severity Rating Integration

All vulnerability findings will be rated using:

### Bugcrowd VRT (P1-P5 Scale)
- **P1**: Critical
- **P2**: High
- **P3**: Medium
- **P4**: Low
- **P5**: Informational

### HackerOne CVSS (0-10 Scale)
- CVSS 3.1/4.0 scoring
- Environmental metrics
- Temporal metrics

### CWE Mapping
- Common Weakness Enumeration
- Standardized vulnerability classification

---

## Tool Development Roadmap

### Phase 1: Foundation (Week 1)
- ✅ Scope management system
- ✅ Taxonomy integration
- 📋 Base tool interface
- 📋 Scope validation engine

### Phase 2: Web Tools (Week 2)
- 📋 XSS testing suite
- 📋 SQLi testing suite
- 📋 SSRF testing tools
- 📋 API security tools

### Phase 3: Cloud Tools (Week 3)
- 📋 S3 bucket enumeration
- 📋 Subdomain takeover
- 📋 DNS reconnaissance
- 📋 SSL/TLS analysis

### Phase 4: Mobile & IoT (Week 4)
- 📋 Mobile app analyzers
- 📋 Additional IoT protocols
- 📋 Firmware analysis
- 📋 Network traffic analysis

### Phase 5: Polish & Documentation (Week 5)
- 📋 Comprehensive tests
- 📋 Documentation updates
- 📋 Example workflows
- 📋 Video tutorials

---

## Sources & Attribution

### Tool Research
- [awesome-web-hacking](https://github.com/infoslack/awesome-web-hacking)
- [Bug Bounty Tools 2025](https://github.com/amrelsagaei/Bug-Bounty-Hunting-Methodology-2025)
- [vavkamil/awesome-bugbounty-tools](https://github.com/vavkamil/awesome-bugbounty-tools)

### Taxonomies
- [Bugcrowd VRT](https://github.com/bugcrowd/vulnerability-rating-taxonomy)
- [HackerOne CVSS](https://docs.hackerone.com/en/articles/8495674-severity)

### Platform Documentation
- HackerOne: https://docs.hackerone.com
- Bugcrowd: https://docs.bugcrowd.com
- Intigriti: https://docs.intigriti.com
- YesWeHack: https://docs.yeswehack.com

---

**Note**: This is a living document. Tools will be added incrementally based on:
1. Community demand
2. Platform popularity
3. Testing effectiveness
4. Maintenance feasibility
