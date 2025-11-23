# Bounty Buddy - Complete Bug Bounty Hunting Guide

**Built upon IoTHackBot** - A comprehensive guide to bug bounty hunting with Bounty Buddy toolkit.

## Table of Contents

1. [Getting Started](#getting-started)
2. [Bug Bounty Methodology](#bug-bounty-methodology)
3. [Tool-by-Tool Guide](#tool-by-tool-guide)
4. [Complete Workflows](#complete-workflows)
5. [OWASP Top 10 Testing](#owasp-top-10-testing)
6. [API Security Testing](#api-security-testing)
7. [IoT Device Testing](#iot-device-testing)
8. [Reporting Guidelines](#reporting-guidelines)
9. [Tips & Tricks](#tips-and-tricks)

---

## Getting Started

### Prerequisites

```bash
# Install Bounty Buddy
git clone https://github.com/BrownFineSecurity/iothackbot.git
cd iothackbot
pip install -e .

# Install external dependencies (optional but recommended)
# Subfinder
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest

# Amass
go install -v github.com/owasp-amass/amass/v4/...@master

# httpx
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest

# Nuclei
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# FFuF
go install github.com/ffuf/ffuf/v2@latest
```

### Your First Bug Bounty

```bash
# 1. Choose a target from a bug bounty platform
#    - HackerOne, Bugcrowd, Intigriti, YesWeHack, etc.
#    - Read the program policy carefully!

# 2. Run basic reconnaissance
subdomain-enum target.com -o subs.txt

# 3. Probe for live hosts
httpx -l subs.txt -o live.txt

# 4. Scan for vulnerabilities
nucleiscan -l live.txt -t cves/ -o vulns.json

# 5. Manual testing (most important!)
#    - Test authentication/authorization
#    - Test input validation
#    - Test business logic

# 6. Report findings
#    - Clear title and description
#    - Steps to reproduce
#    - Impact assessment
#    - Remediation suggestions
```

---

## Bug Bounty Methodology

### Phase 1: Reconnaissance (Passive)

**Goal**: Gather information without touching the target

#### 1.1 Subdomain Enumeration

```bash
# Use Bounty Buddy subdomain enumeration
subdomain-enum target.com -o subdomains.txt

# Manual crt.sh query
curl -s "https://crt.sh/?q=%.target.com&output=json" | \
    jq -r '.[].name_value' | sort -u | tee crtsh-subs.txt

# Combine all sources
cat subdomains.txt crtsh-subs.txt | sort -u > all-subs.txt
```

#### 1.2 OSINT Gathering

```bash
# theHarvester for emails and subdomains
theHarvester -d target.com -b all -f harvest-results

# Shodan search
shodan search "hostname:target.com"

# GitHub code search
# Search for: "target.com" api_key
# Search for: "target.com" password
# Search for: "target.com" token
```

#### 1.3 Historical Data

```bash
# Wayback Machine URLs
waybackurls target.com | tee wayback-urls.txt

# GetAllUrls (gau)
gau target.com | tee gau-urls.txt

# Combine and filter
cat wayback-urls.txt gau-urls.txt | sort -u > all-urls.txt
```

### Phase 2: Reconnaissance (Active)

**Goal**: Actively probe and enumerate the target

#### 2.1 Live Host Discovery

```bash
# Probe for HTTP/HTTPS services
httpx -l all-subs.txt \
    -title \
    -status-code \
    -tech-detect \
    -o live-hosts.txt
```

#### 2.2 Port Scanning

```bash
# Fast port scan with RustScan
rustscan -a target.com -- -sV -sC

# Or use nmap two-phase approach
# Phase 1: Fast port discovery
sudo nmap -p- target.com -oA nmap-portscan

# Phase 2: Service detection on open ports
nmap -p 80,443,8080,8443 -sV -sC target.com -oA nmap-services
```

#### 2.3 Technology Detection

```bash
# Detect technologies
whatweb target.com

# Or with httpx
httpx -l live-hosts.txt -tech-detect
```

### Phase 3: Vulnerability Discovery

**Goal**: Identify security vulnerabilities

#### 3.1 Automated Scanning

```bash
# Nuclei vulnerability scanning
nuclei -l live-hosts.txt \
    -t cves/ \
    -t vulnerabilities/ \
    -t exposures/ \
    -o nuclei-results.json

# Test for subdomain takeover
nuclei -l all-subs.txt -t takeovers/ -o takeover-results.txt
```

#### 3.2 Directory & Endpoint Fuzzing

```bash
# Directory fuzzing with ffuf
ffuf -u https://target.com/FUZZ \
    -w /usr/share/seclists/Discovery/Web-Content/common.txt \
    -mc 200,301,302,403 \
    -o ffuf-dirs.json

# API endpoint fuzzing
ffuf -u https://api.target.com/FUZZ \
    -w api-endpoints.txt \
    -mc 200 \
    -o api-fuzz.json
```

#### 3.3 Parameter Discovery

```bash
# Parameter fuzzing
ffuf -u https://target.com/page?FUZZ=test \
    -w parameters.txt \
    -mc 200 \
    -fw 100  # Filter by word count

# Arjun parameter discovery
arjun -u https://target.com/endpoint
```

### Phase 4: Manual Testing

**Goal**: Deep dive into application logic

#### 4.1 Authentication Testing

```bash
# Test endpoints without authentication
curl -X GET https://api.target.com/users

# Test with different user roles
# Low-privilege user accessing admin endpoints
curl -X GET https://api.target.com/admin/users \
    -H "Authorization: Bearer USER_TOKEN"
```

#### 4.2 Authorization Testing (IDOR)

```python
#!/usr/bin/env python3
"""IDOR Testing Script"""
import requests

base_url = "https://target.com/api/users/"
headers = {"Authorization": "Bearer YOUR_TOKEN"}

for user_id in range(1, 1000):
    r = requests.get(f"{base_url}{user_id}", headers=headers)
    if r.status_code == 200:
        print(f"[+] Accessible user ID: {user_id}")
        print(f"    Data: {r.json()}")
```

#### 4.3 Input Validation Testing

```bash
# SQL Injection
sqlmap -u "https://target.com/page?id=1" --dbs --batch

# XSS Testing
# Use xsshunter or manual payloads:
# <script>alert(document.domain)</script>
# <img src=x onerror=alert(1)>
# "><svg/onload=alert(1)>

# XXE Testing
# <?xml version="1.0"?>
# <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
# <foo>&xxe;</foo>
```

### Phase 5: Exploitation & Validation

**Goal**: Prove the vulnerability and assess impact

```bash
# Document everything:
# 1. Request/response (Burp Suite)
# 2. Screenshots
# 3. Video PoC (if complex)
# 4. Impact assessment

# Use Burp Suite for complex exploitation
# Use custom scripts for automation
# Always test in a safe manner!
```

### Phase 6: Reporting

**Goal**: Professional vulnerability report

See [Reporting Guidelines](#reporting-guidelines) section below.

---

## Tool-by-Tool Guide

### Subdomain Enumeration

```bash
# Basic usage
subdomain-enum target.com

# Save to file
subdomain-enum target.com -o subdomains.txt

# JSON output
subdomain-enum target.com --format json > subs.json

# Disable specific sources
subdomain-enum target.com --no-amass --no-subfinder

# Active reconnaissance (be careful!)
subdomain-enum target.com --active
```

### MQTT Scanner (IoT Testing)

```bash
# Test single broker
mqttscan 192.168.1.100

# Custom port
mqttscan 192.168.1.100 -p 8883

# No authentication testing
mqttscan 192.168.1.100 --no-auth-test

# JSON output
mqttscan 192.168.1.100 --format json
```

### ONVIF Scanner (IP Camera Testing)

```bash
# Authentication bypass testing
onvifscan auth http://192.168.1.100

# Comprehensive testing
onvifscan auth http://192.168.1.100 --all

# Brute force (use responsibly!)
onvifscan brute http://192.168.1.100

# Custom wordlists
onvifscan brute http://192.168.1.100 \
    --usernames users.txt \
    --passwords pass.txt
```

### WS-Discovery (Device Discovery)

```bash
# Discover ONVIF cameras
wsdiscovery 239.255.255.250

# Verbose output
wsdiscovery 239.255.255.250 -v

# JSON output
wsdiscovery 239.255.255.250 --format json
```

---

## Complete Workflows

### Workflow 1: Web Application Bug Bounty

```bash
#!/bin/bash
# Complete web application assessment

TARGET="target.com"
OUTDIR="bounty-$(date +%Y%m%d)"
mkdir -p $OUTDIR && cd $OUTDIR

echo "[+] Phase 1: Subdomain Enumeration"
subdomain-enum $TARGET -o subdomains.txt

echo "[+] Phase 2: HTTP Probing"
httpx -l subdomains.txt \
    -title \
    -status-code \
    -tech-detect \
    -json \
    -o httpx-results.json

# Extract live URLs
cat httpx-results.json | jq -r '.url' > live-urls.txt

echo "[+] Phase 3: Directory Fuzzing"
cat live-urls.txt | while read url; do
    echo "Fuzzing: $url"
    ffuf -u "$url/FUZZ" \
        -w /usr/share/seclists/Discovery/Web-Content/common.txt \
        -mc 200,301,302,403 \
        -o "ffuf-$(echo $url | md5sum | cut -d' ' -f1).json" \
        -json
done

echo "[+] Phase 4: Vulnerability Scanning"
nuclei -l live-urls.txt \
    -t cves/ \
    -t vulnerabilities/ \
    -t exposures/ \
    -json \
    -o nuclei-results.json

echo "[+] Phase 5: URL Collection"
cat live-urls.txt | waybackurls | tee wayback.txt
cat live-urls.txt | gau | tee gau.txt
cat wayback.txt gau.txt | sort -u > all-urls.txt

echo "[+] Phase 6: Parameter Discovery"
cat all-urls.txt | grep "=" | unfurl keys | sort -u > parameters.txt

echo "[+] Assessment Complete!"
echo "[*] Results saved in: $OUTDIR"
```

### Workflow 2: API Security Testing

```bash
#!/bin/bash
# API security assessment

API_URL="https://api.target.com"

echo "[+] Phase 1: Endpoint Discovery"
# Crawl API documentation
katana -u $API_URL -d 3 -jc -o api-endpoints.txt

# Fuzz common API paths
ffuf -u "$API_URL/api/FUZZ" \
    -w api-wordlist.txt \
    -mc 200,401,403 \
    -o api-fuzz.json

echo "[+] Phase 2: Authentication Testing"
# Test without credentials
curl -X GET "$API_URL/api/users" | jq .

# Test with low-privilege user
curl -X GET "$API_URL/api/admin/users" \
    -H "Authorization: Bearer USER_TOKEN" | jq .

echo "[+] Phase 3: IDOR Testing"
# See Python script in manual testing section

echo "[+] Phase 4: Rate Limiting"
for i in {1..1000}; do
    curl -X GET "$API_URL/api/endpoint" -w "%{http_code}\n" -o /dev/null -s
done | sort | uniq -c

echo "[+] Phase 5: Input Validation"
# Test for SQL injection
sqlmap -u "$API_URL/api/users?id=1" --dbs --batch

echo "[+] API Assessment Complete!"
```

### Workflow 3: IoT Device Assessment

```bash
#!/bin/bash
# IoT device security assessment

NETWORK="192.168.1.0/24"

echo "[+] Phase 1: Device Discovery"
wsdiscovery 239.255.255.250 --format json > onvif-devices.json

echo "[+] Phase 2: MQTT Broker Discovery"
# Scan for MQTT brokers
nmap -p 1883,8883 $NETWORK -oG mqtt-scan.txt
grep "1883/open" mqtt-scan.txt | cut -d' ' -f2 > mqtt-brokers.txt

echo "[+] Phase 3: MQTT Security Testing"
cat mqtt-brokers.txt | while read broker; do
    mqttscan $broker --format json > "mqtt-$broker.json"
done

echo "[+] Phase 4: ONVIF Security Testing"
cat onvif-devices.json | jq -r '.devices[].xaddrs' | \
    grep -oP 'http://\K[^/]+' | while read ip; do
    echo "Testing: $ip"
    onvifscan auth "http://$ip" --all --format json > "onvif-$ip.json"
done

echo "[+] Phase 5: Firmware Analysis"
# If you have firmware
# ffind firmware.bin -e
# grep -r "password" /tmp/ffind_*/

echo "[+] IoT Assessment Complete!"
```

---

## OWASP Top 10 Testing

### A01:2024 – Broken Access Control

**What to test:**
- IDOR (Insecure Direct Object Reference)
- Privilege escalation
- Force browsing
- Missing function-level access control

**How to test:**
```bash
# IDOR Testing
# Change user IDs in requests
curl https://target.com/api/users/123
curl https://target.com/api/users/124

# Privilege Escalation
# Access admin endpoints with regular user token
curl https://target.com/admin/users \
    -H "Authorization: Bearer REGULAR_USER_TOKEN"

# Force Browsing
ffuf -u https://target.com/FUZZ \
    -w admin-panels.txt \
    -mc 200,301,302
```

### A02:2024 – Cryptographic Failures

**What to test:**
- Weak encryption
- Sensitive data exposure
- Insecure protocols

**How to test:**
```bash
# SSL/TLS Testing
testssl target.com

# Check for sensitive data in responses
curl https://target.com/api/users | grep -i "password\|key\|secret"

# Check HTTP (should redirect to HTTPS)
curl http://target.com -I
```

### A03:2024 – Injection

**What to test:**
- SQL Injection
- NoSQL Injection
- Command Injection
- XSS

**How to test:**
```bash
# SQL Injection
sqlmap -u "https://target.com/page?id=1" --dbs

# XSS
# Manual payloads in all input fields:
<script>alert(document.domain)</script>

# Command Injection
# Test with: ; ls, | whoami, && id
```

---

## Reporting Guidelines

### Report Structure

```markdown
# [Severity] Vulnerability Title

## Summary
Brief 2-3 sentence overview of the vulnerability.

## Severity
- **CVSS Score**: X.X
- **Severity**: Critical/High/Medium/Low
- **Category**: [OWASP category]

## Vulnerability Details

### Description
Detailed explanation of what the vulnerability is and how it works.

### Steps to Reproduce
1. Navigate to https://target.com/page
2. Enter payload: [payload]
3. Click submit
4. Observe [result]

### Proof of Concept
```bash
curl -X POST https://target.com/api/endpoint \
    -H "Content-Type: application/json" \
    -d '{"user_id": 1337}'
```

### Screenshot/Video
[Attach evidence]

## Impact
Explain what an attacker can achieve:
- Access to other users' data
- Account takeover
- Data exfiltration
- etc.

## Affected Assets
- https://target.com/endpoint
- https://api.target.com/v1/users

## Remediation
1. Implement proper authorization checks
2. Validate user input
3. Use parameterized queries
4. etc.

## References
- [OWASP Link]
- [CVE Link]
- [CWE Link]
```

### Severity Assessment

**Critical:**
- RCE (Remote Code Execution)
- Authentication bypass
- SQL Injection with data access
- Account takeover

**High:**
- IDOR with PII access
- XSS on sensitive pages
- SSRF with internal network access
- Privilege escalation

**Medium:**
- XSS on non-sensitive pages
- CSRF
- Information disclosure
- Security misconfiguration

**Low:**
- Missing security headers
- Verbose error messages
- CORS misconfiguration
- Open redirects (low impact)

---

## Tips and Tricks

### Automation Scripts

```bash
# One-liner for complete recon
echo "target.com" | \
    subfinder -silent | \
    httpx -silent | \
    nuclei -t cves/ -silent
```

### Useful Aliases

```bash
# Add to ~/.bashrc
alias subenum='subdomain-enum'
alias httprobe='httpx -silent'
alias dirscan='ffuf -u FUZZ -w /usr/share/seclists/Discovery/Web-Content/common.txt'
```

### Common Mistakes to Avoid

1. **Not reading the program policy** - Always know what's in scope!
2. **Automated scanning only** - Manual testing finds the best bugs
3. **Poor report quality** - Clear, detailed reports get accepted
4. **Testing production carelessly** - Use safe, non-destructive methods
5. **Ignoring duplicates** - Check existing reports first

### Pro Tips

1. **Focus on less-tested areas** - APIs, mobile apps, IoT devices
2. **Chain vulnerabilities** - Low-severity bugs can become critical when chained
3. **Understand the business** - Business logic flaws are valuable
4. **Build relationships** - Good communication with program teams matters
5. **Keep learning** - Stay updated with new techniques and CVEs

### Resources

- **Platforms**: HackerOne, Bugcrowd, Intigriti, YesWeHack
- **Learning**: PortSwigger Web Security Academy, HackerOne Hacker101
- **Community**: Twitter #bugbounty, Discord servers, Reddit /r/bugbounty
- **Tools**: ProjectDiscovery, OWASP projects, custom scripts

---

## Legal & Ethical Considerations

### Always Remember:

✅ **DO:**
- Get written authorization
- Follow program policies
- Respect scope limitations
- Report responsibly
- Be patient with triage
- Communicate professionally

❌ **DON'T:**
- Test without permission
- Go out of scope
- Conduct DoS attacks
- Access sensitive data unnecessarily
- Share vulnerabilities publicly before disclosure
- Be aggressive with program teams

### Responsible Disclosure Timeline

1. **Day 0**: Submit vulnerability report
2. **Day 1-7**: Program acknowledges receipt
3. **Day 7-30**: Program triages and validates
4. **Day 30-90**: Program fixes vulnerability
5. **Day 90+**: Coordinate public disclosure

---

**Remember**: The best bug bounty hunters are ethical, patient, thorough, and professional. Happy hunting with Bounty Buddy! 🎯

*Built upon [IoTHackBot](https://github.com/BrownFineSecurity/iothackbot) by BrownFine Security*
