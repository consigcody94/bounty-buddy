#!/bin/bash
################################################################################
# Bounty Buddy - Automated Bug Bounty Reconnaissance
# Built upon IoTHackBot by BrownFine Security
#
# Usage: ./bountybuddy-auto.sh <target-domain>
# Example: ./bountybuddy-auto.sh example.com
################################################################################

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Banner
echo -e "${CYAN}"
cat << "EOF"
╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║   ██████╗  ██████╗ ██╗   ██╗███╗   ██╗████████╗██╗   ██╗ ║
║   ██╔══██╗██╔═══██╗██║   ██║████╗  ██║╚══██╔══╝╚██╗ ██╔╝ ║
║   ██████╔╝██║   ██║██║   ██║██╔██╗ ██║   ██║    ╚████╔╝  ║
║   ██╔══██╗██║   ██║██║   ██║██║╚██╗██║   ██║     ╚██╔╝   ║
║   ██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║   ██║      ██║    ║
║   ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝  ╚═══╝   ╚═╝      ╚═╝    ║
║                                                           ║
║   ██████╗ ██╗   ██╗██████╗ ██████╗ ██╗   ██╗             ║
║   ██╔══██╗██║   ██║██╔══██╗██╔══██╗╚██╗ ██╔╝             ║
║   ██████╔╝██║   ██║██║  ██║██║  ██║ ╚████╔╝              ║
║   ██╔══██╗██║   ██║██║  ██║██║  ██║  ╚██╔╝               ║
║   ██████╔╝╚██████╔╝██████╔╝██████╔╝   ██║                ║
║   ╚═════╝  ╚═════╝ ╚═════╝ ╚═════╝    ╚═╝                ║
║                                                           ║
║   Built upon IoTHackBot | BrownFine Security             ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝
EOF
echo -e "${NC}"

# Check if target is provided
if [ $# -eq 0 ]; then
    echo -e "${RED}[!] Error: No target domain provided${NC}"
    echo -e "${YELLOW}Usage: $0 <target-domain>${NC}"
    echo -e "${YELLOW}Example: $0 example.com${NC}"
    exit 1
fi

TARGET="$1"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
OUTDIR="bounty_${TARGET}_${TIMESTAMP}"

# Create output directory
mkdir -p "$OUTDIR"
cd "$OUTDIR"

echo -e "${GREEN}[✓] Target: $TARGET${NC}"
echo -e "${GREEN}[✓] Output directory: $OUTDIR${NC}"
echo ""

# Log file
LOGFILE="bountybuddy_${TIMESTAMP}.log"
exec > >(tee -a "$LOGFILE") 2>&1

################################################################################
# Phase 1: Subdomain Enumeration
################################################################################
echo -e "${BLUE}[+] Phase 1: Subdomain Enumeration${NC}"
echo -e "${CYAN}    This may take a few minutes...${NC}"

if command -v subdomain-enum &> /dev/null; then
    subdomain-enum "$TARGET" -o subdomains.txt
    SUBDOMAIN_COUNT=$(wc -l < subdomains.txt)
    echo -e "${GREEN}[✓] Found $SUBDOMAIN_COUNT subdomains${NC}"
else
    echo -e "${YELLOW}[!] subdomain-enum not found, using alternative methods${NC}"

    # Fallback to individual tools
    if command -v subfinder &> /dev/null; then
        subfinder -d "$TARGET" -silent -o subfinder.txt
    fi

    if command -v amass &> /dev/null; then
        amass enum -passive -d "$TARGET" -o amass.txt
    fi

    # Query crt.sh
    curl -s "https://crt.sh/?q=%.${TARGET}&output=json" | \
        jq -r '.[].name_value' | sort -u > crtsh.txt 2>/dev/null || true

    # Combine and deduplicate
    cat subfinder.txt amass.txt crtsh.txt 2>/dev/null | sort -u > subdomains.txt
    SUBDOMAIN_COUNT=$(wc -l < subdomains.txt)
    echo -e "${GREEN}[✓] Found $SUBDOMAIN_COUNT subdomains${NC}"
fi

echo ""

################################################################################
# Phase 2: HTTP Probing
################################################################################
echo -e "${BLUE}[+] Phase 2: HTTP Probing${NC}"
echo -e "${CYAN}    Checking which subdomains are live...${NC}"

if command -v httpx &> /dev/null; then
    httpx -l subdomains.txt \
        -title \
        -status-code \
        -tech-detect \
        -silent \
        -o live-hosts.txt

    LIVE_COUNT=$(wc -l < live-hosts.txt)
    echo -e "${GREEN}[✓] Found $LIVE_COUNT live hosts${NC}"
else
    echo -e "${YELLOW}[!] httpx not found, skipping live host probing${NC}"
    cp subdomains.txt live-hosts.txt
fi

echo ""

################################################################################
# Phase 3: Port Scanning (Optional)
################################################################################
if command -v nmap &> /dev/null; then
    echo -e "${BLUE}[+] Phase 3: Port Scanning (Top 1000 ports)${NC}"
    echo -e "${CYAN}    This may take several minutes...${NC}"

    # Create list of IPs from subdomains
    cat subdomains.txt | head -10 | while read subdomain; do
        host "$subdomain" 2>/dev/null | grep "has address" | awk '{print $4}'
    done | sort -u > ips.txt

    if [ -s ips.txt ]; then
        sudo nmap -iL ips.txt --top-ports 1000 -oA nmap-scan 2>/dev/null || \
            nmap -iL ips.txt --top-ports 1000 -oA nmap-scan
        echo -e "${GREEN}[✓] Port scan complete${NC}"
    fi
else
    echo -e "${YELLOW}[!] nmap not found, skipping port scanning${NC}"
fi

echo ""

################################################################################
# Phase 4: URL Collection
################################################################################
echo -e "${BLUE}[+] Phase 4: URL Collection${NC}"
echo -e "${CYAN}    Gathering URLs from archives...${NC}"

# Wayback Machine
if command -v waybackurls &> /dev/null; then
    cat live-hosts.txt | head -20 | waybackurls | tee wayback-urls.txt > /dev/null 2>&1 || true
    WAYBACK_COUNT=$(wc -l < wayback-urls.txt 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found $WAYBACK_COUNT wayback URLs${NC}"
fi

# GetAllUrls
if command -v gau &> /dev/null; then
    echo "$TARGET" | gau | tee gau-urls.txt > /dev/null 2>&1 || true
    GAU_COUNT=$(wc -l < gau-urls.txt 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found $GAU_COUNT GAU URLs${NC}"
fi

# Combine all URLs
cat wayback-urls.txt gau-urls.txt 2>/dev/null | sort -u > all-urls.txt
TOTAL_URLS=$(wc -l < all-urls.txt 2>/dev/null || echo "0")
echo -e "${GREEN}[✓] Total unique URLs: $TOTAL_URLS${NC}"

echo ""

################################################################################
# Phase 5: Vulnerability Scanning
################################################################################
echo -e "${BLUE}[+] Phase 5: Vulnerability Scanning${NC}"

if command -v nuclei &> /dev/null && [ -s live-hosts.txt ]; then
    echo -e "${CYAN}    Running Nuclei scans...${NC}"

    # CVE scanning
    nuclei -l live-hosts.txt \
        -t cves/ \
        -silent \
        -o nuclei-cves.txt 2>/dev/null || true

    # Exposure scanning
    nuclei -l live-hosts.txt \
        -t exposures/ \
        -silent \
        -o nuclei-exposures.txt 2>/dev/null || true

    # Vulnerability scanning
    nuclei -l live-hosts.txt \
        -t vulnerabilities/ \
        -silent \
        -o nuclei-vulns.txt 2>/dev/null || true

    # Combine results
    cat nuclei-*.txt 2>/dev/null | sort -u > nuclei-all.txt
    VULN_COUNT=$(wc -l < nuclei-all.txt 2>/dev/null || echo "0")
    echo -e "${GREEN}[✓] Found $VULN_COUNT potential vulnerabilities${NC}"

    if [ "$VULN_COUNT" -gt 0 ]; then
        echo -e "${RED}[!] Vulnerabilities detected! Check nuclei-all.txt${NC}"
    fi
else
    echo -e "${YELLOW}[!] nuclei not found or no live hosts, skipping vulnerability scanning${NC}"
fi

echo ""

################################################################################
# Phase 6: Directory Fuzzing (Sample)
################################################################################
if command -v ffuf &> /dev/null && [ -s live-hosts.txt ]; then
    echo -e "${BLUE}[+] Phase 6: Directory Fuzzing (Sample)${NC}"
    echo -e "${CYAN}    Fuzzing top 3 hosts for common directories...${NC}"

    head -3 live-hosts.txt | while read url; do
        echo -e "${CYAN}    Fuzzing: $url${NC}"
        ffuf -u "$url/FUZZ" \
            -w /usr/share/seclists/Discovery/Web-Content/common.txt \
            -mc 200,301,302,403 \
            -maxtime 60 \
            -silent \
            -o "ffuf-$(echo $url | md5sum | cut -d' ' -f1).json" 2>/dev/null || true
    done
    echo -e "${GREEN}[✓] Directory fuzzing complete${NC}"
else
    echo -e "${YELLOW}[!] ffuf not found, skipping directory fuzzing${NC}"
fi

echo ""

################################################################################
# Phase 7: Generate Summary Report
################################################################################
echo -e "${BLUE}[+] Phase 7: Generating Summary Report${NC}"

cat > SUMMARY.md << EOF
# Bounty Buddy - Reconnaissance Summary

**Target**: ${TARGET}
**Date**: $(date)
**Duration**: Automated scan

## Statistics

- **Subdomains Found**: ${SUBDOMAIN_COUNT}
- **Live Hosts**: ${LIVE_COUNT:-0}
- **Total URLs**: ${TOTAL_URLS}
- **Potential Vulnerabilities**: ${VULN_COUNT:-0}

## Files Generated

- \`subdomains.txt\` - All discovered subdomains
- \`live-hosts.txt\` - Live HTTP/HTTPS hosts
- \`all-urls.txt\` - Collected URLs from archives
- \`nuclei-all.txt\` - Vulnerability scan results
- \`nmap-scan.*\` - Port scan results (if available)
- \`ffuf-*.json\` - Directory fuzzing results

## Next Steps

### Manual Testing Required

1. **Authentication Testing**
   - Test login pages for brute force protection
   - Check for authentication bypass
   - Test password reset functionality

2. **Authorization Testing**
   - Test for IDOR vulnerabilities
   - Check privilege escalation
   - Test API endpoints with different user roles

3. **Input Validation**
   - Test for SQL injection
   - Test for XSS
   - Test for command injection
   - Test file upload functionality

4. **Business Logic**
   - Review application workflows
   - Test for race conditions
   - Check pricing/payment logic
   - Test multi-step processes

5. **API Security**
   - Test API authentication
   - Check rate limiting
   - Test for information disclosure
   - Fuzz API parameters

### Tools for Manual Testing

- **Burp Suite**: Web proxy and scanner
- **SQLMap**: SQL injection testing
- **Custom Scripts**: IDOR, logic flaws
- **Browser DevTools**: JavaScript analysis

## Important Reminders

⚠️  **Only test systems you have permission to test**
⚠️  **Follow the program's scope and rules**
⚠️  **Document all findings with proof**
⚠️  **Report responsibly**

---

*Generated by Bounty Buddy - Built upon IoTHackBot*
EOF

echo -e "${GREEN}[✓] Summary report generated: SUMMARY.md${NC}"

################################################################################
# Completion
################################################################################
echo ""
echo -e "${GREEN}╔════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║                 RECONNAISSANCE COMPLETE!                   ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${CYAN}Results saved in: ${PWD}${NC}"
echo -e "${CYAN}Review SUMMARY.md for next steps${NC}"
echo ""
echo -e "${YELLOW}Remember:${NC}"
echo -e "${YELLOW}  • Always get proper authorization${NC}"
echo -e "${YELLOW}  • Follow responsible disclosure${NC}"
echo -e "${YELLOW}  • Manual testing finds the best bugs${NC}"
echo ""
echo -e "${GREEN}Happy Hunting! 🎯${NC}"
