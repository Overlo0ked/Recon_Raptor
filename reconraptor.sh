#!/bin/bash
# ReconRaptor Pro v3.0 - Advanced Bug Bounty Automation Suite
# Author: ZeroDay Threat Intelligence
# Features: Tech detection, CMS scanning, API discovery, cloud audit, and AI-powered triage

# Configuration
BOT_TOKEN="YOUR_TELEGRAM_BOT_TOKEN"
CHAT_ID="YOUR_TELEGRAM_CHAT_ID"
THREADS=12
WORDLIST="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-large-words.txt"
HYDRA_USERLIST="/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
HYDRA_PASSLIST="/usr/share/wordlists/seclists/Passwords/Leaked-Databases/rockyou.txt"
CLOUD_CREDS=("aws" "gcp" "azure" "digitalocean" "heroku" "slack" "stripe")

# CLI Arguments
TARGET=""
NO_BRUTE=false
NO_SCREENSHOT=false
QUICK_MODE=false
RESUME=false
DEEP_SCAN=false

# Setup directories
setup_dirs() {
    echo "[+] Setting up directories"
    mkdir -p output/$TARGET/{screenshots,reports,cms_scans,api_endpoints,cloud_audit}
    WORKDIR="output/$TARGET"
}

# Telegram alerts
telegram_alert() {
    if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        return
    fi
    
    MESSAGE="ReconRaptor Pro: $1"
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$MESSAGE" >/dev/null
}

# Technology Detection
tech_detection() {
    echo "[+] Running technology detection"
    whatweb -i $WORKDIR/live.txt --log-verbose=$WORKDIR/tech_detection.txt --no-errors
    
    # Extract CMS platforms
    grep -i 'wordpress' $WORKDIR/tech_detection.txt > $WORKDIR/cms_scans/wordpress.txt
    grep -i 'joomla' $WORKDIR/tech_detection.txt > $WORKDIR/cms_scans/joomla.txt
    grep -i 'drupal' $WORKDIR/tech_detection.txt > $WORKDIR/cms_scans/drupal.txt
    grep -i 'magento' $WORKDIR/tech_detection.txt > $WORKDIR/cms_scans/magento.txt
}

# CMS-Specific Scanning
cms_scanning() {
    echo "[+] Starting CMS-specific scanning"
    
    # WordPress
    if [ -s "$WORKDIR/cms_scans/wordpress.txt" ]; then
        echo "  [+] Scanning WordPress sites"
        cat $WORKDIR/cms_scans/wordpress.txt | awk '{print $1}' | xargs -P $THREADS -I % sh -c '
            wpscan --url % --enumerate vp,vt,tt,cb,dbe --random-user-agent --no-banner \
            --output $WORKDIR/cms_scans/wpscan_$(echo % | sed "s|/|_|g").txt'
    fi
    
    # Joomla
    if [ -s "$WORKDIR/cms_scans/joomla.txt" ]; then
        echo "  [+] Scanning Joomla sites"
        cat $WORKDIR/cms_scans/joomla.txt | awk '{print $1}' | xargs -P $THREADS -I % \
            joomscan -u % -ec > $WORKDIR/cms_scans/joomscan_%.txt
    fi
    
    # Drupal
    if [ -s "$WORKDIR/cms_scans/drupal.txt" ]; then
        echo "  [+] Scanning Drupal sites"
        cat $WORKDIR/cms_scans/drupal.txt | awk '{print $1}' | xargs -P $THREADS -I % \
            droopescan scan drupal -u % > $WORKDIR/cms_scans/droopescan_%.txt
    fi
    
    # Magento
    if [ -s "$WORKDIR/cms_scans/magento.txt" ]; then
        echo "  [+] Scanning Magento sites"
        cat $WORKDIR/cms_scans/magento.txt | awk '{print $1}' | xargs -P $THREADS -I % \
            magereport scan -u % > $WORKDIR/cms_scans/magereport_%.txt
    fi
    
    # Check for critical CMS findings
    grep -r "CRITICAL\|VULNERABLE" $WORKDIR/cms_scans/ | tee $WORKDIR/cms_critical.txt
    if [ -s "$WORKDIR/cms_critical.txt" ]; then
        telegram_alert "Critical CMS vulnerabilities found on $TARGET!"
    fi
}

# API Endpoint Discovery
api_discovery() {
    echo "[+] Discovering API endpoints"
    katana -list $WORKDIR/live.txt -d 3 -jc -kf -fs rdn -o $WORKDIR/api_endpoints/katana.txt
    gau $TARGET | grep -iE 'api|graphql|rest|soap|json|xmlrpc' > $WORKDIR/api_endpoints/gau_api.txt
    
    # Combine and deduplicate
    cat $WORKDIR/api_endpoints/*.txt | sort -u > $WORKDIR/api_endpoints/all_endpoints.txt
    
    # Test for common API vulnerabilities
    if [ -s "$WORKDIR/api_endpoints/all_endpoints.txt" ]; then
        echo "  [+] Testing API endpoints"
        nuclei -l $WORKDIR/api_endpoints/all_endpoints.txt -t api/ -o $WORKDIR/api_endpoints/nuclei_results.txt
        
        # Advanced API fuzzing
        if command -v ffuf &> /dev/null; then
            ffuf -w $WORDLIST -u FUZZ -recursion -t $THREADS \
                -H "Content-Type: application/json" -X POST \
                -d '{"query":"FUZZ"}' -mc all -of csv -o $WORKDIR/api_endpoints/ffuf_results.csv
        fi
    fi
}

# Cloud Credential Scanning
cloud_audit() {
    echo "[+] Scanning for cloud credentials"
    for provider in "${CLOUD_CREDS[@]}"; do
        gitleaks detect -s . -c /opt/gitleaks/config.toml --include=$provider \
            -r $WORKDIR/cloud_audit/${provider}_leaks.json
    done
    
    # Check for valid credentials
    for report in $WORKDIR/cloud_audit/*_leaks.json; do
        if jq -e '.[].match' $report >/dev/null; then
            provider=$(basename $report | cut -d'_' -f1)
            telegram_alert "Live $provider credentials found! Check $report"
        fi
    done
    
    # AWS specific checks
    if [ -f "$WORKDIR/cloud_audit/aws_leaks.json" ]; then
        aws_scan
    fi
}

# AWS Environment Scanner
aws_scan() {
    echo "  [+] Auditing AWS environment"
    # Assume role with found credentials
    export AWS_ACCESS_KEY_ID=$(jq -r '.[0].secret' $WORKDIR/cloud_audit/aws_leaks.json)
    export AWS_SECRET_ACCESS_KEY=$(jq -r '.[0].match' $WORKDIR/cloud_audit/aws_leaks.json)
    
    # Run cloud security scanner
    cloudmapper collect --account-name $TARGET
    cloudmapper audit --account-name $TARGET --json > $WORKDIR/cloud_audit/aws_audit.json
    
    # Check for critical misconfigurations
    if jq -e '.[].risk_level == "CRITICAL"' $WORKDIR/cloud_audit/aws_audit.json; then
        telegram_alert "Critical AWS misconfigurations found!"
    fi
}

# AI-Powered Triage
ai_triage() {
    echo "[+] Running AI-powered vulnerability triage"
    # Use NLP to prioritize critical findings
    cat $WORKDIR/vulns_found.txt $WORKDIR/nuclei_results.txt $WORKDIR/cms_critical.txt | \
        python3 -c "
import sys
import re

criticals = []
highs = []
mediums = []

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
        
    # AI priority scoring
    score = 0
    if re.search(r'critical|rce|sql\s?injection|takeover', line, re.I):
        score += 100
    if re.search(r'aws|gcp|azure|cloud', line, re.I):
        score += 80
    if re.search(r'xss|csrf|ssrf', line, re.I):
        score += 40
        
    # CVE scoring
    if re.search(r'CVE-\d{4}-\d{4,7}', line):
        score += 60
        
    # Classify
    if score >= 90:
        criticals.append(line)
    elif score >= 60:
        highs.append(line)
    else:
        mediums.append(line)

# Output sorted findings
print('\n'.join(criticals))
print('\n'.join(highs))
print('\n'.join(mediums))
" > $WORKDIR/ai_prioritized.txt

    # Send top findings via Telegram
    head -n 5 $WORKDIR/ai_prioritized.txt | while read -r line; do
        telegram_alert "AI Priority: $line"
    done
}

# Add to existing functions
subdomain_enum() {
    # ... (existing code) ... 
    # Add new tools
    crobat -s $TARGET >> $WORKDIR/crobat.txt
    chaos -d $TARGET -o $WORKDIR/chaos.txt
}

live_hosts() {
    # ... (existing code) ... 
    # Add port scanning
    naabu -iL $WORKDIR/subdomains.txt -p 1-10000,30000-50000 -o $WORKDIR/naabu_ports.txt
}

vuln_scanning() {
    # ... (existing code) ... 
    # Add new scanners
    nuclei -l $WORKDIR/live.txt -t exposures/ -o $WORKDIR/exposures.txt
    nikto -h $WORKDIR/live.txt -o $WORKDIR/nikto_scan.txt
}

# Update main function
main() {
    # ... (existing banner) ...
    
    setup_dirs
    telegram_alert "Recon started for $TARGET"
    
    # Enhanced execution pipeline
    subdomain_enum
    live_hosts
    tech_detection        # NEW
    cms_scanning          # NEW
    url_scraping
    js_analysis
    api_discovery         # NEW
    screenshot
    admin_panels
    vuln_scanning
    nuclei_scan
    cloud_audit           # NEW
    ai_triage             # NEW
    generate_report
    
    telegram_alert "Recon completed for $TARGET! Report: $WORKDIR/reports/report_summary.md"
    echo -e "\n[+] Recon completed! Results saved to: output/$TARGET"
}

# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        # ... existing args ...
        --deep)
            DEEP_SCAN=true
            THREADS=16
            shift
            ;;
    esac
done

# ... rest of script ...
#!/bin/bash
# ReconRaptor v2.0 - Ultimate Bug Bounty Reconnaissance Suite
# Author: SecurityAutomation.ai
# Requirements: subfinder, amass, assetfinder, findomain, httpx, gau, waybackurls, hakrawler, LinkFinder, SecretFinder, gowitness, dirsearch, hydra, dalfox, sqlmap, gf, nuclei

# Configuration
BOT_TOKEN="7767401198:AAENXdRc440k7F0jOW8q-plDstCuFORg8Zc"
CHAT_ID="1253970404"
THREADS=8
WORDLIST="/usr/share/wordlists/dirb/common.txt"
HYDRA_USERLIST="/usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt"
HYDRA_PASSLIST="/usr/share/wordlists/seclists/Passwords/2020-200_most_used_passwords.txt"

# CLI Arguments
TARGET=""
NO_BRUTE=false
NO_SCREENSHOT=false
QUICK_MODE=false
RESUME=false

# Setup directories
setup_dirs() {
    echo "[+] Setting up directories"
    mkdir -p output/$TARGET/{screenshots,reports}
    WORKDIR="output/$TARGET"
}

# Telegram alerts
telegram_alert() {
    if [ -z "$BOT_TOKEN" ] || [ -z "$CHAT_ID" ]; then
        return
    fi
    
    MESSAGE="ReconRaptor: $1"
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
        -d "chat_id=$CHAT_ID" \
        -d "text=$MESSAGE" >/dev/null
}

# Subdomain enumeration
subdomain_enum() {
    if [ "$RESUME" = true ] && [ -f "$WORKDIR/subdomains.txt" ]; then
        echo "[+] Resuming subdomain enumeration"
        return
    fi
    
    echo "[+] Starting subdomain enumeration"
    telegram_alert "Subdomain enumeration started for $TARGET"
    
    subfinder -d $TARGET -silent -o $WORKDIR/subfinder.txt &
    amass enum -passive -d $TARGET -o $WORKDIR/amass.txt &
    assetfinder --subs-only $TARGET > $WORKDIR/assetfinder.txt &
    findomain -t $TARGET -q -u $WORKDIR/findomain.txt &
    wait
    
    cat $WORKDIR/{subfinder,amass,assetfinder,findomain}.txt | sort -u > $WORKDIR/subdomains.txt
    rm $WORKDIR/{subfinder,amass,assetfinder,findomain}.txt
    
    echo "[+] Found $(wc -l < $WORKDIR/subdomains.txt) subdomains"
}

# Live host detection
live_hosts() {
    if [ "$RESUME" = true ] && [ -f "$WORKDIR/live.txt" ]; then
        echo "[+] Resuming live host detection"
        return
    fi
    
    echo "[+] Probing live hosts"
    httpx -l $WORKDIR/subdomains.txt -status-code -title -tech-detect -content-length \
        -o $WORKDIR/httpx.txt -silent
    
    grep -v "FAILED" $WORKDIR/httpx.txt | awk '{print $1}' > $WORKDIR/live.txt
    echo "[+] Found $(wc -l < $WORKDIR/live.txt) live hosts"
}

# URL scraping with keyword filtering
url_scraping() {
    if [ "$RESUME" = true ] && [ -f "$WORKDIR/keywords.txt" ]; then
        echo "[+] Resuming URL scraping"
        return
    fi
    
    echo "[+] Scraping URLs"
    KEYWORDS="admin|debug|token|redirect|password|auth|login|secret|api|key"
    
    gau $TARGET | grep -E $KEYWORDS > $WORKDIR/gau.txt &
    waybackurls $TARGET | grep -E $KEYWORDS > $WORKDIR/wayback.txt &
    cat $WORKDIR/live.txt | hakrawler -depth 2 -scope exact | grep -E $KEYWORDS > $WORKDIR/hakrawler.txt &
    wait
    
    cat $WORKDIR/{gau,wayback,hakrawler}.txt | sort -u > $WORKDIR/keywords.txt
    rm $WORKDIR/{gau,wayback,hakrawler}.txt
    
    echo "[+] Found $(wc -l < $WORKDIR/keywords.txt) sensitive URLs"
}

# JavaScript analysis
js_analysis() {
    if [ "$RESUME" = true ] && [ -f "$WORKDIR/js_secrets.txt" ]; then
        echo "[+] Resuming JavaScript analysis"
        return
    fi
    
    echo "[+] Analyzing JavaScript files"
    mkdir -p $WORKDIR/js_files
    
    # Find JS URLs
    grep -E '\.js$' $WORKDIR/live.txt > $WORKDIR/js_urls.txt
    echo "[+] Found $(wc -l < $WORKDIR/js_urls.txt) JavaScript files"
    
    # Download JS files
    cat $WORKDIR/js_urls.txt | xargs -P $THREADS -I % sh -c 'curl -s "%" -o "$WORKDIR/js_files/$(echo "%" | sha1sum | cut -d" " -f1).js"'
    
    # Analyze with LinkFinder
    find $WORKDIR/js_files -type f -name "*.js" | xargs -P $THREADS -I % python3 /opt/LinkFinder/linkfinder.py -i % -o cli >> $WORKDIR/linkfinder.txt
    
    # Analyze with SecretFinder
    find $WORKDIR/js_files -type f -name "*.js" | xargs -P $THREADS -I % python3 /opt/SecretFinder/SecretFinder.py -i % -o cli >> $WORKDIR/secretfinder.txt
    
    cat $WORKDIR/linkfinder.txt $WORKDIR/secretfinder.txt | sort -u > $WORKDIR/js_secrets.txt
    rm $WORKDIR/{linkfinder,secretfinder}.txt
    
    # Check for critical findings
    if grep -q "API_KEY\|SECRET\|PASSWORD" $WORKDIR/js_secrets.txt; then
        telegram_alert "Critical secrets found in JavaScript files!"
    fi
}

# Screenshots
screenshot() {
    if [ "$NO_SCREENSHOT" = true ]; then
        return
    fi
    
    if [ "$RESUME" = true ] && [ -d "$WORKDIR/screenshots" ] && [ "$(ls -A $WORKDIR/screenshots)" ]; then
        echo "[+] Resuming screenshots"
        return
    fi
    
    echo "[+] Capturing screenshots"
    gowitness file -f $WORKDIR/live.txt -D $WORKDIR/screenshots -P $WORKDIR/screenshots
}

# Admin panel discovery and brute force
admin_panels() {
    if [ "$NO_BRUTE" = true ]; then
        return
    fi
    
    echo "[+] Searching for admin panels"
    mkdir -p $WORKDIR/dirsearch
    
    # Run dirsearch in parallel
    cat $WORKDIR/live.txt | xargs -P $THREADS -I % sh -c 'dirsearch -u % -e php,asp,aspx,jsp,html,zip,jar -w $WORDLIST -t 2 -q --plain-text-report=$WORKDIR/dirsearch/$(echo % | sed "s/\//_/g").txt'
    
    # Process results
    grep -r "Login\|Admin" $WORKDIR/dirsearch/ > $WORKDIR/admin_panels.txt
    
    if [ -s "$WORKDIR/admin_panels.txt" ]; then
        echo "[+] Found $(wc -l < $WORKDIR/admin_panels.txt) admin panels"
        telegram_alert "Admin panels found on $TARGET!"
        
        # Brute-force found panels
        while read -r line; do
            URL=$(echo $line | awk '{print $1}')
            CODE=$(echo $line | awk '{print $3}')
            
            if [[ $CODE == 200 ]] || [[ $CODE == 302 ]]; then
                echo "[+] Brute-forcing $URL"
                hydra -L $HYDRA_USERLIST -P $HYDRA_PASSLIST $URL http-post-form "/:username=^USER^&password=^PASS^:F=incorrect" -t 4 -o $WORKDIR/hydra_$URL.txt
                
                if grep -q "login successful" $WORKDIR/hydra_$URL.txt; then
                    telegram_alert "Successful brute-force on $URL!"
                fi
            fi
        done < $WORKDIR/admin_panels.txt
    else
        echo "[-] No admin panels found"
    fi
}

# Vulnerability scanning
vuln_scanning() {
    echo "[+] Starting vulnerability scanning"
    
    # XSS scanning
    dalfox file $WORKDIR/keywords.txt -b hahwul.xss.alert -o $WORKDIR/dalfox.txt &
    
    # SQLi scanning
    sqlmap -m $WORKDIR/keywords.txt --batch --level=2 --risk=2 --output-dir=$WORKDIR/sqlmap/ &
    
    # GF pattern scanning
    mkdir -p $WORKDIR/gf
    gf ssrf $WORKDIR/keywords.txt > $WORKDIR/gf/ssrf.txt &
    gf lfi $WORKDIR/keywords.txt > $WORKDIR/gf/lfi.txt &
    gf rce $WORKDIR/keywords.txt > $WORKDIR/gf/rce.txt &
    wait
    
    # Combine results
    cat $WORKDIR/dalfox.txt > $WORKDIR/vulns_found.txt
    [ -f "$WORKDIR/sqlmap/output" ] && cat $WORKDIR/sqlmap/output >> $WORKDIR/vulns_found.txt
    cat $WORKDIR/gf/*.txt >> $WORKDIR/vulns_found.txt
    
    # Check for critical findings
    if grep -qE "VULNERABLE|injection" $WORKDIR/vulns_found.txt; then
        telegram_alert "Critical vulnerabilities found on $TARGET!"
    fi
}

# Nuclei scanning
nuclei_scan() {
    if [ "$RESUME" = true ] && [ -f "$WORKDIR/nuclei_results.txt" ]; then
        echo "[+] Resuming Nuclei scan"
        return
    fi
    
    echo "[+] Running Nuclei scans"
    nuclei -l $WORKDIR/live.txt -t cves/ -t misconfiguration/ \
        -t exposures/ -t vulnerabilities/ -severity critical,high \
        -o $WORKDIR/nuclei_results.txt -silent
    
    # Check for critical findings
    if grep -q "critical" $WORKDIR/nuclei_results.txt; then
        telegram_alert "Critical Nuclei findings on $TARGET!"
    fi
}

# Generate report
generate_report() {
    echo "[+] Generating final report"
    REPORT="$WORKDIR/reports/report_summary.md"
    
    echo "# ReconRaptor Report for $TARGET" > $REPORT
    echo "Generated on: $(date)" >> $REPORT
    echo "" >> $REPORT
    
    echo "## Reconnaissance Summary" >> $REPORT
    echo "- **Subdomains Found**: $(wc -l < $WORKDIR/subdomains.txt)" >> $REPORT
    echo "- **Live Hosts**: $(wc -l < $WORKDIR/live.txt)" >> $REPORT
    echo "- **Sensitive URLs**: $(wc -l < $WORKDIR/keywords.txt)" >> $REPORT
    echo "- **JavaScript Secrets**: $(wc -l < $WORKDIR/js_secrets.txt)" >> $REPORT
    echo "- **Critical Vulnerabilities**: $(grep -c "CRITICAL" $WORKDIR/vulns_found.txt)" >> $REPORT
    echo "- **Nuclei Findings**: $(grep -c "high\|critical" $WORKDIR/nuclei_results.txt)" >> $REPORT
    echo "" >> $REPORT
    
    echo "## Critical Findings" >> $REPORT
    grep "CRITICAL" $WORKDIR/vulns_found.txt | head -n 5 | sed 's/^/- /' >> $REPORT
    grep "critical" $WORKDIR/nuclei_results.txt | head -n 5 | sed 's/^/- /' >> $REPORT
    echo "" >> $REPORT
    
    echo "## Next Steps" >> $REPORT
    echo "- Manually verify all critical findings" >> $REPORT
    echo "- Test for business logic vulnerabilities" >> $REPORT
    echo "- Check for access control issues" >> $REPORT
    echo "- Submit valid findings to bug bounty platform" >> $REPORT
    
    # Convert to PDF if pandoc installed
    if command -v pandoc &> /dev/null; then
        pandoc $REPORT -o ${REPORT%.md}.pdf
    fi
}

# Main function
main() {
    clear
    echo -e "\n\033[1;34m"
    echo " ██▀███  ▓█████ ▒█████  ▓█████▄ ▓█████  ██▀███  ▄████▄  ▓█████ "
    echo "▓██ ▒ ██▒▓█   ▀▒██▒  ██▒▒██▀ ██▌▓█   ▀ ▓██ ▒ ██▒▒██▀ ▀█  ▓█   ▀ "
    echo "▓██ ░▄█ ▒▒███  ▒██░  ██▒░██   █▌▒███   ▓██ ░▄█ ▒▒▓█    ▄ ▒███   "
    echo "▒██▀▀█▄  ▒▓█  ▄▒██   ██░░▓█▄   ▌▒▓█  ▄ ▒██▀▀█▄  ▒▓▓▄ ▄██▒▒▓█  ▄ "
    echo "░██▓ ▒██▒░▒████░ ████▓▒░░▒████▓ ░▒████▒░██▓ ▒██▒▒ ▓███▀ ░░▒████▒"
    echo "░ ▒▓ ░▒▓░░░ ▒░ ░ ▒░▒░▒░  ▒▒▓  ▒ ░░ ▒░ ░░ ▒▓ ░▒▓░░ ░▒ ▒  ░░░ ▒░ ░"
    echo "  ░▒ ░ ▒░ ░ ░  ░ ░ ▒ ▒░  ░ ▒  ▒  ░ ░  ░  ░▒ ░ ▒░  ░  ▒    ░ ░  ░"
    echo "  ░░   ░    ░  ░ ░ ░ ▒   ░ ░  ░    ░     ░░   ░ ░           ░   "
    echo "   ░        ░  ░   ░ ░     ░       ░  ░   ░     ░ ░         ░  ░"
    echo "                            ░                  ░                 "
    echo -e "\033[0m"
    echo "ReconRaptor v2.0 - Ultimate Bug Bounty Automation"
    echo "-------------------------------------------------"
    
    setup_dirs
    telegram_alert "Recon started for $TARGET"
    
    # Execution pipeline
    subdomain_enum
    live_hosts
    url_scraping
    js_analysis
    screenshot
    admin_panels
    vuln_scanning
    nuclei_scan
    generate_report
    
    telegram_alert "Recon completed for $TARGET! Report: $WORKDIR/reports/report_summary.md"
    echo -e "\n[+] Recon completed! Results saved to: output/$TARGET"
}

# Argument parsing
while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--domain)
            TARGET="$2"
            shift 2
            ;;
        --no-brute)
            NO_BRUTE=true
            shift
            ;;
        --no-screenshot)
            NO_SCREENSHOT=true
            shift
            ;;
        --quick)
            QUICK_MODE=true
            THREADS=4
            shift
            ;;
        --resume)
            RESUME=true
            shift
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Validate target
if [ -z "$TARGET" ]; then
    echo "Usage: $0 -d target.com [--no-brute] [--no-screenshot] [--quick] [--resume]"
    exit 1
fi

# Start main process
main