#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — Nginx Security Audit                                   ║
# ║  Version: 1.0.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based Nginx security audit — NO AI, NO external API calls.
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-nginx.sh [options]

set -uo pipefail

VERSION="2.1.0"
FRAMEWORK_VERSION="2.0.0"
SCRIPT_NAME="NawaSec Audit - Nginx"

# ── Colors ──
setup_colors() {
    if [[ "${NO_COLOR:-}" == "1" ]] || [[ "$TERM" == "dumb" ]]; then
        R=''; G=''; Y=''; B=''; C=''; M=''; W=''; N=''; BOLD=''; DIM=''
    else
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
        C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; N='\033[0m'
        BOLD='\033[1m'; DIM='\033[2m'
    fi
}

PASS=0; WARN=0; FAIL=0; INFO=0; SKIP=0; TOTAL=0; SCORE=100
declare -a RESULTS=()

OPT_HTML=1; OPT_JSON=0; OPT_TXT=0; OPT_QUIET=0
OUTPUT_DIR="/tmp/nawasec-nginx"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

while [[ $# -gt 0 ]]; do
    case $1 in
        --json)     OPT_JSON=1; OPT_HTML=0; shift ;;
        --html)     OPT_HTML=1; shift ;;
        --txt)      OPT_TXT=1; shift ;;
        --all)      OPT_HTML=1; OPT_JSON=1; OPT_TXT=1; shift ;;
        --quiet)    OPT_QUIET=1; shift ;;
        --no-color) export NO_COLOR=1; shift ;;
        --output)   OUTPUT_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: sudo $0 [options]"
            echo "NawaSec Audit - Nginx v${VERSION}"
            echo "Options: --html --json --txt --all --quiet --no-color --output DIR --help"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
REPORT_HTML="$OUTPUT_DIR/nginx-audit-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/nginx-audit-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/nginx-audit-${TIMESTAMP}.txt"

# ── Detect Nginx ──
NGINX_CONF=""
NGINX_BIN=""

detect_nginx() {
    if command -v nginx &>/dev/null; then
        NGINX_BIN="nginx"
    elif [[ -f /usr/sbin/nginx ]]; then
        NGINX_BIN="/usr/sbin/nginx"
    else
        NGINX_BIN=""
    fi

    if [[ -f /etc/nginx/nginx.conf ]]; then
        NGINX_CONF="/etc/nginx/nginx.conf"
    elif [[ -f /usr/local/nginx/conf/nginx.conf ]]; then
        NGINX_CONF="/usr/local/nginx/conf/nginx.conf"
    else
        NGINX_CONF=""
    fi
}

add_result() {
    local category="$1" name="$2" status="$3" severity="$4" message="$5"
    local explanation="${6:-}" risk="${7:-}" impact="${8:-}" recommendation="${9:-}" example="${10:-}" reference="${11:-}"
    TOTAL=$((TOTAL + 1))

    case "$status" in PASS) PASS=$((PASS + 1));; WARN) WARN=$((WARN + 1));; FAIL) FAIL=$((FAIL + 1));; INFO) INFO=$((INFO + 1));; SKIP) SKIP=$((SKIP + 1));; esac

    if [[ "$OPT_QUIET" -eq 0 ]]; then
        case "$status" in
            PASS) echo -e "  ${G}✓${N} ${name} ${DIM}— ${message}${N}" ;;
            WARN) echo -e "  ${Y}⚠${N} ${name} ${DIM}— ${message}${N}" ;;
            FAIL) echo -e "  ${R}✗${N} ${name} ${DIM}— ${message}${N}" ;;
            INFO) echo -e "  ${B}ℹ${N} ${name} ${DIM}— ${message}${N}" ;;
            SKIP) echo -e "  ${DIM}○ ${name} — ${message}${N}" ;;
        esac
        if [[ -n "$explanation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${DIM}ℹ️  ${explanation}${N}"
        fi
        if [[ -n "$risk" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${Y}⚠️  Risk: ${risk}${N}"
        fi
        if [[ -n "$recommendation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${M}🔧 ${recommendation}${N}"
        fi
        if [[ -n "$example" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${DIM}   Example: ${example}${N}"
        fi
    fi

    local esc_msg=$(echo "$message" | sed 's/"/\\"/g')
    local esc_expl=$(echo "$explanation" | sed 's/"/\\"/g')
    local esc_risk=$(echo "$risk" | sed 's/"/\\"/g')
    local esc_impact=$(echo "$impact" | sed 's/"/\\"/g')
    local esc_rec=$(echo "$recommendation" | sed 's/"/\\"/g')
    local esc_ex=$(echo "$example" | sed 's/"/\\"/g')
    local esc_ref=$(echo "$reference" | sed 's/"/\\"/g')
    RESULTS+=("{\"category\":\"${category}\",\"name\":\"${name}\",\"status\":\"${status}\",\"severity\":\"${severity}\",\"message\":\"${esc_msg}\",\"explanation\":\"${esc_expl}\",\"risk\":\"${esc_risk}\",\"impact\":\"${esc_impact}\",\"recommendation\":\"${esc_rec}\",\"example\":\"${esc_ex}\",\"reference\":\"${esc_ref}\"}")
}

print_section() {
    [[ "$OPT_QUIET" -eq 0 ]] && echo -e "\n${C}${BOLD}${2:-▸} ${1}${N}" && echo -e "${DIM}$(printf '─%.0s' {1..60})${N}"
}

# ═══════════════════════════════════════════════════════════════
#  AUDIT FUNCTIONS
# ═══════════════════════════════════════════════════════════════

audit_detection() {
    print_section "Nginx Detection" "🔍"

    if [[ -z "$NGINX_BIN" ]]; then
        add_result "detection" "Nginx Binary" "FAIL" "CRITICAL" "Nginx not found" "Cannot perform audit" "Install: apt install nginx" "" "" ""
        return 1
    fi
    add_result "detection" "Nginx Binary" "PASS" "INFO" "Found: $NGINX_BIN" "" "" "" "" ""

    if [[ -z "$NGINX_CONF" ]]; then
        add_result "detection" "Config File" "FAIL" "CRITICAL" "Config not found" "Cannot audit" "Check installation" "" "" ""
        return 1
    fi
    add_result "detection" "Config File" "PASS" "INFO" "$NGINX_CONF" "" "" "" "" ""

    local version=$($NGINX_BIN -v 2>&1 | grep -oP 'nginx/\K[\d.]+')
    [[ -n "$version" ]] && add_result "detection" "Version" "INFO" "INFO" "$version" "" "" "" "" ""

    if systemctl is-active --quiet nginx 2>/dev/null; then
        add_result "detection" "Service Status" "PASS" "INFO" "Running" "" "" "" "" ""
    else
        add_result "detection" "Service Status" "WARN" "MEDIUM" "Not running" "Nginx is not active" "Start: systemctl start nginx" "" "" ""
    fi
    return 0
}

audit_security_headers() {
    print_section "Security Headers" "🛡️"

    # server_tokens
    local tokens=$(grep -rni "server_tokens" "$NGINX_CONF" /etc/nginx/conf.d/ /etc/nginx/sites-enabled/ 2>/dev/null | head -1)
    if echo "$tokens" | grep -qi "off"; then
        add_result "headers" "server_tokens" "PASS" "LOW" "Off — version hidden" "" "" "" "" ""
    else
        add_result "headers" "server_tokens" "FAIL" "MEDIUM" "Not set or On — version exposed" \
            "Exposing Nginx version helps attackers find known vulnerabilities" \
            "Targeted attacks based on version" \
            "Add 'server_tokens off;' to http block" \
            "server_tokens off;" "https://nginx.org/en/docs/http/ngx_http_core_module.html#server_tokens"
    fi

    # X-Frame-Options
    local xframe=$(grep -rni "X-Frame-Options" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$xframe" ]]; then
        add_result "headers" "X-Frame-Options" "PASS" "MEDIUM" "Configured" "" "" "" "" ""
    else
        add_result "headers" "X-Frame-Options" "FAIL" "MEDIUM" "Not configured" \
            "Without X-Frame-Options, site can be embedded in iframes (Clickjacking)" \
            "Users tricked into clicking hidden elements" \
            "Add 'add_header X-Frame-Options DENY;'" \
            'add_header X-Frame-Options "DENY";' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    fi

    # X-Content-Type-Options
    local xcto=$(grep -rni "X-Content-Type-Options" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$xcto" ]]; then
        add_result "headers" "X-Content-Type-Options" "PASS" "MEDIUM" "Configured" "" "" "" "" ""
    else
        add_result "headers" "X-Content-Type-Options" "FAIL" "MEDIUM" "Not configured" \
            "Browsers may MIME-sniff responses" \
            "XSS via content type confusion" \
            "Add 'add_header X-Content-Type-Options nosniff;'" \
            'add_header X-Content-Type-Options "nosniff";' ""
    fi

    # Content-Security-Policy
    local csp=$(grep -rni "Content-Security-Policy" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$csp" ]]; then
        add_result "headers" "Content-Security-Policy" "PASS" "HIGH" "Configured" "" "" "" "" ""
    else
        add_result "headers" "Content-Security-Policy" "FAIL" "HIGH" "Not configured" \
            "CSP prevents XSS and code injection attacks" \
            "Major security risk" \
            "Implement Content Security Policy" \
            'add_header Content-Security-Policy "default-src '"'"'self'"'"'";' ""
    fi

    # Strict-Transport-Security
    local hsts=$(grep -rni "Strict-Transport-Security" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$hsts" ]]; then
        add_result "headers" "Strict-Transport-Security" "PASS" "HIGH" "Configured" "" "" "" "" ""
    else
        add_result "headers" "Strict-Transport-Security" "FAIL" "HIGH" "Not configured" \
            "HSTS forces HTTPS, preventing SSL stripping" \
            "MITM attacks possible" \
            "Add HSTS header (if HTTPS configured)" \
            'add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;' ""
    fi

    # Referrer-Policy
    local refpol=$(grep -rni "Referrer-Policy" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$refpol" ]]; then
        add_result "headers" "Referrer-Policy" "PASS" "MEDIUM" "Configured" "" "" "" "" ""
    else
        add_result "headers" "Referrer-Policy" "WARN" "MEDIUM" "Not configured" \
            "May leak URL paths to external sites" \
            "Information disclosure" \
            "Add Referrer-Policy header" \
            'add_header Referrer-Policy "strict-origin-when-cross-origin" always;' ""
    fi

    # Permissions-Policy
    local permpol=$(grep -rni "Permissions-Policy\|Feature-Policy" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$permpol" ]]; then
        add_result "headers" "Permissions-Policy" "PASS" "MEDIUM" "Configured" "" "" "" "" ""
    else
        add_result "headers" "Permissions-Policy" "WARN" "MEDIUM" "Not configured" \
            "Browser features (camera, mic) not restricted" \
            "Third-party scripts may access sensitive features" \
            "Add Permissions-Policy header" \
            'add_header Permissions-Policy "camera=(), microphone=(), geolocation=()" always;' ""
    fi
}

audit_ssl() {
    print_section "SSL/TLS Configuration" "🔒"

    local ssl_block=$(grep -rn "ssl_protocols\|ssl_certificate\|listen.*443.*ssl" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -z "$ssl_block" ]]; then
        add_result "ssl" "SSL" "SKIP" "INFO" "No SSL config found" "" "" "" "" ""
        return
    fi

    # ssl_protocols
    local protocols=$(grep -rni "ssl_protocols" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$protocols" ]]; then
        if echo "$protocols" | grep -qi "SSLv2\|SSLv3\|TLSv1\b\|TLSv1.0"; then
            add_result "ssl" "ssl_protocols" "FAIL" "CRITICAL" "Insecure protocols enabled" \
                "SSLv2/SSLv3/TLSv1.0 have known vulnerabilities" \
                "Traffic decryption possible" \
                "Use: ssl_protocols TLSv1.2 TLSv1.3;" \
                "ssl_protocols TLSv1.2 TLSv1.3;" ""
        else
            add_result "ssl" "ssl_protocols" "PASS" "HIGH" "Secure protocols only" "" "" "" "" ""
        fi
    fi

    # ssl_prefer_server_ciphers
    local prefer=$(grep -rni "ssl_prefer_server_ciphers" /etc/nginx/ 2>/dev/null | head -1)
    if echo "$prefer" | grep -qi "on"; then
        add_result "ssl" "ssl_prefer_server_ciphers" "PASS" "MEDIUM" "On — server controls cipher order" "" "" "" "" ""
    else
        add_result "ssl" "ssl_prefer_server_ciphers" "WARN" "MEDIUM" "Not set or off" \
            "Server should control cipher order" \
            "Clients could choose weaker ciphers" \
            "Set 'ssl_prefer_server_ciphers on;'" \
            "ssl_prefer_server_ciphers on;" ""
    fi

    # ssl_ciphers
    local ciphers=$(grep -rni "ssl_ciphers" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$ciphers" ]]; then
        if echo "$ciphers" | grep -qi "RC4\|DES\|3DES\|NULL\|EXPORT"; then
            add_result "ssl" "ssl_ciphers" "FAIL" "CRITICAL" "Weak ciphers detected" \
                "Weak ciphers can be cracked" \
                "Encrypted traffic decryption" \
                "Use modern cipher suite" \
                "ssl_ciphers 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256';" ""
        else
            add_result "ssl" "ssl_ciphers" "PASS" "HIGH" "Configured" "" "" "" "" ""
        fi
    fi

    # ssl_stapling
    local stapling=$(grep -rni "ssl_stapling" /etc/nginx/ 2>/dev/null | head -1)
    if echo "$stapling" | grep -qi "on"; then
        add_result "ssl" "ssl_stapling" "PASS" "MEDIUM" "On — OCSP stapling enabled" "" "" "" "" ""
    else
        add_result "ssl" "ssl_stapling" "WARN" "MEDIUM" "Not enabled" \
            "OCSP stapling improves SSL handshake performance" \
            "Slower SSL connections" \
            "Enable ssl_stapling" \
            "ssl_stapling on;" ""
    fi
}

audit_server_config() {
    print_section "Server Configuration" "⚙️"

    # autoindex
    local autoindex=$(grep -rni "autoindex" /etc/nginx/ 2>/dev/null | head -1)
    if echo "$autoindex" | grep -qi "on"; then
        add_result "server" "autoindex" "FAIL" "HIGH" "Enabled — directory listing" \
            "Directory listing exposes all files" \
            "Sensitive files discoverable" \
            "Set 'autoindex off;'" \
            "autoindex off;" ""
    else
        add_result "server" "autoindex" "PASS" "HIGH" "Disabled" "" "" "" "" ""
    fi

    # client_max_body_size
    local maxbody=$(grep -rni "client_max_body_size" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$maxbody" ]]; then
        local size=$(echo "$maxbody" | awk '{print $NF}' | tr -d ';')
        add_result "server" "client_max_body_size" "INFO" "INFO" "$size" "" "" "" "" ""
    else
        add_result "server" "client_max_body_size" "WARN" "LOW" "Default (1M)" \
            "Default may be too small or too large for your needs" \
            "" \
            "Set appropriate limit" \
            "client_max_body_size 10M;" ""
    fi

    # server_names_hash_bucket_size
    local hashsize=$(grep -rni "server_names_hash_bucket_size" /etc/nginx/ 2>/dev/null | head -1)
    [[ -n "$hashsize" ]] && add_result "server" "server_names_hash" "INFO" "INFO" "Configured" "" "" "" "" ""

    # Limit request methods
    local limit_except=$(grep -rni "limit_except" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$limit_except" ]]; then
        add_result "server" "HTTP Methods" "PASS" "MEDIUM" "Restricted" "" "" "" "" ""
    else
        add_result "server" "HTTP Methods" "WARN" "MEDIUM" "No method restrictions" \
            "All HTTP methods allowed (GET, POST, PUT, DELETE, etc.)" \
            "Unnecessary methods could be exploited" \
            "Use limit_except to restrict methods" \
            "limit_except GET POST { deny all; }" ""
    fi
}

audit_access_control() {
    print_section "Access Control" "🔐"

    # Default server (catch-all)
    local default_server=$(grep -rn "default_server\|server_name _" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$default_server" ]]; then
        add_result "access" "Default Server" "PASS" "MEDIUM" "Configured — catches unknown hosts" "" "" "" "" ""
    else
        add_result "access" "Default Server" "WARN" "MEDIUM" "Not configured" \
            "Without default_server, first server block handles unknown hosts" \
            "Could expose unintended content" \
            "Add default_server to catch unmatched requests" \
            "listen 80 default_server;" ""
    fi

    # Sensitive files
    local sensitive=$(grep -rn "location.*\.\(env\|git\|htaccess\|bak\|sql\|log\)" /etc/nginx/ 2>/dev/null)
    if [[ -n "$sensitive" ]]; then
        add_result "access" "Sensitive Files" "PASS" "HIGH" "Blocked in config" "" "" "" "" ""
    else
        add_result "access" "Sensitive Files" "FAIL" "HIGH" "No protection for sensitive files" \
            ".env, .git, .htaccess, .bak files could be accessed" \
            "Credentials, source code, backups exposed" \
            "Add location blocks to deny access" \
            'location ~ /\. { deny all; }' ""
    fi
}

audit_logging() {
    print_section "Logging" "📋"

    local error_log=$(grep -rn "error_log" "$NGINX_CONF" 2>/dev/null | head -1)
    if [[ -n "$error_log" ]]; then
        add_result "logging" "Error Log" "PASS" "INFO" "Configured" "" "" "" "" ""
    else
        add_result "logging" "Error Log" "WARN" "MEDIUM" "Not configured in main context" \
            "Error logging is essential for debugging and security" \
            "Cannot detect attacks" \
            "Configure error_log" \
            "error_log /var/log/nginx/error.log warn;" ""
    fi

    local access_log=$(grep -rn "access_log" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$access_log" ]]; then
        add_result "logging" "Access Log" "PASS" "INFO" "Configured" "" "" "" "" ""
    else
        add_result "logging" "Access Log" "WARN" "MEDIUM" "Not configured" \
            "Access logging records all requests" \
            "Cannot track activity or detect attacks" \
            "Configure access_log" \
            "access_log /var/log/nginx/access.log;" ""
    fi
}

audit_performance() {
    print_section "Performance & Caching" "⚡"

    # gzip
    local gzip=$(grep -rni "gzip" /etc/nginx/ 2>/dev/null | grep -i "on" | head -1)
    if [[ -n "$gzip" ]]; then
        add_result "performance" "gzip" "PASS" "INFO" "Enabled" "" "" "" "" ""
    else
        add_result "performance" "gzip" "WARN" "LOW" "Not enabled" \
            "gzip reduces bandwidth and improves load times" \
            "Slower page loads" \
            "Enable gzip" \
            "gzip on;" ""
    fi

    # keepalive
    local keepalive=$(grep -rni "keepalive_timeout" /etc/nginx/ 2>/dev/null | head -1)
    if [[ -n "$keepalive" ]]; then
        add_result "performance" "keepalive" "PASS" "INFO" "Configured" "" "" "" "" ""
    fi

    # worker_connections
    local workers=$(grep -rni "worker_connections" /etc/nginx/ 2>/dev/null | head -1)
    [[ -n "$workers" ]] && add_result "performance" "worker_connections" "INFO" "INFO" "Configured" "" "" "" "" ""
}

# ═══════════════════════════════════════════════════════════════
#  OUTPUT GENERATORS
# ═══════════════════════════════════════════════════════════════

calculate_score() {
    [[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100 + INFO * 50) / TOTAL )) && [[ $SCORE -gt 100 ]] && SCORE=100
}

print_summary() {
    [[ "$OPT_QUIET" -eq 1 ]] && return
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════${N}"
    echo -e "${BOLD}  AUDIT COMPLETE${N}"
    echo -e "${BOLD}════════════════════════════════════════════${N}"
    echo ""
    local sc="$G"; [[ "$SCORE" -lt 70 ]] && sc="$R"; [[ "$SCORE" -lt 85 ]] && sc="$Y"
    echo -e "  Security Score: ${sc}${BOLD}${SCORE}/100${N}"
    echo ""
    echo -e "  ${G}✓ Passed:${N}   $PASS  ${Y}⚠ Warnings:${N} $WARN  ${R}✗ Failed:${N}   $FAIL"
    echo -e "  ${B}ℹ Info:${N}      $INFO  ${DIM}○ Skipped:${N}  $SKIP  ${W}Total:${N}      $TOTAL"
    echo ""
    [[ "$OPT_HTML" -eq 1 ]] && echo -e "  HTML: $REPORT_HTML"
    [[ "$OPT_JSON" -eq 1 ]] && echo -e "  JSON: $REPORT_JSON"
    [[ "$OPT_TXT" -eq 1 ]]  && echo -e "  TXT:  $REPORT_TXT"
    echo ""
}

generate_json() {
    local arr=""; for i in "${!RESULTS[@]}"; do [[ $i -gt 0 ]] && arr+=","; arr+="${RESULTS[$i]}"; done
    cat > "$REPORT_JSON" <<EOF
{
  "tool": "nawasec-audit-nginx", "version": "$VERSION", "timestamp": "$(date -Iseconds)",
  "nginx": {"binary": "$NGINX_BIN", "config": "$NGINX_CONF"},
  "score": $SCORE,
  "summary": {"total": $TOTAL, "pass": $PASS, "warn": $WARN, "fail": $FAIL, "info": $INFO, "skip": $SKIP},
  "results": [$arr]
}
EOF
}

generate_html() {
    local sc_color="#10b981"; [[ "$SCORE" -lt 70 ]] && sc_color="#ef4444"; [[ "$SCORE" -lt 85 ]] && sc_color="#f59e0b"
    cat > "$REPORT_HTML" <<'HTMLHEAD'
<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NawaSec Audit — Nginx Security Report</title>
<style>
:root{--bg:#06060f;--card:#0d0d1a;--border:#1a1a2e;--text:#e2e8f0;--muted:#64748b;--pass:#10b981;--warn:#f59e0b;--fail:#ef4444;--info:#3b82f6}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:0 auto;line-height:1.6}
h1{font-size:1.5rem;font-weight:800}.sub{color:var(--muted);font-size:.85rem;margin-bottom:2rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.8rem;margin-bottom:2rem}
.c{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.2rem;text-align:center}
.c-val{font-size:1.8rem;font-weight:800}.c-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}
.section{font-size:1rem;font-weight:700;margin:2.5rem 0 .8rem;padding:.6rem 0;border-bottom:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:1.5rem}
th{text-align:left;padding:.5rem .7rem;background:var(--card);color:var(--muted);font-size:.7rem;text-transform:uppercase}
td{padding:.5rem .7rem;border-bottom:1px solid var(--border);vertical-align:top}
.badge{display:inline-block;padding:.12rem .45rem;border-radius:100px;font-size:.68rem;font-weight:600}
.b-pass{background:rgba(16,185,129,.12);color:var(--pass)}.b-warn{background:rgba(245,158,11,.12);color:var(--warn)}
.b-fail{background:rgba(239,68,68,.12);color:var(--fail)}.b-info{background:rgba(59,130,246,.12);color:var(--info)}
.rem{color:var(--pass);font-size:.72rem;margin-top:.3rem;padding:.3rem .5rem;background:rgba(16,185,129,.06);border-left:2px solid var(--pass);border-radius:4px}
.expl{color:var(--muted);font-size:.72rem;margin-top:.2rem;padding:.2rem .4rem;background:rgba(59,130,246,.04);border-left:2px solid var(--info);border-radius:4px}
footer{text-align:center;padding:2rem 0;color:#334155;font-size:.72rem;border-top:1px solid var(--border);margin-top:2rem}
</style></head><body>
HTMLHEAD
    cat >> "$REPORT_HTML" <<EOF
<h1>🔒 NawaSec Audit — Nginx Security</h1>
<p class="sub">$(hostname) — $(date)</p>
<div class="cards">
<div class="c"><div class="c-val" style="color:${sc_color}">${SCORE}</div><div class="c-lbl">Score</div></div>
<div class="c"><div class="c-val" style="color:var(--pass)">${PASS}</div><div class="c-lbl">Passed</div></div>
<div class="c"><div class="c-val" style="color:var(--warn)">${WARN}</div><div class="c-lbl">Warnings</div></div>
<div class="c"><div class="c-val" style="color:var(--fail)">${FAIL}</div><div class="c-lbl">Failed</div></div>
<div class="c"><div class="c-val" style="color:var(--info)">${TOTAL}</div><div class="c-lbl">Total</div></div>
</div>
EOF
    local current_cat=""
    for entry in "${RESULTS[@]}"; do
        local cat=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['category'])" 2>/dev/null)
        local name=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['name'])" 2>/dev/null)
        local status=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])" 2>/dev/null)
        local msg=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['message'])" 2>/dev/null)
        local explanation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('explanation',''))" 2>/dev/null)
        local recommendation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recommendation',''))" 2>/dev/null)
        if [[ "$cat" != "$current_cat" ]]; then
            [[ -n "$current_cat" ]] && echo "</tbody></table>" >> "$REPORT_HTML"
            current_cat="$cat"
            echo "<div class='section'>${cat^^}</div>" >> "$REPORT_HTML"
            echo "<table><thead><tr><th>Status</th><th>Check</th><th>Details</th></tr></thead><tbody>" >> "$REPORT_HTML"
        fi
        local bc="b-info"; case "$status" in PASS) bc="b-pass";; WARN) bc="b-warn";; FAIL) bc="b-fail";; esac
        echo "<tr><td><span class='badge ${bc}'>${status}</span></td><td>${name}</td><td>${msg}" >> "$REPORT_HTML"
        [[ -n "$explanation" ]] && echo "<div class='expl'>ℹ️ ${explanation}</div>" >> "$REPORT_HTML"
        [[ -n "$recommendation" ]] && echo "<div class='rem'>🔧 ${recommendation}</div>" >> "$REPORT_HTML"
        echo "</td></tr>" >> "$REPORT_HTML"
    done
    echo "</tbody></table><footer>NawaSec Audit v${VERSION} — Nginx Security — https://github.com/kangaman/nawasec-audit</footer></body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — Nginx Security Report                       ║
║  Version: ${VERSION}                                          ║
╚══════════════════════════════════════════════════════════════╝
Hostname: $(hostname)  |  Date: $(date)  |  Score: ${SCORE}/100
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
EOF
    local current_cat=""
    for entry in "${RESULTS[@]}"; do
        local cat=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['category'])" 2>/dev/null)
        local name=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['name'])" 2>/dev/null)
        local status=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])" 2>/dev/null)
        local severity=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('severity',''))" 2>/dev/null)
        local msg=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['message'])" 2>/dev/null)
        local explanation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('explanation',''))" 2>/dev/null)
        local recommendation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recommendation',''))" 2>/dev/null)
        [[ "$cat" != "$current_cat" ]] && current_cat="$cat" && echo "" >> "$REPORT_TXT" && echo "━━━ ${cat^^} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_TXT"
        echo "  [${status}] ${name} (${severity})" >> "$REPORT_TXT"
        echo "      ${msg}" >> "$REPORT_TXT"
        [[ -n "$explanation" ]] && echo "      ℹ️ ${explanation}" >> "$REPORT_TXT"
        [[ -n "$recommendation" ]] && echo "      🔧 ${recommendation}" >> "$REPORT_TXT"
    done
    cat >> "$REPORT_TXT" <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score: ${SCORE}/100 | Pass: $PASS | Warn: $WARN | Fail: $FAIL | Total: $TOTAL
  NawaSec Audit v${VERSION} — https://github.com/kangaman/nawasec-audit
EOF
}

main() {
    [[ "$EUID" -ne 0 ]] && { echo -e "${R}Error: Run as root${N}" >&2; exit 1; }
    setup_colors
    detect_nginx
    [[ "$OPT_QUIET" -eq 0 ]] && echo -e "${C}${BOLD}  ╔═══════════════════════════════════════════════════════╗\n  ║  NawaSec Audit — Nginx Security                      ║\n  ║  v${VERSION}                                            ║\n  ╚═══════════════════════════════════════════════════════╝${N}\n"
    if audit_detection; then
        audit_security_headers
        audit_ssl
        audit_server_config
        audit_access_control
        audit_logging
        audit_performance
    fi
    calculate_score
    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]]  && generate_txt

    # Return non-zero if any FAILs, useful for CI wrappers
    [[ "$FAIL" -gt 0 ]] && exit 2 || exit 0
}

main "$@"
