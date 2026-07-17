#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — Apache HTTP Server Security Audit                      ║
# ║  Version: 1.0.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based Apache security audit — NO AI, NO external API calls.
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-apache.sh [options]
#
# Options:
#   --html          Generate HTML dashboard (default)
#   --json          Generate JSON report
#   --txt           Generate TXT report
#   --all           Generate all formats
#   --quiet         Minimal console output
#   --no-color      Disable colored output
#   --output DIR    Custom output directory
#   --help          Show help

set -uo pipefail

# ── Version ──
VERSION="1.0.0"
SCRIPT_NAME="NawaSec Audit - Apache"

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

# ── Counters ──
PASS=0; WARN=0; FAIL=0; INFO=0; SKIP=0; TOTAL=0; SCORE=100

# ── Arrays ──
declare -a RESULTS=()

# ── Options ──
OPT_HTML=1; OPT_JSON=0; OPT_TXT=0; OPT_QUIET=0
OUTPUT_DIR="/tmp/nawasec-apache"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# ── Parse arguments ──
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
            echo ""
            echo "NawaSec Audit - Apache v${VERSION}"
            echo ""
            echo "Options:"
            echo "  --html        Generate HTML dashboard (default)"
            echo "  --json        Generate JSON report"
            echo "  --txt         Generate TXT report"
            echo "  --all         Generate all formats"
            echo "  --quiet       Minimal console output"
            echo "  --no-color    Disable colors"
            echo "  --output DIR  Custom output directory"
            echo "  --help        Show this help"
            exit 0
            ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ── Init ──
mkdir -p "$OUTPUT_DIR"
REPORT_HTML="$OUTPUT_DIR/apache-audit-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/apache-audit-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/apache-audit-${TIMESTAMP}.txt"

# ── Detect Apache ──
APACHE_CONF=""
APACHE_BIN=""
APACHE_USER=""
APACHE_GROUP=""

detect_apache() {
    # Detect Apache binary
    if command -v httpd &>/dev/null; then
        APACHE_BIN="httpd"
    elif command -v apache2 &>/dev/null; then
        APACHE_BIN="apache2"
    elif [[ -f /usr/sbin/httpd ]]; then
        APACHE_BIN="/usr/sbin/httpd"
    elif [[ -f /usr/sbin/apache2 ]]; then
        APACHE_BIN="/usr/sbin/apache2"
    else
        APACHE_BIN=""
    fi

    # Detect config file
    if [[ -f /etc/httpd/conf/httpd.conf ]]; then
        APACHE_CONF="/etc/httpd/conf/httpd.conf"
    elif [[ -f /etc/apache2/apache2.conf ]]; then
        APACHE_CONF="/etc/apache2/apache2.conf"
    elif [[ -f /usr/local/apache2/conf/httpd.conf ]]; then
        APACHE_CONF="/usr/local/apache2/conf/httpd.conf"
    else
        APACHE_CONF=""
    fi

    # Detect user/group
    if [[ -n "$APACHE_CONF" ]]; then
        APACHE_USER=$(grep -i "^User " "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
        APACHE_GROUP=$(grep -i "^Group " "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    fi
    APACHE_USER="${APACHE_USER:-www-data}"
    APACHE_GROUP="${APACHE_GROUP:-www-data}"
}

# ── Helper: Add result ──
add_result() {
    local category="$1" name="$2" status="$3" severity="$4" message="$5"
    local explanation="${6:-}" risk="${7:-}" impact="${8:-}" recommendation="${9:-}" example="${10:-}" reference="${11:-}"
    TOTAL=$((TOTAL + 1))

    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        WARN) WARN=$((WARN + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        INFO) INFO=$((INFO + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
    esac

    # Console
    if [[ "$OPT_QUIET" -eq 0 ]]; then
        case "$status" in
            PASS) echo -e "  ${G}✓${N} ${name} ${DIM}— ${message}${N}" ;;
            WARN) echo -e "  ${Y}⚠${N} ${name} ${DIM}— ${message}${N}" ;;
            FAIL) echo -e "  ${R}✗${N} ${name} ${DIM}— ${message}${N}" ;;
            INFO) echo -e "  ${B}ℹ${N} ${name} ${DIM}— ${message}${N}" ;;
            SKIP) echo -e "  ${DIM}○ ${name} — ${message}${N}" ;;
        esac
        if [[ -n "$explanation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${DIM}ℹ️ ${explanation}${N}"
        fi
        if [[ -n "$recommendation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${M}🔧 ${recommendation}${N}"
        fi
    fi

    # Store for JSON (escape special chars)
    local esc_msg=$(echo "$message" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_expl=$(echo "$explanation" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_risk=$(echo "$risk" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_impact=$(echo "$impact" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_rec=$(echo "$recommendation" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_ex=$(echo "$example" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_ref=$(echo "$reference" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    RESULTS+=("{\"category\":\"${category}\",\"name\":\"${name}\",\"status\":\"${status}\",\"severity\":\"${severity}\",\"message\":\"${esc_msg}\",\"explanation\":\"${esc_expl}\",\"risk\":\"${esc_risk}\",\"impact\":\"${esc_impact}\",\"recommendation\":\"${esc_rec}\",\"example\":\"${esc_ex}\",\"reference\":\"${esc_ref}\"}")
}

# ── Helper: Print section ──
print_section() {
    local title="$1" icon="${2:-▸}"
    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "\n${C}${BOLD}${icon} ${title}${N}"
        echo -e "${DIM}$(printf '─%.0s' {1..60})${N}"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  AUDIT FUNCTIONS
# ═══════════════════════════════════════════════════════════════

# ──1. APACHE DETECTION ──
audit_detection() {
    print_section "Apache Detection" "🔍"

    # Check if Apache is installed
    if [[ -z "$APACHE_BIN" ]]; then
        add_result "detection" "Apache Binary" "FAIL" "CRITICAL" \
            "Apache not found" \
            "Apache HTTP Server is not installed or not in PATH" \
            "Cannot perform audit without Apache" \
            "Install Apache: apt install apache2 or yum install httpd" \
            "" ""
        return 1
    fi
    add_result "detection" "Apache Binary" "PASS" "INFO" \
        "Found: $APACHE_BIN" \
        "" "" "" "" ""

    # Check if config exists
    if [[ -z "$APACHE_CONF" ]]; then
        add_result "detection" "Config File" "FAIL" "CRITICAL" \
            "Config not found" \
            "Apache configuration file not found" \
            "Cannot audit configuration" \
            "Check Apache installation" \
            "" ""
        return 1
    fi
    add_result "detection" "Config File" "PASS" "INFO" \
        "$APACHE_CONF" \
        "" "" "" "" ""

    # Check version
    local version=$($APACHE_BIN -v 2>/dev/null | grep "Server version" | awk -F'/' '{print $2}' | awk '{print $1}')
    if [[ -n "$version" ]]; then
        add_result "detection" "Version" "INFO" "INFO" \
            "$version" \
            "" "" "" "" ""
    fi

    # Check if running
    if systemctl is-active --quiet httpd 2>/dev/null || systemctl is-active --quiet apache2 2>/dev/null; then
        add_result "detection" "Service Status" "PASS" "INFO" \
            "Running" \
            "" "" "" "" ""
    else
        add_result "detection" "Service Status" "WARN" "MEDIUM" \
            "Not running" \
            "Apache service is not active" \
            "Web server is not serving requests" \
            "Start Apache: systemctl start httpd/apache2" \
            "" ""
    fi

    return 0
}

# ──2. SECURITY HEADERS ──
audit_headers() {
    print_section "Security Headers" "🛡️"

    # ServerTokens
    local tokens=$(grep -i "^ServerTokens" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$tokens" == "Prod" ]] || [[ "$tokens" == "ProductOnly" ]]; then
        add_result "headers" "ServerTokens" "PASS" "LOW" \
            "$tokens — Minimal info exposed" \
            "ServerTokens controls how much server info is revealed" \
            "Exposing version helps attackers find known vulnerabilities" \
            "" "" "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"
    elif [[ -z "$tokens" ]]; then
        add_result "headers" "ServerTokens" "FAIL" "MEDIUM" \
            "Not set — defaults to Full" \
            "ServerTokens defaults to 'Full' which exposes Apache version, OS, and modules" \
            "Attackers can target specific known vulnerabilities" \
            "Add 'ServerTokens Prod' to $APACHE_CONF" \
            "ServerTokens Prod" "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"
    else
        add_result "headers" "ServerTokens" "WARN" "MEDIUM" \
            "$tokens — Consider using 'Prod'" \
            "Current setting exposes more info than necessary" \
            "Information disclosure aids reconnaissance" \
            "Set 'ServerTokens Prod'" \
            "ServerTokens Prod" "https://httpd.apache.org/docs/2.4/mod/core.html#servertokens"
    fi

    # ServerSignature
    local sig=$(grep -i "^ServerSignature" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$sig" == "Off" ]]; then
        add_result "headers" "ServerSignature" "PASS" "LOW" \
            "Off — No signature in error pages" \
            "" "" "" "" ""
    elif [[ -z "$sig" ]]; then
        add_result "headers" "ServerSignature" "WARN" "LOW" \
            "Not set — defaults to On" \
            "ServerSignature adds server info to error pages and directory listings" \
            "Information disclosure" \
            "Add 'ServerSignature Off'" \
            "ServerSignature Off" "https://httpd.apache.org/docs/2.4/mod/core.html#serversignature"
    else
        add_result "headers" "ServerSignature" "WARN" "LOW" \
            "$sig" \
            "ServerSignature should be Off in production" \
            "Information disclosure" \
            "Set 'ServerSignature Off'" \
            "ServerSignature Off" "https://httpd.apache.org/docs/2.4/mod/core.html#serversignature"
    fi

    # X-Frame-Options
    local xframe=$(grep -ri "X-Frame-Options" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -n "$xframe" ]]; then
        add_result "headers" "X-Frame-Options" "PASS" "MEDIUM" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "headers" "X-Frame-Options" "FAIL" "MEDIUM" \
            "Not configured" \
            "Without X-Frame-Options, site can be embedded in iframes (Clickjacking)" \
            "Users can be tricked into clicking hidden elements" \
            "Add 'Header always set X-Frame-Options DENY'" \
            'Header always set X-Frame-Options "DENY"' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options"
    fi

    # X-Content-Type-Options
    local xcto=$(grep -ri "X-Content-Type-Options" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -n "$xcto" ]]; then
        add_result "headers" "X-Content-Type-Options" "PASS" "MEDIUM" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "headers" "X-Content-Type-Options" "FAIL" "MEDIUM" \
            "Not configured" \
            "Without this header, browsers may MIME-sniff responses" \
            "Can lead to XSS attacks via content type confusion" \
            "Add 'Header always set X-Content-Type-Options nosniff'" \
            'Header always set X-Content-Type-Options "nosniff"' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options"
    fi

    # X-XSS-Protection
    local xxss=$(grep -ri "X-XSS-Protection" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -n "$xxss" ]]; then
        add_result "headers" "X-XSS-Protection" "PASS" "LOW" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "headers" "X-XSS-Protection" "WARN" "LOW" \
            "Not configured" \
            "Legacy XSS filter header not set" \
            "Older browsers may not enable XSS protection" \
            "Add 'Header always set X-XSS-Protection 1; mode=block'" \
            'Header always set X-XSS-Protection "1; mode=block"' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection"
    fi

    # Content-Security-Policy
    local csp=$(grep -ri "Content-Security-Policy" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -n "$csp" ]]; then
        add_result "headers" "Content-Security-Policy" "PASS" "HIGH" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "headers" "Content-Security-Policy" "FAIL" "HIGH" \
            "Not configured" \
            "CSP prevents XSS, data injection, and other code injection attacks" \
            "Major security risk without CSP" \
            "Implement a Content Security Policy" \
            'Header always set Content-Security-Policy "default-src '"'"'self'"'"'"' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy"
    fi

    # Strict-Transport-Security
    local hsts=$(grep -ri "Strict-Transport-Security" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -n "$hsts" ]]; then
        add_result "headers" "Strict-Transport-Security" "PASS" "HIGH" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "headers" "Strict-Transport-Security" "FAIL" "HIGH" \
            "Not configured" \
            "HSTS forces browsers to use HTTPS, preventing SSL stripping attacks" \
            "Man-in-the-middle attacks possible on HTTP" \
            "Add HSTS header (only if HTTPS is configured)" \
            'Header always set Strict-Transport-Security "max-age=31536000; includeSubDomains"' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security"
    fi

    # Referrer-Policy
    local refpol=$(grep -ri "Referrer-Policy" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -n "$refpol" ]]; then
        add_result "headers" "Referrer-Policy" "PASS" "MEDIUM" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "headers" "Referrer-Policy" "WARN" "MEDIUM" \
            "Not configured" \
            "Referrer-Policy controls how much referrer info is sent" \
            "May leak sensitive URL paths to external sites" \
            "Add 'Header always set Referrer-Policy strict-origin-when-cross-origin'" \
            'Header always set Referrer-Policy "strict-origin-when-cross-origin"' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy"
    fi

    # Permissions-Policy
    local permpol=$(grep -ri "Permissions-Policy\|Feature-Policy" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -n "$permpol" ]]; then
        add_result "headers" "Permissions-Policy" "PASS" "MEDIUM" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "headers" "Permissions-Policy" "WARN" "MEDIUM" \
            "Not configured" \
            "Permissions-Policy restricts browser features (camera, mic, geolocation)" \
            "Third-party scripts may access sensitive features" \
            "Add Permissions-Policy header" \
            'Header always set Permissions-Policy "camera=(), microphone=(), geolocation=()"' "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy"
    fi
}

# ──3. DIRECTORY SECURITY ──
audit_directories() {
    print_section "Directory Security" "📂"

    # DocumentRoot permissions
    local docroot=$(grep -i "^DocumentRoot" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ -n "$docroot" ]] && [[ -d "$docroot" ]]; then
        local perms=$(stat -c "%a" "$docroot" 2>/dev/null)
        if [[ "$perms" -le 755 ]]; then
            add_result "directories" "DocumentRoot Perms" "PASS" "MEDIUM" \
                "$docroot ($perms)" \
                "" "" "" "" ""
        else
            add_result "directories" "DocumentRoot Perms" "WARN" "MEDIUM" \
                "$docroot ($perms) — too permissive" \
                "DocumentRoot should not be world-writable" \
                "Attackers could modify website files" \
                "chmod 755 $docroot" \
                "chmod 755 $docroot" ""
        fi
    else
        add_result "directories" "DocumentRoot" "SKIP" "INFO" \
            "Not found or not accessible" \
            "" "" "" "" ""
    fi

    # Directory listing
    local listing=$(grep -i "Options.*Indexes" "$APACHE_CONF" 2>/dev/null)
    if [[ -n "$listing" ]]; then
        add_result "directories" "Directory Listing" "FAIL" "HIGH" \
            "Enabled — files can be browsed" \
            "Directory listing shows all files in a directory without index.html" \
            "Attackers can discover sensitive files (backups, configs, scripts)" \
            "Remove 'Indexes' from Options directive" \
            "Options -Indexes" "https://httpd.apache.org/docs/2.4/mod/core.html#options"
    else
        add_result "directories" "Directory Listing" "PASS" "HIGH" \
            "Disabled" \
            "" "" "" "" ""
    fi

    # .htaccess override
    local override=$(grep -i "AllowOverride" "$APACHE_CONF" 2>/dev/null | grep -i "All" | head -1)
    if [[ -n "$override" ]]; then
        add_result "directories" "AllowOverride" "WARN" "MEDIUM" \
            "AllowOverride All — .htaccess can override everything" \
            "AllowOverride All lets .htfiles override any Apache directive" \
            "Compromised .htaccess could change security settings" \
            "Use 'AllowOverride None' or limit to specific directives" \
            "AllowOverride FileInfo AuthConfig" "https://httpd.apache.org/docs/2.4/mod/core.html#allowoverride"
    else
        add_result "directories" "AllowOverride" "PASS" "MEDIUM" \
            "Restricted" \
            "" "" "" "" ""
    fi

    # FollowSymLinks
    local symlinks=$(grep -i "Options.*FollowSymLinks" "$APACHE_CONF" 2>/dev/null)
    if [[ -n "$symlinks" ]]; then
        add_result "directories" "FollowSymLinks" "WARN" "MEDIUM" \
            "Enabled" \
            "FollowSymLinks allows Apache to follow symbolic links" \
            "Symlink attacks could expose files outside DocumentRoot" \
            "Replace with 'Options SymLinksIfOwnerMatch'" \
            "Options -FollowSymLinks +SymLinksIfOwnerMatch" "https://httpd.apache.org/docs/2.4/mod/core.html#options"
    else
        add_result "directories" "FollowSymLinks" "PASS" "MEDIUM" \
            "Disabled or restricted" \
            "" "" "" "" ""
    fi
}

# ──4. MODULES SECURITY ──
audit_modules() {
    print_section "Modules Security" "⚙️"

    # Check loaded modules
    local modules=""
    if $APACHE_BIN -M 2>/dev/null | grep -q "loaded"; then
        modules=$($APACHE_BIN -M 2>/dev/null)
    fi

    # Dangerous modules
    local dangerous_mods=("status" "info" "autoindex" "userdir" "proxy" "proxy_http" "proxy_ftp" "proxy_connect" "php" "php5" "php7" "php8")
    for mod in "${dangerous_mods[@]}"; do
        if echo "$modules" | grep -qi "${mod}_module"; then
            case "$mod" in
                status|info)
                    add_result "modules" "Module: $mod" "WARN" "MEDIUM" \
                        "Loaded — exposes server info" \
                        "mod_status/mod_info expose detailed server information" \
                        "Information disclosure aids attackers" \
                        "Disable or restrict access: <Location /server-status> Require ip 127.0.0.1 </Location>" \
                        "LoadModule ${mod}_module modules/mod_${mod}.so" ""
                    ;;
                autoindex)
                    add_result "modules" "Module: $mod" "WARN" "MEDIUM" \
                        "Loaded — directory browsing" \
                        "mod_autoindex enables directory listing" \
                        "Files can be browsed without index.html" \
                        "Disable: a2dismod autoindex" \
                        "" ""
                    ;;
                userdir)
                    add_result "modules" "Module: $mod" "WARN" "MEDIUM" \
                        "Loaded — user directories" \
                        "mod_userdir serves content from ~/public_html" \
                        "May expose user home directories" \
                        "Disable if not needed: a2dismod userdir" \
                        "" ""
                    ;;
                proxy|proxy_http|proxy_ftp|proxy_connect)
                    add_result "modules" "Module: $mod" "WARN" "HIGH" \
                        "Loaded — proxy capability" \
                        "Proxy modules can be abused for SSRF attacks" \
                        "Attackers could use server as proxy to reach internal systems" \
                        "Disable if not needed, or restrict with <Proxy> directives" \
                        "" "https://httpd.apache.org/docs/2.4/mod/mod_proxy.html"
                    ;;
            esac
        fi
    done

    # mod_rewrite (usually OK)
    if echo "$modules" | grep -qi "rewrite_module"; then
        add_result "modules" "Module: rewrite" "PASS" "INFO" \
            "Loaded — URL rewriting" \
            "" "" "" "" ""
    fi

    # mod_ssl
    if echo "$modules" | grep -qi "ssl_module"; then
        add_result "modules" "Module: ssl" "PASS" "INFO" \
            "Loaded — SSL/TLS support" \
            "" "" "" "" ""
    else
        add_result "modules" "Module: ssl" "WARN" "HIGH" \
            "Not loaded" \
            "mod_ssl is required for HTTPS" \
            "Cannot serve encrypted traffic" \
            "Enable: a2enmod ssl" \
            "" ""
    fi

    # mod_headers
    if echo "$modules" | grep -qi "headers_module"; then
        add_result "modules" "Module: headers" "PASS" "INFO" \
            "Loaded — custom headers" \
            "" "" "" "" ""
    else
        add_result "modules" "Module: headers" "WARN" "MEDIUM" \
            "Not loaded" \
            "mod_headers is needed for security headers (HSTS, CSP, etc.)" \
            "Cannot set custom security headers" \
            "Enable: a2enmod headers" \
            "" ""
    fi
}

# ──5. SSL/TLS CONFIGURATION ──
audit_ssl() {
    print_section "SSL/TLS Configuration" "🔒"

    # Check if mod_ssl is loaded
    if ! $APACHE_BIN -M 2>/dev/null | grep -qi "ssl_module"; then
        add_result "ssl" "SSL Module" "SKIP" "INFO" \
            "mod_ssl not loaded" \
            "" "" "" "" ""
        return
    fi

    # Check for SSL config
    local ssl_conf=$(grep -rn "SSLEngine\|SSLProtocol\|SSLCipherSuite" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1)
    if [[ -z "$ssl_conf" ]]; then
        add_result "ssl" "SSL Configuration" "SKIP" "INFO" \
            "No SSL config found" \
            "" "" "" "" ""
        return
    fi

    # SSLProtocol
    local protocol=$(grep -rni "SSLProtocol" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    if [[ -n "$protocol" ]]; then
        if echo "$protocol" | grep -qi "SSLv2\|SSLv3\|TLSv1\b\|TLSv1.0"; then
            add_result "ssl" "SSLProtocol" "FAIL" "CRITICAL" \
                "$protocol — insecure protocols enabled" \
                "SSLv2/SSLv3/TLSv1.0 have known vulnerabilities (POODLE, BEAST)" \
                "Attackers can decrypt SSL/TLS traffic" \
                "Use: SSLProtocol -all +TLSv1.2 +TLSv1.3" \
                'SSLProtocol -all +TLSv1.2 +TLSv1.3' "https://httpd.apache.org/docs/2.4/mod/mod_ssl.html#sslprotocol"
        else
            add_result "ssl" "SSLProtocol" "PASS" "HIGH" \
                "$protocol" \
                "" "" "" "" ""
        fi
    fi

    # SSLCipherSuite
    local ciphers=$(grep -rni "SSLCipherSuite" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1 | awk -F'"' '{print $2}')
    if [[ -n "$ciphers" ]]; then
        if echo "$ciphers" | grep -qi "RC4\|DES\|3DES\|MD5\|NULL\|EXPORT"; then
            add_result "ssl" "SSLCipherSuite" "FAIL" "CRITICAL" \
                "Weak ciphers detected" \
                "Weak ciphers can be cracked or have known attacks" \
                "Encrypted traffic could be decrypted" \
                "Use modern cipher suite" \
                'SSLCipherSuite ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384' ""
        else
            add_result "ssl" "SSLCipherSuite" "PASS" "HIGH" \
                "Configured" \
                "" "" "" "" ""
        fi
    fi

    # SSLHonorCipherOrder
    local honor=$(grep -rni "SSLHonorCipherOrder" /etc/httpd/ /etc/apache2/ 2>/dev/null | head -1 | awk '{print $2}' | tr -d '"')
    if [[ "$honor" == "On" ]]; then
        add_result "ssl" "SSLHonorCipherOrder" "PASS" "MEDIUM" \
            "On — server chooses cipher order" \
            "" "" "" "" ""
    else
        add_result "ssl" "SSLHonorCipherOrder" "WARN" "MEDIUM" \
            "Not set or Off" \
            "Server should control cipher order, not client" \
            "Clients could choose weaker ciphers" \
            "Set 'SSLHonorCipherOrder On'" \
            "SSLHonorCipherOrder On" ""
    fi
}

# ──6. ACCESS CONTROL ──
audit_access() {
    print_section "Access Control" "🔐"

    # Check for Require directives
    local require_all=$(grep -rn "Require all granted" "$APACHE_CONF" /etc/httpd/conf.d/ /etc/apache2/sites-enabled/ 2>/dev/null | wc -l | xargs)
    if [[ "$require_all" -gt 0 ]]; then
        add_result "access" "Access Control" "WARN" "MEDIUM" \
            "Require all granted found ($require_all locations)" \
            "Some locations allow unrestricted access" \
            "May expose sensitive directories" \
            "Review and restrict access where needed" \
            "<Directory /path> Require ip 192.168.1.0/24 </Directory>" ""
    fi

    # Check for .htaccess files
    local htaccess=$(find /var/www/ /home/*/public_html/ -name ".htaccess" 2>/dev/null | wc -l | xargs)
    if [[ "$htaccess" -gt 0 ]]; then
        add_result "access" ".htaccess Files" "INFO" "INFO" \
            "$htaccess files found" \
            ".htaccess files can override server configuration" \
            "" "" "" ""
    fi

    # Check for authentication
    local auth=$(grep -rn "AuthType\|AuthUserFile\|Require user\|Require group" "$APACHE_CONF" /etc/httpd/conf.d/ /etc/apache2/sites-enabled/ 2>/dev/null | wc -l | xargs)
    if [[ "$auth" -gt 0 ]]; then
        add_result "access" "Authentication" "PASS" "INFO" \
            "Authentication configured" \
            "" "" "" "" ""
    fi
}

# ──7. LOGGING ──
audit_logging() {
    print_section "Logging" "📋"

    # Error log
    local error_log=$(grep -i "^ErrorLog" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ -n "$error_log" ]]; then
        add_result "logging" "Error Log" "PASS" "INFO" \
            "$error_log" \
            "" "" "" "" ""
    else
        add_result "logging" "Error Log" "WARN" "MEDIUM" \
            "Not configured" \
            "Error logging is essential for debugging and security monitoring" \
            "Cannot detect attacks or troubleshoot issues" \
            "Configure ErrorLog directive" \
            "ErrorLog \${APACHE_LOG_DIR}/error.log" ""
    fi

    # Custom log
    local access_log=$(grep -i "^CustomLog\|TransferLog" "$APACHE_CONF" 2>/dev/null | head -1)
    if [[ -n "$access_log" ]]; then
        add_result "logging" "Access Log" "PASS" "INFO" \
            "Configured" \
            "" "" "" "" ""
    else
        add_result "logging" "Access Log" "WARN" "MEDIUM" \
            "Not configured" \
            "Access logging records all requests for analysis" \
            "Cannot track user activity or detect attacks" \
            "Configure CustomLog directive" \
            'CustomLog ${APACHE_LOG_DIR}/access.log combined' ""
    fi

    # Log level
    local loglevel=$(grep -i "^LogLevel" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$loglevel" == "warn" ]] || [[ "$loglevel" == "info" ]]; then
        add_result "logging" "Log Level" "PASS" "INFO" \
            "$loglevel" \
            "" "" "" "" ""
    elif [[ -z "$loglevel" ]]; then
        add_result "logging" "Log Level" "PASS" "INFO" \
            "Default (warn)" \
            "" "" "" "" ""
    else
        add_result "logging" "Log Level" "WARN" "LOW" \
            "$loglevel — may be too verbose" \
            "Verbose logging can fill disk and impact performance" \
            "" \
            "Use 'LogLevel warn' for production" \
            "LogLevel warn" ""
    fi
}

# ──8. PERFORMANCE & CACHING ──
audit_performance() {
    print_section "Performance & Caching" "⚡"

    # KeepAlive
    local keepalive=$(grep -i "^KeepAlive" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$keepalive" == "On" ]] || [[ "$keepalive" == "On" ]]; then
        add_result "performance" "KeepAlive" "PASS" "INFO" \
            "On — connection reuse enabled" \
            "" "" "" "" ""
    else
        add_result "performance" "KeepAlive" "WARN" "LOW" \
            "Off or not set" \
            "KeepAlive improves performance by reusing connections" \
            "More connections needed, higher latency" \
            "Set 'KeepAlive On'" \
            "KeepAlive On" ""
    fi

    # MaxKeepAliveRequests
    local maxka=$(grep -i "^MaxKeepAliveRequests" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ -n "$maxka" ]] && [[ "$maxka" -gt 0 ]]; then
        add_result "performance" "MaxKeepAliveRequests" "PASS" "INFO" \
            "$maxka" \
            "" "" "" "" ""
    fi

    # Timeout
    local timeout=$(grep -i "^Timeout" "$APACHE_CONF" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ -n "$timeout" ]]; then
        if [[ "$timeout" -gt 300 ]]; then
            add_result "performance" "Timeout" "WARN" "LOW" \
                "${timeout}s — may be too long" \
                "Long timeouts can tie up resources during attacks" \
                "Slowloris-style DoS attacks" \
                "Set 'Timeout 60'" \
                "Timeout 60" ""
        else
            add_result "performance" "Timeout" "PASS" "INFO" \
                "${timeout}s" \
                "" "" "" "" ""
        fi
    fi
}

# ═══════════════════════════════════════════════════════════════
#  OUTPUT GENERATORS
# ═══════════════════════════════════════════════════════════════

calculate_score() {
    if [[ $TOTAL -gt 0 ]]; then
        SCORE=$(( (PASS * 100 + INFO * 50) / TOTAL ))
        [[ $SCORE -gt 100 ]] && SCORE=100
    fi
}

print_summary() {
    [[ "$OPT_QUIET" -eq 1 ]] && return
    echo ""
    echo -e "${BOLD}════════════════════════════════════════════${N}"
    echo -e "${BOLD}  AUDIT COMPLETE${N}"
    echo -e "${BOLD}════════════════════════════════════════════${N}"
    echo ""

    local sc="$G"
    [[ "$SCORE" -lt 70 ]] && sc="$R"
    [[ "$SCORE" -lt 85 ]] && sc="$Y"

    echo -e "  Security Score: ${sc}${BOLD}${SCORE}/100${N}"
    echo ""
    echo -e "  ${G}✓ Passed:${N}   $PASS"
    echo -e "  ${Y}⚠ Warnings:${N} $WARN"
    echo -e "  ${R}✗ Failed:${N}   $FAIL"
    echo -e "  ${B}ℹ Info:${N}      $INFO"
    echo -e "  ${DIM}○ Skipped:${N}  $SKIP"
    echo -e "  ─────────────────────"
    echo -e "  ${W}Total:${N}      $TOTAL"
    echo ""
    echo -e "  ${DIM}Reports:${N}"
    [[ "$OPT_HTML" -eq 1 ]] && echo -e "    HTML: $REPORT_HTML"
    [[ "$OPT_JSON" -eq 1 ]] && echo -e "    JSON: $REPORT_JSON"
    [[ "$OPT_TXT" -eq 1 ]]  && echo -e "    TXT:  $REPORT_TXT"
    echo ""
}

generate_json() {
    local arr=""
    for i in "${!RESULTS[@]}"; do
        [[ $i -gt 0 ]] && arr+=","
        arr+="${RESULTS[$i]}"
    done

    cat > "$REPORT_JSON" <<EOF
{
  "tool": "nawasec-audit-apache",
  "version": "$VERSION",
  "timestamp": "$(date -Iseconds)",
  "apache": {
    "binary": "$APACHE_BIN",
    "config": "$APACHE_CONF",
    "user": "$APACHE_USER",
    "group": "$APACHE_GROUP"
  },
  "score": $SCORE,
  "summary": {
    "total": $TOTAL,
    "pass": $PASS,
    "warn": $WARN,
    "fail": $FAIL,
    "info": $INFO,
    "skip": $SKIP
  },
  "results": [
    $arr
  ]
}
EOF
}

generate_html() {
    local sc_color="#10b981"
    [[ "$SCORE" -lt 70 ]] && sc_color="#ef4444"
    [[ "$SCORE" -lt 85 ]] && sc_color="#f59e0b"

    cat > "$REPORT_HTML" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>NawaSec Audit — Apache Security Report</title>
<style>
:root{--bg:#06060f;--card:#0d0d1a;--border:#1a1a2e;--text:#e2e8f0;--muted:#64748b;--pass:#10b981;--warn:#f59e0b;--fail:#ef4444;--info:#3b82f6}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:0 auto;line-height:1.6}
h1{font-size:1.5rem;font-weight:800}.sub{color:var(--muted);font-size:.85rem;margin-bottom:2rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.8rem;margin-bottom:2rem}
.c{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.2rem;text-align:center}
.c-val{font-size:1.8rem;font-weight:800}.c-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}
.section{font-size:1rem;font-weight:700;margin:2.5rem 0 .8rem;padding:.6rem 0;border-bottom:1px solid var(--border);display:flex;align-items:center;gap:.5rem}
table{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:1.5rem}
th{text-align:left;padding:.5rem .7rem;background:var(--card);color:var(--muted);font-size:.7rem;text-transform:uppercase;letter-spacing:.04em}
td{padding:.5rem .7rem;border-bottom:1px solid var(--border);vertical-align:top}
.badge{display:inline-block;padding:.12rem .45rem;border-radius:100px;font-size:.68rem;font-weight:600}
.b-pass{background:rgba(16,185,129,.12);color:var(--pass)}.b-warn{background:rgba(245,158,11,.12);color:var(--warn)}
.b-fail{background:rgba(239,68,68,.12);color:var(--fail)}.b-info{background:rgba(59,130,246,.12);color:var(--info)}
.b-skip{background:rgba(100,116,139,.12);color:var(--muted)}
.sev{display:inline-block;padding:.1rem .35rem;border-radius:100px;font-size:.62rem;font-weight:600;margin-left:.3rem}
.s-critical{background:rgba(239,68,68,.2);color:#ef4444}.s-high{background:rgba(245,158,11,.2);color:#f59e0b}
.s-medium{background:rgba(59,130,246,.2);color:#3b82f6}.s-low{background:rgba(100,116,139,.2);color:#94a3b8}
.rem{color:var(--pass);font-size:.72rem;margin-top:.3rem;padding:.3rem .5rem;background:rgba(16,185,129,.06);border-left:2px solid var(--pass);border-radius:4px}
.expl{color:var(--muted);font-size:.72rem;margin-top:.2rem;padding:.2rem .4rem;background:rgba(59,130,246,.04);border-left:2px solid var(--info);border-radius:4px}
footer{text-align:center;padding:2rem 0;color:#334155;font-size:.72rem;border-top:1px solid var(--border);margin-top:2rem}
@media(max-width:640px){.cards{grid-template-columns:repeat(2,1fr)}body{padding:1rem}}
</style>
</head>
<body>
HTMLHEAD

    cat >> "$REPORT_HTML" <<EOF
<h1>🔒 NawaSec Audit — Apache Security</h1>
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
        local severity=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('severity',''))" 2>/dev/null)
        local msg=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['message'])" 2>/dev/null)
        local explanation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('explanation',''))" 2>/dev/null)
        local recommendation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recommendation',''))" 2>/dev/null)

        if [[ "$cat" != "$current_cat" ]]; then
            [[ -n "$current_cat" ]] && echo "</tbody></table>" >> "$REPORT_HTML"
            current_cat="$cat"
            echo "<div class='section'>${cat^^}</div>" >> "$REPORT_HTML"
            echo "<table><thead><tr><th>Status</th><th>Check</th><th>Details</th></tr></thead><tbody>" >> "$REPORT_HTML"
        fi

        local bc="b-info"
        case "$status" in PASS) bc="b-pass";; WARN) bc="b-warn";; FAIL) bc="b-fail";; SKIP) bc="b-skip";; esac

        local sev_class=""
        local sev_badge=""
        if [[ -n "$severity" ]] && [[ "$severity" != "INFO" ]]; then
            sev_class="s-$(echo "$severity" | tr '[:upper:]' '[:lower:]')"
            sev_badge="<span class='sev ${sev_class}'>${severity}</span>"
        fi

        echo "<tr><td><span class='badge ${bc}'>${status}</span>${sev_badge}</td><td>${name}</td><td>${msg}" >> "$REPORT_HTML"
        [[ -n "$explanation" ]] && echo "<div class='expl'>ℹ️ ${explanation}</div>" >> "$REPORT_HTML"
        [[ -n "$recommendation" ]] && echo "<div class='rem'>🔧 ${recommendation}</div>" >> "$REPORT_HTML"
        echo "</td></tr>" >> "$REPORT_HTML"
    done

    echo "</tbody></table>" >> "$REPORT_HTML"
    echo "<footer>NawaSec Audit v${VERSION} — Apache Security — Generated $(date) — https://github.com/kangaman/nawasec-audit</footer>" >> "$REPORT_HTML"
    echo "</body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — Apache Security Report                      ║
║  Version: ${VERSION}                                          ║
╚══════════════════════════════════════════════════════════════╝

Hostname: $(hostname)
Date:     $(date)
Score:    ${SCORE}/100

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

        if [[ "$cat" != "$current_cat" ]]; then
            current_cat="$cat"
            echo "" >> "$REPORT_TXT"
            echo "━━━ ${cat^^} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_TXT"
        fi

        echo "  [${status}] ${name} (${severity})" >> "$REPORT_TXT"
        echo "      ${msg}" >> "$REPORT_TXT"
        [[ -n "$explanation" ]] && echo "      ℹ️ ${explanation}" >> "$REPORT_TXT"
        [[ -n "$recommendation" ]] && echo "      🔧 ${recommendation}" >> "$REPORT_TXT"
    done

    cat >> "$REPORT_TXT" <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score:  ${SCORE}/100
  Passed: ${PASS}  |  Warnings: ${WARN}  |  Failed: ${FAIL}
  Info:   ${INFO}  |  Skipped: ${SKIP}   |  Total: ${TOTAL}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NawaSec Audit v${VERSION} — Apache Security
  https://github.com/kangaman/nawasec-audit
EOF
}

# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

main() {
    [[ "$EUID" -ne 0 ]] && { echo -e "${R}Error: Run as root (sudo $0)${N}" >&2; exit 1; }

    setup_colors
    detect_apache

    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "${C}${BOLD}"
        echo "  ╔═══════════════════════════════════════════════════════╗"
        echo "  ║  NawaSec Audit — Apache Security                     ║"
        echo "  ║  v${VERSION}                                            ║"
        echo "  ╚═══════════════════════════════════════════════════════╝"
        echo -e "${N}"
        echo -e "  ${DIM}Started: $(date)${N}"
        echo ""
    fi

    # Run audits
    if audit_detection; then
        audit_headers
        audit_directories
        audit_modules
        audit_ssl
        audit_access
        audit_logging
        audit_performance
    fi

    # Calculate & output
    calculate_score
    print_summary

    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]]  && generate_txt

    exit 0
}

main "$@"
