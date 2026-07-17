#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — DNS Security Audit                                    ║
# ║  Version: 2.1.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based DNS security audit — NO AI, NO external API calls.
# Supports: BIND 9, systemd-resolved, /etc/resolv.conf
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-dns.sh [options]
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

# ═══════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════

VERSION="2.1.0"
SCRIPT_NAME="NawaSec Audit - DNS"
FRAMEWORK_VERSION="2.0.0"

# ═══════════════════════════════════════════════════════════════
#  COLORS & FORMATTING
# ═══════════════════════════════════════════════════════════════

setup_colors() {
    if [[ "${NO_COLOR:-}" == "1" ]] || [[ "$TERM" == "dumb" ]]; then
        R=''; G=''; Y=''; B=''; C=''; M=''; W=''; N=''; BOLD=''; DIM=''
    else
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
        C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; N='\033[0m'
        BOLD='\033[1m'; DIM='\033[2m'
    fi
}

# ═══════════════════════════════════════════════════════════════
#  COUNTERS & ARRAYS
# ═══════════════════════════════════════════════════════════════

PASS=0; WARN=0; FAIL=0; INFO=0; SKIP=0; TOTAL=0; SCORE=100
declare -a RESULTS=()

# ═══════════════════════════════════════════════════════════════
#  OPTIONS
# ═══════════════════════════════════════════════════════════════

OPT_HTML=1; OPT_JSON=0; OPT_TXT=0; OPT_QUIET=0
OUTPUT_DIR="/tmp/nawasec-dns"
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
            echo ""
            echo "NawaSec Audit - DNS v${VERSION}"
            echo "Framework: NawaSec Audit v${FRAMEWORK_VERSION}"
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

# ═══════════════════════════════════════════════════════════════
#  INITIALIZATION
# ═══════════════════════════════════════════════════════════════

mkdir -p "$OUTPUT_DIR"
REPORT_HTML="$OUTPUT_DIR/nawasec-dns-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/nawasec-dns-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/nawasec-dns-${TIMESTAMP}.txt"

# ═══════════════════════════════════════════════════════════════
#  STANDARD add_result FUNCTION (NawaSec Template v2.1.0)
# ═══════════════════════════════════════════════════════════════

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

# ═══════════════════════════════════════════════════════════════
#  STANDARD print_section FUNCTION
# ═══════════════════════════════════════════════════════════════

print_section() {
    local title="$1"
    local icon="${2:-▸}"
    [[ "$OPT_QUIET" -eq 0 ]] && echo -e "\n${C}${BOLD}${icon} ${title}${N}" && echo -e "${DIM}$(printf '─%.0s' {1..60})${N}"
}

# ═══════════════════════════════════════════════════════════════
#  DETECTION
# ═══════════════════════════════════════════════════════════════

DNS_TYPE=""
NAMED_CONF=""
RESOLV_CONF="/etc/resolv.conf"

detect_dns() {
    print_section "DNS Detection" "🔍"

    # Check for BIND/named
    if command -v named &>/dev/null || command -v bind9 &>/dev/null; then
        DNS_TYPE="bind"
        NAMED_CONF="/etc/bind/named.conf"
        [[ ! -f "$NAMED_CONF" ]] && NAMED_CONF="/etc/named.conf"
        [[ ! -f "$NAMED_CONF" ]] && NAMED_CONF="/etc/named/named.conf"
        add_result "detection" "BIND/named" "PASS" "INFO" \
            "Found: $(command -v named 2>/dev/null || command -v bind9 2>/dev/null)" "" "" "" "" ""
    fi

    # Check for systemd-resolved
    if systemctl is-active --quiet systemd-resolved 2>/dev/null; then
        if [[ -z "$DNS_TYPE" ]]; then
            DNS_TYPE="systemd-resolved"
        fi
        add_result "detection" "systemd-resolved" "PASS" "INFO" \
            "Running" "" "" "" "" ""
    fi

    # Check resolv.conf
    if [[ -f "$RESOLV_CONF" ]]; then
        add_result "detection" "resolv.conf" "PASS" "INFO" \
            "Found: $RESOLV_CONF" "" "" "" "" ""
    fi

    # Check if any DNS found
    if [[ -z "$DNS_TYPE" ]] && [[ ! -f "$RESOLV_CONF" ]]; then
        add_result "detection" "DNS" "FAIL" "CRITICAL" \
            "No DNS configuration found" \
            "No BIND, systemd-resolved, or resolv.conf detected" \
            "DNS resolution may not work" \
            "Install BIND: apt install bind9" \
            "apt install bind9" \
            ""
        return 1
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════
#  BIND/NAMED AUDIT
# ═══════════════════════════════════════════════════════════════

audit_bind() {
    print_section "BIND/named Security" "🔒"

    if [[ -z "$NAMED_CONF" ]] || [[ ! -f "$NAMED_CONF" ]]; then
        add_result "config" "Config File" "WARN" "HIGH" \
            "BIND config not found" \
            "Cannot audit BIND without named.conf" \
            "Security settings may be unknown" \
            "Check BIND installation" \
            "" ""
        return 1
    fi

    add_result "config" "Config File" "PASS" "INFO" \
        "$NAMED_CONF" "" "" "" "" ""

    # ── 1. Recursion ──
    print_section "Recursion Settings" "🔄"

    local recursion=$(grep -i "^recursion" "$NAMED_CONF" 2>/dev/null | awk '{print $2}' | tr -d ';')
    if [[ "$recursion" == "no" ]]; then
        add_result "recursion" "Recursion" "PASS" "HIGH" \
            "Disabled — Authoritative only" \
            "Server only answers for its own zones" \
            "" "" "" ""
    elif [[ "$recursion" == "yes" ]]; then
        add_result "recursion" "Recursion" "WARN" "HIGH" \
            "Enabled — Open resolver" \
            "Server performs recursive queries for anyone" \
            "DNS amplification attacks, cache poisoning" \
            "Disable recursion or restrict with allow-recursion" \
            "recursion no;" \
            "https://bind9.readthedocs.io/en/latest/reference.html"
    else
        add_result "recursion" "Recursion" "INFO" "HIGH" \
            "Not set — Defaults to yes" "" "" "" "" ""
    fi

    local allow_recursion=$(grep -i "allow-recursion" "$NAMED_CONF" 2>/dev/null | head -1)
    if [[ -n "$allow_recursion" ]]; then
        add_result "recursion" "Allow-Recursion" "PASS" "HIGH" \
            "Restricted: $allow_recursion" "" "" "" "" ""
    elif [[ "$recursion" == "yes" ]] || [[ -z "$recursion" ]]; then
        add_result "recursion" "Allow-Recursion" "WARN" "HIGH" \
            "Not restricted" \
            "Any client can use this server for recursive queries" \
            "DNS amplification attacks" \
            "Add: allow-recursion { trusted-nets; };" \
            "allow-recursion { 127.0.0.1; 10.0.0.0/8; };" \
            ""
    fi

    # ── 2. Zone Transfer ──
    print_section "Zone Transfer Security" "📤"

    local allow_transfer=$(grep -i "allow-transfer" "$NAMED_CONF" 2>/dev/null | head -1)
    if [[ -n "$allow_transfer" ]]; then
        if echo "$allow_transfer" | grep -qi "none"; then
            add_result "transfer" "Zone Transfer" "PASS" "HIGH" \
                "Disabled (none)" "" "" "" "" ""
        else
            add_result "transfer" "Zone Transfer" "PASS" "HIGH" \
                "Restricted: $allow_transfer" "" "" "" "" ""
        fi
    else
        add_result "transfer" "Zone Transfer" "WARN" "HIGH" \
            "Not restricted" \
            "Zone transfers allowed to any host" \
            "Full zone data can be downloaded by attackers" \
            "Add: allow-transfer { none; }; or restrict to slave servers" \
            "allow-transfer { none; };" \
            "https://bind9.readthedocs.io/en/latest/reference.html"
    fi

    # ── 3. Listen Configuration ──
    print_section "Listen Configuration" "🌐"

    local listen_on=$(grep -i "listen-on" "$NAMED_CONF" 2>/dev/null | head -1)
    if [[ -n "$listen_on" ]]; then
        if echo "$listen_on" | grep -qi "127.0.0.1\|localhost"; then
            add_result "listen" "Listen-On" "PASS" "HIGH" \
                "Localhost only" "" "" "" "" ""
        else
            add_result "listen" "Listen-On" "INFO" "HIGH" \
                "$listen_on" "" "" "" "" ""
        fi
    else
        add_result "listen" "Listen-On" "INFO" "HIGH" \
            "Not set — Listening on all interfaces" "" "" "" "" ""
    fi

    # ── 4. Query Logging ──
    print_section "Logging" "📝"

    local logging=$(grep -i "querylog" "$NAMED_CONF" 2>/dev/null | head -1)
    if echo "$logging" | grep -qi "yes\|on"; then
        add_result "logging" "Query Log" "PASS" "MEDIUM" \
            "Enabled" "" "" "" "" ""
    else
        add_result "logging" "Query Log" "INFO" "MEDIUM" \
            "Not enabled — Consider enabling for security monitoring" "" "" "" "" ""
    fi

    # ── 5. File Permissions ──
    print_section "File Permissions" "📁"

    if [[ -f "$NAMED_CONF" ]]; then
        local conf_perms=$(stat -c "%a" "$NAMED_CONF" 2>/dev/null)
        if [[ "$conf_perms" -le 640 ]]; then
            add_result "permissions" "named.conf" "PASS" "MEDIUM" \
                "Permissions: $conf_perms" "" "" "" "" ""
        else
            add_result "permissions" "named.conf" "WARN" "MEDIUM" \
                "Permissions: $conf_perms — Too open" \
                "Config may contain sensitive data (TSIG keys, ACLs)" \
                "Information disclosure" \
                "Set permissions to 640: chmod 640 $NAMED_CONF" \
                "chmod 640 $NAMED_CONF" \
                ""
        fi
    fi

    # Check zone files directory
    local zone_dir="/var/cache/bind"
    [[ -d "/var/named" ]] && zone_dir="/var/named"
    if [[ -d "$zone_dir" ]]; then
        local zone_perms=$(stat -c "%a" "$zone_dir" 2>/dev/null)
        if [[ "$zone_perms" -le 750 ]]; then
            add_result "permissions" "Zone Directory" "PASS" "MEDIUM" \
                "$zone_dir: $zone_perms" "" "" "" "" ""
        else
            add_result "permissions" "Zone Directory" "WARN" "MEDIUM" \
                "$zone_dir: $zone_perms — Too open" \
                "Zone files contain DNS records" \
                "Zone data can be read by unauthorized users" \
                "Set permissions to 750: chmod 750 $zone_dir" \
                "chmod 750 $zone_dir" \
                ""
        fi
    fi

    # ── 6. DNSSEC ──
    print_section "DNSSEC" "🔐"

    local dnssec=$(grep -i "dnssec-validation" "$NAMED_CONF" 2>/dev/null | head -1)
    if echo "$dnssec" | grep -qi "yes\|auto"; then
        add_result "dnssec" "DNSSEC Validation" "PASS" "HIGH" \
            "Enabled" "" "" "" "" ""
    elif echo "$dnssec" | grep -qi "no"; then
        add_result "dnssec" "DNSSEC Validation" "WARN" "HIGH" \
            "Disabled" \
            "DNS responses not cryptographically verified" \
            "Cache poisoning, DNS spoofing" \
            "Enable: dnssec-validation auto;" \
            "dnssec-validation auto;" \
            "https://bind9.readthedocs.io/en/latest/dnssec-guide.html"
    else
        add_result "dnssec" "DNSSEC Validation" "INFO" "HIGH" \
            "Not configured" "" "" "" "" ""
    fi

    # ── 7. Response Rate Limiting ──
    print_section "Rate Limiting" "⏱️"

    local rrl=$(grep -i "rate-limit" "$NAMED_CONF" 2>/dev/null | head -1)
    if [[ -n "$rrl" ]]; then
        add_result "ratelimit" "Response Rate Limiting" "PASS" "MEDIUM" \
            "Configured: $rrl" "" "" "" "" ""
    else
        add_result "ratelimit" "Response Rate Limiting" "INFO" "MEDIUM" \
            "Not configured — Consider enabling for DDoS protection" "" "" "" "" ""
    fi

    # ── 8. Forwarders ──
    print_section "Forwarders" "↗️"

    local forwarders=$(grep -i "forwarders" "$NAMED_CONF" 2>/dev/null | head -1)
    if [[ -n "$forwarders" ]]; then
        add_result "forwarders" "Forwarders" "INFO" "MEDIUM" \
            "Configured: $forwarders" "" "" "" "" ""
    else
        add_result "forwarders" "Forwarders" "INFO" "MEDIUM" \
            "Not configured — Using root hints" "" "" "" "" ""
    fi
}

# ═══════════════════════════════════════════════════════════════
#  RESOLV.CONF AUDIT
# ═══════════════════════════════════════════════════════════════

audit_resolv_conf() {
    print_section "resolv.conf Configuration" "📄"

    if [[ ! -f "$RESOLV_CONF" ]]; then
        add_result "resolv" "resolv.conf" "WARN" "MEDIUM" \
            "Not found" \
            "DNS resolution configuration missing" \
            "System cannot resolve domain names" \
            "Create /etc/resolv.conf with nameserver entries" \
            "echo 'nameserver 8.8.8.8' > /etc/resolv.conf" \
            ""
        return 1
    fi

    # Check nameservers
    local nameservers=$(grep -c "^nameserver" "$RESOLV_CONF" 2>/dev/null || echo "0")
    if [[ "$nameservers" -eq 0 ]]; then
        add_result "resolv" "Nameservers" "FAIL" "HIGH" \
            "No nameservers configured" \
            "No DNS servers configured for resolution" \
            "Domain name resolution will fail" \
            "Add nameserver entries to /etc/resolv.conf" \
            "nameserver 8.8.8.8" \
            ""
    elif [[ "$nameservers" -eq 1 ]]; then
        add_result "resolv" "Nameservers" "WARN" "MEDIUM" \
            "Only 1 nameserver — No redundancy" \
            "Single point of failure for DNS" \
            "DNS resolution fails if server is down" \
            "Add a second nameserver" \
            "nameserver 8.8.4.4" \
            ""
    else
        add_result "resolv" "Nameservers" "PASS" "MEDIUM" \
            "$nameservers nameservers configured" "" "" "" "" ""
    fi

    # Check for common public DNS
    if grep -q "8.8.8.8\|8.8.4.4\|1.1.1.1\|9.9.9.9" "$RESOLV_CONF" 2>/dev/null; then
        add_result "resolv" "Public DNS" "INFO" "LOW" \
            "Using public DNS (Google/Cloudflare/Quad9)" "" "" "" "" ""
    fi

    # Check search domain
    local search=$(grep "^search\|^domain" "$RESOLV_CONF" 2>/dev/null | head -1)
    if [[ -n "$search" ]]; then
        add_result "resolv" "Search Domain" "INFO" "LOW" \
            "$search" "" "" "" "" ""
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
  "tool": "nawasec-audit-dns",
  "version": "$VERSION",
  "framework": "$FRAMEWORK_VERSION",
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "dns_type": "$DNS_TYPE",
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
<title>NawaSec Audit — DNS Security Report</title>
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
.sev{display:inline-block;padding:.1rem .35rem;border-radius:100px;font-size:.62rem;font-weight:600;margin-left:.3rem}
.s-critical{background:rgba(239,68,68,.2);color:#ef4444}.s-high{background:rgba(245,158,11,.2);color:#f59e0b}
.s-medium{background:rgba(59,130,246,.2);color:#3b82f6}.s-low{background:rgba(100,116,139,.2);color:#94a3b8}
.expl{color:var(--info);font-size:.72rem;margin-top:.3rem;padding:.3rem .5rem;background:rgba(59,130,246,.06);border-left:2px solid var(--info);border-radius:4px}
.risk{color:var(--warn);font-size:.72rem;margin-top:.2rem;padding:.2rem .4rem;background:rgba(245,158,11,.06);border-left:2px solid var(--warn);border-radius:4px}
.rem{color:var(--pass);font-size:.72rem;margin-top:.3rem;padding:.3rem .5rem;background:rgba(16,185,129,.06);border-left:2px solid var(--pass);border-radius:4px}
.example{color:var(--muted);font-size:.7rem;margin-top:.2rem;padding:.2rem .4rem;background:rgba(100,116,139,.06);border-left:2px solid var(--muted);border-radius:4px;font-family:monospace}
footer{text-align:center;padding:2rem 0;color:#334155;font-size:.72rem;border-top:1px solid var(--border);margin-top:2rem}
@media(max-width:640px){.cards{grid-template-columns:repeat(2,1fr)}body{padding:1rem}}
</style>
</head>
<body>
HTMLHEAD

    cat >> "$REPORT_HTML" <<EOF
<h1>🔒 NawaSec Audit — DNS Security</h1>
<p class="sub">$(hostname) — $(date) — ${DNS_TYPE^} — v${VERSION}</p>
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
        local risk=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('risk',''))" 2>/dev/null)
        local recommendation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recommendation',''))" 2>/dev/null)
        local example=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('example',''))" 2>/dev/null)

        if [[ "$cat" != "$current_cat" ]]; then
            [[ -n "$current_cat" ]] && echo "</tbody></table>" >> "$REPORT_HTML"
            current_cat="$cat"
            echo "<div class='section'>${cat^^}</div>" >> "$REPORT_HTML"
            echo "<table><thead><tr><th>Status</th><th>Check</th><th>Details</th></tr></thead><tbody>" >> "$REPORT_HTML"
        fi

        local bc="b-info"
        case "$status" in PASS) bc="b-pass";; WARN) bc="b-warn";; FAIL) bc="b-fail";; esac

        local sev_badge=""
        if [[ -n "$severity" ]] && [[ "$severity" != "INFO" ]]; then
            sev_badge="<span class='sev s-$(echo "$severity" | tr '[:upper:]' '[:lower:]')'>${severity}</span>"
        fi

        echo "<tr><td><span class='badge ${bc}'>${status}</span>${sev_badge}</td><td>${name}</td><td>${msg}" >> "$REPORT_HTML"
        [[ -n "$explanation" ]] && echo "<div class='expl'>ℹ️ ${explanation}</div>" >> "$REPORT_HTML"
        [[ -n "$risk" ]] && echo "<div class='risk'>⚠️ Risk: ${risk}</div>" >> "$REPORT_HTML"
        [[ -n "$recommendation" ]] && echo "<div class='rem'>🔧 ${recommendation}</div>" >> "$REPORT_HTML"
        [[ -n "$example" ]] && echo "<div class='example'>\$ ${example}</div>" >> "$REPORT_HTML"
        echo "</td></tr>" >> "$REPORT_HTML"
    done

    echo "</tbody></table>" >> "$REPORT_HTML"
    echo "<footer>NawaSec Audit v${VERSION} — DNS Security — Generated $(date) — https://github.com/kangaman/nawasec-audit</footer>" >> "$REPORT_HTML"
    echo "</body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — DNS Security Report                         ║
║  Version: ${VERSION} (Framework: ${FRAMEWORK_VERSION})       ║
╚══════════════════════════════════════════════════════════════╝

Hostname:   $(hostname)
Date:       $(date)
DNS Type:   ${DNS_TYPE^}
Score:      ${SCORE}/100

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
        local risk=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('risk',''))" 2>/dev/null)
        local recommendation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recommendation',''))" 2>/dev/null)
        local example=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('example',''))" 2>/dev/null)

        if [[ "$cat" != "$current_cat" ]]; then
            current_cat="$cat"
            echo "" >> "$REPORT_TXT"
            echo "━━━ ${cat^^} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_TXT"
        fi

        echo "  [${status}] ${name} (${severity})" >> "$REPORT_TXT"
        echo "      ${msg}" >> "$REPORT_TXT"
        [[ -n "$explanation" ]] && echo "      ℹ️ ${explanation}" >> "$REPORT_TXT"
        [[ -n "$risk" ]] && echo "      ⚠️ Risk: ${risk}" >> "$REPORT_TXT"
        [[ -n "$recommendation" ]] && echo "      🔧 ${recommendation}" >> "$REPORT_TXT"
        [[ -n "$example" ]] && echo "      \$ ${example}" >> "$REPORT_TXT"
    done

    cat >> "$REPORT_TXT" <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score:  ${SCORE}/100
  Passed: ${PASS}  |  Warnings: ${WARN}  |  Failed: ${FAIL}
  Info:   ${INFO}  |  Skipped: ${SKIP}   |  Total: ${TOTAL}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NawaSec Audit v${VERSION} — DNS Security
  Framework: NawaSec Audit v${FRAMEWORK_VERSION}
  https://github.com/kangaman/nawasec-audit
EOF
}

# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

main() {
    [[ "$EUID" -ne 0 ]] && { echo -e "${R}Error: Run as root (sudo $0)${N}" >&2; exit 1; }

    setup_colors

    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "${C}${BOLD}"
        echo "  ╔═══════════════════════════════════════════════════════╗"
        echo "  ║  NawaSec Audit — DNS Security                        ║"
        echo "  ║  v${VERSION} (Framework v${FRAMEWORK_VERSION})                        ║"
        echo "  ╚═══════════════════════════════════════════════════════╝"
        echo -e "${N}"
        echo -e "  ${DIM}Started: $(date)${N}"
        echo ""
    fi

    # Detect DNS
    detect_dns || true

    # Run audit
    case "$DNS_TYPE" in
        bind) audit_bind ;;
    esac

    # Always audit resolv.conf
    audit_resolv_conf

    # Calculate & output
    calculate_score
    print_summary

    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]]  && generate_txt

    exit 0
}

main "$@"
