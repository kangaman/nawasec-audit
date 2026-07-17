#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — cPanel & WHM Security Audit                            ║
# ║  Version: 1.0.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based cPanel/WHM security audit — NO AI, NO external API calls.
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-cpanel.sh [options]

set -uo pipefail

VERSION="2.1.0"
FRAMEWORK_VERSION="2.0.0"
FRAMEWORK_VERSION="2.0.0"
SCRIPT_NAME="NawaSec Audit - cPanel"

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
OUTPUT_DIR="/tmp/nawasec-cpanel"
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
            echo "NawaSec Audit - cPanel v${VERSION}"
            echo "Options: --html --json --txt --all --quiet --no-color --output DIR --help"
            exit 0 ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
REPORT_HTML="$OUTPUT_DIR/cpanel-audit-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/cpanel-audit-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/cpanel-audit-${TIMESTAMP}.txt"

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

audit_cpanel_detection() {
    print_section "cPanel Detection" "🔍"

    if [[ ! -d /usr/local/cpanel ]]; then
        add_result "detection" "cPanel" "FAIL" "CRITICAL" \
            "cPanel not found" \
            "This system does not have cPanel installed" \
            "" \
            "Install cPanel: https://docs.cpanel.net/installation-guide/" \
            "" \
            "" ""
        return 1
    fi
        add_result "detection" "cPanel" "PASS" "INFO" \
            "Found at /usr/local/cpanel" \
            "" \
            "" \
            "" \
            "" \
            "" ""

    local cpanel_version=$(cat /usr/local/cpanel/version 2>/dev/null || echo "unknown")
        add_result "detection" "cPanel Version" "INFO" "INFO" \
            "$cpanel_version" \
            "" \
            "" \
            "" \
            "" \
            "" ""

    if systemctl is-active --quiet cpanel 2>/dev/null || /usr/local/cpanel/cpsrvd status 2>/dev/null | grep -q "running"; then
        add_result "detection" "cpsrvd" "PASS" "INFO" \
            "Running" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "detection" "cpsrvd" "WARN" "HIGH" \
            "Not running" \
            "cPanel service is not active" \
            "" \
            "Start: /usr/local/cpanel/startup" \
            "" \
            "" ""
    fi

    # WHM access
    local whm_port=$(ss -tlnp 2>/dev/null | grep -c ":2087" || echo "0")
    if [[ "$whm_port" -gt 0 ]]; then
        add_result "detection" "WHM Port" "PASS" "INFO" \
            "2087 open" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    fi

    return 0
}

audit_whm_security() {
    print_section "WHM Security" "🛡️"

    # Check if whm API is accessible
    if [[ -f /var/cpanel/authn/api_tokens/root/cpanel.json ]]; then
        add_result "whm" "API Tokens" "INFO" "INFO" \
            "Root API tokens exist" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    fi

    # Check Tweak Settings
    local tweak_conf="/var/cpanel/cpanel.config"
    if [[ -f "$tweak_conf" ]]; then
        # Require SSL
        local require_ssl=$(grep "^requiressl=" "$tweak_conf" 2>/dev/null | cut -d= -f2)
        if [[ "$require_ssl" == "1" ]]; then
        add_result "whm" "Require SSL" "PASS" "HIGH" \
            "Enabled — WHM requires HTTPS" \
            "" \
            "" \
            "" \
            "" \
            "" ""
        else
        add_result "whm" "Require SSL" "FAIL" "HIGH" \
            "Disabled — WHM accessible via HTTP" \
            "WHM login credentials sent in plaintext" \
            "Credential theft via network sniffing" \
            "Enable in WHM: Tweak Settings > Require SSL" \
            "requiressl=1" \
            "" ""
        fi

        # Referrer security
        local refsec=$(grep "^referrerblanksafety=" "$tweak_conf" 2>/dev/null | cut -d= -f2)
        if [[ "$refsec" == "1" ]]; then
        add_result "whm" "Referrer Security" "PASS" "MEDIUM" \
            "Enabled" \
            "" \
            "" \
            "" \
            "" \
            "" ""
        else
        add_result "whm" "Referrer Security" "WARN" "MEDIUM" \
            "Disabled" \
            "Blank referrer not blocked" \
            "CSRF attacks possible" \
            "Enable in WHM: Tweak Settings" \
            "referrerblanksafety=1" \
            "" ""
        fi

        # Max emails per hour
        local max_emails=$(grep "^maxemailsperhour=" "$tweak_conf" 2>/dev/null | cut -d= -f2)
        if [[ -n "$max_emails" ]] && [[ "$max_emails" -gt 0 ]] && [[ "$max_emails" -le 500 ]]; then
        add_result "whm" "Max Emails/Hour" "PASS" "MEDIUM" \
            "$max_emails" \
            "" \
            "" \
            "" \
            "" \
            "" ""
        elif [[ -n "$max_emails" ]]; then
        add_result "whm" "Max Emails/Hour" "WARN" "MEDIUM" \
            "$max_emails — may be too high" \
            "High limit allows spam if account compromised" \
            "IP blacklisting" \
            "Set reasonable limit (100-500)" \
            "maxemailsperhour=200" \
            "" ""
        fi
    fi
}

audit_security_config() {
    print_section "Security Configuration" "🔐"

    # cPHulk Brute Force Protection
    local cphulk=$(grep "^cphulk_enabled=" /var/cpanel/cpanel.config 2>/dev/null | cut -d= -f2)
    if [[ "$cphulk" == "1" ]]; then
        add_result "security" "cPHulk" "PASS" "HIGH" \
            "Enabled — brute force protection active" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "security" "cPHulk" "FAIL" "HIGH" \
            "Disabled" \
            "cPHulk protects against brute force attacks on cPanel/WHM/SSH" \
            "Accounts vulnerable to password guessing" \
            "Enable in WHM: Security Center > cPHulk Brute Force Protection" \
            "" \
            "" ""
    fi

    # SSH Password Auth
    local ssh_pass=$(grep "^PasswordAuthentication" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}')
    if [[ "$ssh_pass" == "no" ]]; then
        add_result "security" "SSH Password Auth" "PASS" "HIGH" \
            "Disabled — key-only authentication" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "security" "SSH Password Auth" "WARN" "HIGH" \
            "Enabled" \
            "SSH password authentication allows brute force attacks" \
            "Server compromise via password guessing" \
            "Disable and use SSH keys" \
            "PasswordAuthentication no" \
            "" ""
    fi

    # Shell access
    local shell_access=$(grep "^SHELL=" /var/cpanel/cpanel.config 2>/dev/null | cut -d= -f2)
    if [[ -n "$shell_access" ]]; then
        add_result "security" "Default Shell" "INFO" "INFO" \
            "$shell_access" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    fi

    # Compiler access
    if [[ -x /usr/bin/gcc ]]; then
        local gcc_perms=$(stat -c "%a" /usr/bin/gcc 2>/dev/null)
        if [[ "$gcc_perms" == "700" ]] || [[ "$gcc_perms" == "750" ]]; then
        add_result "security" "Compiler Access" "PASS" "MEDIUM" \
            "Restricted ($gcc_perms)" \
            "" \
            "" \
            "" \
            "" \
            "" ""
        else
        add_result "security" "Compiler Access" "WARN" "MEDIUM" \
            "Available to all users ($gcc_perms)" \
            "Attackers can compile exploits on the server" \
            "Privilege escalation" \
            "Disable in WHM: Security Center > Compiler Access" \
            "chmod 750 /usr/bin/gcc" \
            "" ""
        fi
    fi
}

audit_php_config() {
    print_section "PHP Configuration" "🐘"

    # Check PHP versions
    local php_versions=$(ls /opt/cpanel/ea-php*/root/usr/bin/php 2>/dev/null | wc -l)
    if [[ "$php_versions" -gt 0 ]]; then
        add_result "php" "PHP Versions" "INFO" "INFO" \
            "$php_versions versions installed" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    fi

    # Check for old PHP
    for php_bin in /opt/cpanel/ea-php*/root/usr/bin/php; do
        [[ -x "$php_bin" ]] || continue
        local ver=$($php_bin -r "echo PHP_VERSION;" 2>/dev/null)
        local major=$(echo "$ver" | cut -d. -f1)
        local minor=$(echo "$ver" | cut -d. -f2)
        if [[ "$major" -lt 7 ]] || [[ "$major" -eq 7 && "$minor" -lt 4 ]]; then
        add_result "php" "PHP $ver" "FAIL" "HIGH" \
            "End of Life — no security patches" \
            "PHP $ver no longer receives security updates" \
            "Known vulnerabilities exploitable" \
            "Upgrade to PHP 8.1+ in WHM: EasyApache 4" \
            "" \
            "" ""
        fi
    done

    # Check disable_functions
    local disable_func=$(php -r "echo ini_get('disable_functions');" 2>/dev/null)
    if [[ -n "$disable_func" ]] && [[ "$disable_func" != "no value" ]]; then
        add_result "php" "disable_functions" "PASS" "HIGH" \
            "Configured" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "php" "disable_functions" "FAIL" "HIGH" \
            "Not configured" \
            "PHP dangerous functions (exec, system, passthru) are enabled" \
            "Remote code execution if site is compromised" \
            "Add dangerous functions to disable_functions" \
            "disable_functions = exec,passthru,shell_exec,system,proc_open,popen" \
            "" ""
    fi

    # expose_php
    local expose_php=$(php -r "echo ini_get('expose_php');" 2>/dev/null)
    if [[ "$expose_php" == "0" ]] || [[ "$expose_php" == "" ]]; then
        add_result "php" "expose_php" "PASS" "LOW" \
            "Off — PHP version hidden" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "php" "expose_php" "WARN" "LOW" \
            "On — PHP version exposed in headers" \
            "X-Powered-By header reveals PHP version" \
            "Information disclosure for reconnaissance" \
            "Set expose_php = Off in php.ini" \
            "expose_php = Off" \
            "" ""
    fi

    # display_errors
    local display_errors=$(php -r "echo ini_get('display_errors');" 2>/dev/null)
    if [[ "$display_errors" == "0" ]] || [[ "$display_errors" == "" ]]; then
        add_result "php" "display_errors" "PASS" "MEDIUM" \
            "Off — errors not shown to users" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "php" "display_errors" "FAIL" "MEDIUM" \
            "On — errors visible to users" \
            "PHP errors reveal file paths, database info, and code structure" \
            "Information disclosure" \
            "Set display_errors = Off in php.ini" \
            "display_errors = Off" \
            "" ""
    fi
}

audit_email_security() {
    print_section "Email Security" "📧"

    # SPF
    local spf=$(grep -r "include:_spf" /etc/ /var/cpanel/ 2>/dev/null | head -1)
    if [[ -n "$spf" ]]; then
        add_result "email" "SPF" "PASS" "MEDIUM" \
            "Configured" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "email" "SPF" "WARN" "MEDIUM" \
            "Not detected in config" \
            "SPF prevents email spoofing" \
            "Domain can be used for spam/phishing" \
            "Configure SPF records for your domains" \
            "v=spf1 +a +mx ~all" \
            "" ""
    fi

    # DKIM
    if [[ -d /var/cpanel/domain_keys ]]; then
        local dkim_count=$(ls /var/cpanel/domain_keys/public/ 2>/dev/null | wc -l)
        if [[ "$dkim_count" -gt 0 ]]; then
        add_result "email" "DKIM" "PASS" "MEDIUM" \
            "$dkim_count domains configured" \
            "" \
            "" \
            "" \
            "" \
            "" ""
        else
        add_result "email" "DKIM" "WARN" "MEDIUM" \
            "No DKIM keys found" \
            "DKIM verifies email authenticity" \
            "Emails may be marked as spam" \
            "Enable DKIM in WHM: Email > DKIM Keys" \
            "" \
            "" ""
        fi
    fi

    # SMTP restrictions
    if [[ -f /etc/exim.conf ]]; then
        local smtp_restrict=$(grep "^smtp_enforce_sync" /etc/exim.conf 2>/dev/null)
        if [[ -n "$smtp_restrict" ]]; then
        add_result "email" "SMTP Restrictions" "PASS" "MEDIUM" \
            "Configured" \
            "" \
            "" \
            "" \
            "" \
            "" ""
        fi
    fi
}

audit_backup_config() {
    print_section "Backup Configuration" "💾"

    local backup_conf="/var/cpanel/backups/config"
    if [[ -f "$backup_conf" ]]; then
        local backup_enabled=$(grep "^BACKUPENABLE=" "$backup_conf" 2>/dev/null | cut -d= -f2)
        if [[ "$backup_enabled" == "yes" ]]; then
        add_result "backup" "Backup" "PASS" "HIGH" \
            "Enabled" \
            "" \
            "" \
            "" \
            "" \
            "" ""

            local backup_retention=$(grep "^BACKUP_RETENTION=" "$backup_conf" 2>/dev/null | cut -d= -f2)
            [[ -n "$backup_retention" ]] && add_result "backup" "Retention" "INFO" "INFO" "$backup_retention days" "" "" "" "" ""
        else
        add_result "backup" "Backup" "FAIL" "HIGH" \
            "Disabled" \
            "No automated backups configured" \
            "Data loss risk in case of failure or compromise" \
            "Enable in WHM: Backup > Backup Configuration" \
            "" \
            "" ""
        fi
    else
        add_result "backup" "Backup" "WARN" "HIGH" \
            "Configuration not found" \
            "Backup configuration file missing" \
            "May not have backups configured" \
            "Configure backups in WHM" \
            "" \
            "" ""
    fi
}

audit_firewall() {
    print_section "Firewall" "🛡️"

    # ConfigServer Firewall (CSF)
    if [[ -f /etc/csf/csf.conf ]]; then
        local csf_enabled=$(grep "^TESTING =" /etc/csf/csf.conf 2>/dev/null | awk '{print $3}')
        if [[ "$csf_enabled" == "0" ]]; then
        add_result "firewall" "CSF" "PASS" "HIGH" \
            "Active (TESTING=0)" \
            "" \
            "" \
            "" \
            "" \
            "" ""
        else
        add_result "firewall" "CSF" "WARN" "HIGH" \
            "In TESTING mode" \
            "CSF is in testing mode and not blocking" \
            "Firewall not actually protecting server" \
            "Set TESTING = 0 in /etc/csf/csf.conf" \
            "TESTING = 0" \
            "" ""
        fi
    else
        add_result "firewall" "CSF" "WARN" "HIGH" \
            "Not installed" \
            "ConfigServer Firewall not found" \
            "No firewall protection" \
            "Install CSF: https://configserver.com/csf/" \
            "" \
            "" ""
    fi

    # ModSecurity
    if [[ -f /etc/apache2/conf.d/modsec2.conf ]] || [[ -f /etc/nginx/modsec/modsec2.conf ]]; then
        add_result "firewall" "ModSecurity" "PASS" "HIGH" \
            "Installed" \
            "" \
            "" \
            "" \
            "" \
            "" ""
    else
        add_result "firewall" "ModSecurity" "WARN" "HIGH" \
            "Not detected" \
            "ModSecurity is a web application firewall" \
            "Web apps vulnerable to common attacks (SQLi, XSS)" \
            "Install via EasyApache 4" \
            "" \
            "" ""
    fi
}

# ═══════════════════════════════════════════════════════════════
#  OUTPUT GENERATORS
# ═══════════════════════════════════════════════════════════════

calculate_score() { [[ $TOTAL -gt 0 ]] && SCORE=$(( (PASS * 100 + INFO * 50) / TOTAL )) && [[ $SCORE -gt 100 ]] && SCORE=100; }

print_summary() {
    [[ "$OPT_QUIET" -eq 1 ]] && return
    echo -e "\n${BOLD}════════════════════════════════════════════${N}\n${BOLD}  AUDIT COMPLETE${N}\n${BOLD}════════════════════════════════════════════${N}\n"
    local sc="$G"; [[ "$SCORE" -lt 70 ]] && sc="$R"; [[ "$SCORE" -lt 85 ]] && sc="$Y"
    echo -e "  Security Score: ${sc}${BOLD}${SCORE}/100${N}\n"
    echo -e "  ${G}✓${N} $PASS  ${Y}⚠${N} $WARN  ${R}✗${N} $FAIL  ${B}ℹ${N} $INFO  ${DIM}○${N} $SKIP  ${W}Total:${N} $TOTAL\n"
    [[ "$OPT_HTML" -eq 1 ]] && echo -e "  HTML: $REPORT_HTML"
    [[ "$OPT_JSON" -eq 1 ]] && echo -e "  JSON: $REPORT_JSON"
    [[ "$OPT_TXT" -eq 1 ]]  && echo -e "  TXT:  $REPORT_TXT"
    echo ""
}

generate_json() {
    local arr=""; for i in "${!RESULTS[@]}"; do [[ $i -gt 0 ]] && arr+=","; arr+="${RESULTS[$i]}"; done
    cat > "$REPORT_JSON" <<EOF
{"tool":"nawasec-audit-cpanel","version":"$VERSION","timestamp":"$(date -Iseconds)","score":$SCORE,
"summary":{"total":$TOTAL,"pass":$PASS,"warn":$WARN,"fail":$FAIL,"info":$INFO,"skip":$SKIP},
"results":[$arr]}
EOF
}

generate_html() {
    local sc_color="#10b981"; [[ "$SCORE" -lt 70 ]] && sc_color="#ef4444"; [[ "$SCORE" -lt 85 ]] && sc_color="#f59e0b"
    cat > "$REPORT_HTML" <<'HTMLHEAD'
<!DOCTYPE html><html lang="id"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NawaSec Audit — cPanel Security Report</title>
<style>
:root{--bg:#06060f;--card:#0d0d1a;--border:#1a1a2e;--text:#e2e8f0;--muted:#64748b;--pass:#10b981;--warn:#f59e0b;--fail:#ef4444;--info:#3b82f6}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Inter',-apple-system,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1100px;margin:0 auto}
h1{font-size:1.5rem;font-weight:800}.sub{color:var(--muted);font-size:.85rem;margin-bottom:2rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.8rem;margin-bottom:2rem}
.c{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.2rem;text-align:center}
.c-val{font-size:1.8rem;font-weight:800}.c-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;margin-top:.2rem}
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
<h1>🔒 NawaSec Audit — cPanel Security</h1>
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
        [[ "$cat" != "$current_cat" ]] && [[ -n "$current_cat" ]] && echo "</tbody></table>" >> "$REPORT_HTML"
        [[ "$cat" != "$current_cat" ]] && current_cat="$cat" && echo "<div class='section'>${cat^^}</div><table><thead><tr><th>Status</th><th>Check</th><th>Details</th></tr></thead><tbody>" >> "$REPORT_HTML"
        local bc="b-info"; case "$status" in PASS) bc="b-pass";; WARN) bc="b-warn";; FAIL) bc="b-fail";; esac
        echo "<tr><td><span class='badge ${bc}'>${status}</span></td><td>${name}</td><td>${msg}" >> "$REPORT_HTML"
        [[ -n "$explanation" ]] && echo "<div class='expl'>ℹ️ ${explanation}</div>" >> "$REPORT_HTML"
        [[ -n "$recommendation" ]] && echo "<div class='rem'>🔧 ${recommendation}</div>" >> "$REPORT_HTML"
        echo "</td></tr>" >> "$REPORT_HTML"
    done
    echo "</tbody></table><footer>NawaSec Audit v${VERSION} — cPanel Security — https://github.com/kangaman/nawasec-audit</footer></body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — cPanel Security Report                      ║
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
    echo -e "\n━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n  Score: ${SCORE}/100 | Pass: $PASS | Warn: $WARN | Fail: $FAIL | Total: $TOTAL\n  NawaSec Audit v${VERSION} — https://github.com/kangaman/nawasec-audit" >> "$REPORT_TXT"
}

main() {
    [[ "$EUID" -ne 0 ]] && { echo -e "${R}Error: Run as root${N}" >&2; exit 1; }
    setup_colors
    [[ "$OPT_QUIET" -eq 0 ]] && echo -e "${C}${BOLD}  ╔═══════════════════════════════════════════════════════╗\n  ║  NawaSec Audit — cPanel Security                    ║\n  ║  v${VERSION}                                            ║\n  ╚═══════════════════════════════════════════════════════╝${N}\n"
    if audit_cpanel_detection; then
        audit_whm_security
        audit_security_config
        audit_php_config
        audit_email_security
        audit_backup_config
        audit_firewall
    fi
    calculate_score
    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]]  && generate_txt

    # Return non-zero if any FAILs, useful for CI wrappers
    [[ "$FAIL" -gt 0 ]] && exit 2 || exit 0
}

main "$@"
