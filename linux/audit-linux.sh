#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — Linux VPS Security Audit                              ║
# ║  Version: 2.1.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ║                                                                        ║
# ║  STANDARD TEMPLATE for NawaSec Audit Framework                         ║
# ║  This script serves as the reference implementation for all modules.   ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based Linux VPS security audit — NO AI, NO external API calls.
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-linux.sh [options]
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
SCRIPT_NAME="NawaSec Audit - Linux"
FRAMEWORK_VERSION="2.0.0"

# ═══════════════════════════════════════════════════════════════
#  COLORS & FORMATTING
# ═══════════════════════════════════════════════════════════════

setup_colors() {
    if [[ "${NO_COLOR:-}" == "1" ]] || [[ "$TERM" == "dumb" ]]; then
        R=''; G=''; Y=''; B=''; C=''; M=''; W=''; N=''; BOLD=''; DIM=''
        RED=''; GREEN=''; YELLOW=''; BLUE=''; CYAN=''; MAGENTA=''; WHITE=''; RESET=''
    else
        R='\033[0;31m'; G='\033[0;32m'; Y='\033[0;33m'; B='\033[0;34m'
        C='\033[0;36m'; M='\033[0;35m'; W='\033[1;37m'; N='\033[0m'
        BOLD='\033[1m'; DIM='\033[2m'
        RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[0;33m'; BLUE='\033[0;34m'
        CYAN='\033[0;36m'; MAGENTA='\033[0;35m'; WHITE='\033[1;37m'; RESET='\033[0m'
    fi
}

# ═══════════════════════════════════════════════════════════════
#  COUNTERS & ARRAYS
# ═══════════════════════════════════════════════════════════════

PASS=0; WARN=0; FAIL=0; INFO=0; SKIP=0; TOTAL=0; SCORE=100
declare -a RESULTS=()
declare -a FINDINGS=()

# ═══════════════════════════════════════════════════════════════
#  OPTIONS
# ═══════════════════════════════════════════════════════════════

OPT_HTML=1; OPT_JSON=0; OPT_TXT=0; OPT_QUIET=0
OUTPUT_DIR="/tmp/nawasec-linux"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

# Parse arguments
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
            echo "NawaSec Audit - Linux v${VERSION}"
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
REPORT_HTML="$OUTPUT_DIR/nawasec-linux-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/nawasec-linux-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/nawasec-linux-${TIMESTAMP}.txt"

# ═══════════════════════════════════════════════════════════════
#  STANDARD add_result FUNCTION (NawaSec Template)
# ═══════════════════════════════════════════════════════════════
#
# This is the STANDARD function for all NawaSec Audit modules.
# Parameters:
#   $1 - category (string): Audit category name
#   $2 - name (string): Check name
#   $3 - status (string): PASS|WARN|FAIL|INFO|SKIP
#   $4 - severity (string): CRITICAL|HIGH|MEDIUM|LOW|INFO
#   $5 - message (string): Short description of finding
#   $6 - explanation (string): Why this check matters
#   $7 - risk (string): What could happen if not addressed
#   $8 - impact (string): Business/technical impact
#   $9 - recommendation (string): How to fix
#   $10 - example (string): Example configuration/command
#   $11 - reference (string): Link to documentation

add_result() {
    local category="$1"
    local name="$2"
    local status="$3"
    local severity="$4"
    local message="$5"
    local explanation="${6:-}"
    local risk="${7:-}"
    local impact="${8:-}"
    local recommendation="${9:-}"
    local example="${10:-}"
    local reference="${11:-}"

    TOTAL=$((TOTAL + 1))

    # Update counters
    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        WARN) WARN=$((WARN + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        INFO) INFO=$((INFO + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
    esac

    # Console output
    if [[ "$OPT_QUIET" -eq 0 ]]; then
        case "$status" in
            PASS) echo -e "  ${G}✓${N} ${name} ${DIM}— ${message}${N}" ;;
            WARN) echo -e "  ${Y}⚠${N} ${name} ${DIM}— ${message}${N}" ;;
            FAIL) echo -e "  ${R}✗${N} ${name} ${DIM}— ${message}${N}" ;;
            INFO) echo -e "  ${B}ℹ${N} ${name} ${DIM}— ${message}${N}" ;;
            SKIP) echo -e "  ${DIM}○ ${name} — ${message}${N}" ;;
        esac

        # Show explanation for WARN/FAIL
        if [[ -n "$explanation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${DIM}ℹ️  ${explanation}${N}"
        fi

        # Show risk for WARN/FAIL
        if [[ -n "$risk" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${Y}⚠️  Risk: ${risk}${N}"
        fi

        # Show recommendation for WARN/FAIL
        if [[ -n "$recommendation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${M}🔧 ${recommendation}${N}"
        fi

        # Show example for WARN/FAIL
        if [[ -n "$example" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
            echo -e "    ${DIM}   Example: ${example}${N}"
        fi
    fi

    # Store for JSON output
    local esc_msg=$(echo "$message" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_expl=$(echo "$explanation" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_risk=$(echo "$risk" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_impact=$(echo "$impact" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_rec=$(echo "$recommendation" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_ex=$(echo "$example" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_ref=$(echo "$reference" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")

    RESULTS+=("{\"category\":\"${category}\",\"name\":\"${name}\",\"status\":\"${status}\",\"severity\":\"${severity}\",\"message\":\"${esc_msg}\",\"explanation\":\"${esc_expl}\",\"risk\":\"${esc_risk}\",\"impact\":\"${esc_impact}\",\"recommendation\":\"${esc_rec}\",\"example\":\"${esc_ex}\",\"reference\":\"${esc_ref}\"}")
}

# ═══════════════════════════════════════════════════════════════
#  STANDARD print_section FUNCTION (NawaSec Template)
# ═══════════════════════════════════════════════════════════════

print_section() {
    local title="$1"
    local icon="${2:-▸}"
    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "\n${C}${BOLD}${icon} ${title}${N}"
        echo -e "${DIM}$(printf '─%.0s' {1..60})${N}"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  DETECT OS
# ═══════════════════════════════════════════════════════════════

detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_NAME="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_PRETTY="${PRETTY_NAME:-unknown}"
    else
        OS_NAME="unknown"
        OS_VERSION="unknown"
        OS_PRETTY="unknown"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  AUDIT FUNCTIONS
# ═══════════════════════════════════════════════════════════════

audit_system() {
    print_section "System Foundation" "🖥"

    # OS Version
    add_result "system" "OS Version" "INFO" "INFO" \
        "$OS_PRETTY" \
        "" "" "" "" "" ""

    # OS Support
    case "$OS_NAME" in
        ubuntu)
            if [[ "$(echo "$OS_VERSION < 22" | bc)" == "1" ]]; then
                add_result "system" "OS Support" "FAIL" "HIGH" \
                    "Ubuntu $OS_VERSION — may be EOL" \
                    "End-of-Life operating systems no longer receive security patches" \
                    "Known vulnerabilities remain unpatched, increasing attack surface" \
                    "Compromised system could be used as pivot point for lateral movement" \
                    "Upgrade to Ubuntu 22.04+ LTS" \
                    "do-release-upgrade" \
                    "https://ubuntu.com/about/release-cycle"
            else
                add_result "system" "OS Support" "PASS" "INFO" \
                    "Ubuntu $OS_VERSION — supported" \
                    "" "" "" "" "" ""
            fi
            ;;
        centos)
            if [[ "$(echo "$OS_VERSION < 8" | bc)" == "1" ]]; then
                add_result "system" "OS Support" "FAIL" "CRITICAL" \
                    "CentOS $OS_VERSION — EOL June 2024" \
                    "CentOS 7 reached End-of-Life and no longer receives security updates" \
                    "Critical vulnerabilities will remain unpatched indefinitely" \
                    "System is vulnerable to all future CVEs; compliance violations" \
                    "Migrate to Rocky Linux 9 or AlmaLinux 9" \
                    "https://www.rocky-linux.org/migration-guide" \
                    "https://wiki.centos.org/Manuals/ReleaseNotes/CentOS7.2003"
            else
                add_result "system" "OS Support" "PASS" "INFO" \
                    "CentOS $OS_VERSION — supported" \
                    "" "" "" "" "" ""
            fi
            ;;
        debian)
            if [[ "$(echo "$OS_VERSION < 11" | bc)" == "1" ]]; then
                add_result "system" "OS Support" "FAIL" "HIGH" \
                    "Debian $OS_VERSION — EOL" \
                    "Debian Buster (10) reached End-of-Life" \
                    "No security patches available" \
                    "System vulnerable to known exploits" \
                    "Upgrade to Debian 12 (Bookworm)" \
                    "apt full-upgrade && do-release-upgrade" \
                    "https://www.debian.org/releases/"
            else
                add_result "system" "OS Support" "PASS" "INFO" \
                    "Debian $OS_VERSION — supported" \
                    "" "" "" "" "" ""
            fi
            ;;
        *)
            add_result "system" "OS Support" "INFO" "INFO" \
                "$OS_NAME $OS_VERSION" \
                "" "" "" "" "" ""
            ;;
    esac

    # Kernel
    local kernel=$(uname -r)
    add_result "system" "Kernel" "INFO" "INFO" \
        "$kernel" \
        "" "" "" "" "" ""

    # Boot Loader
    if [[ -f /boot/grub/grub.cfg ]] || [[ -f /boot/grub2/grub.cfg ]]; then
        if grep -q "^set superusers" /boot/grub/grub.cfg 2>/dev/null || \
           grep -q "^set superusers" /boot/grub2/grub.cfg 2>/dev/null; then
            add_result "system" "Boot Loader" "PASS" "MEDIUM" \
                "GRUB password set" \
                "" "" "" "" "" ""
        else
            add_result "system" "Boot Loader" "WARN" "MEDIUM" \
                "No GRUB password" \
                "Without GRUB password, anyone with physical access can boot into single-user mode" \
                "Physical access = root access to the system" \
                "Data theft, malware installation, system compromise" \
                "Set GRUB password" \
                "grub2-setpassword" \
                "https://docs.redhat.com/en/documentation/red_hat_enterprise_linux/9/html/securing_red_hat_enterprise_linux/assembly_protecting-boot-loader-with-password_securing-rhel"
        fi
    fi

    # Package Integrity
    if command -v debsums &>/dev/null; then
        local modified=$(debsums -c 2>/dev/null | wc -l)
        if [[ "$modified" -gt 0 ]]; then
            add_result "system" "Package Integrity" "WARN" "HIGH" \
                "$modified modified files detected" \
                "Modified system files could indicate compromise or unauthorized changes" \
                "Backdoors, rootkits, or malicious modifications may be present" \
                "System integrity cannot be trusted; potential data breach" \
                "Investigate modified files and reinstall packages if needed" \
                "debsums -c | head -20" \
                "https://manpages.debian.org/bookworm/debsums/debsums.1.en.html"
        else
            add_result "system" "Package Integrity" "PASS" "HIGH" \
                "All packages verified" \
                "" "" "" "" "" ""
        fi
    elif command -v rpm &>/dev/null; then
        local modified=$(rpm -Va 2>/dev/null | grep -c "^..5")
        if [[ "$modified" -gt 0 ]]; then
            add_result "system" "Package Integrity" "WARN" "HIGH" \
                "$modified modified files detected" \
                "Modified system files could indicate compromise" \
                "System integrity questionable" \
                "Investigate and reinstall affected packages" \
                "rpm -Va | head -20" \
                ""
        else
            add_result "system" "Package Integrity" "PASS" "HIGH" \
                "All packages verified" \
                "" "" "" "" "" ""
        fi
    else
        add_result "system" "Package Integrity" "SKIP" "INFO" \
            "No package verification tool available" \
            "" "" "" "" "" ""
    fi

    # ASLR
    local aslr=$(cat /proc/sys/kernel/randomize_va_space 2>/dev/null)
    if [[ "$aslr" == "2" ]]; then
        add_result "system" "ASLR" "PASS" "HIGH" \
            "Full randomization" \
            "" "" "" "" "" ""
    elif [[ "$aslr" == "1" ]]; then
        add_result "system" "ASLR" "WARN" "HIGH" \
            "Partial randomization" \
            "ASLR (Address Space Layout Randomization) makes buffer overflow exploits harder" \
            "Partial ASLR is less effective than full randomization" \
            "Exploits may succeed more easily" \
            "Enable full ASLR" \
            "sysctl -w kernel.randomize_va_space=2" \
            "https://www.kernel.org/doc/Documentation/sysctl/kernel.txt"
    else
        add_result "system" "ASLR" "FAIL" "CRITICAL" \
            "ASLR disabled" \
            "ASLR is a critical defense against memory corruption attacks" \
            "Without ASLR, buffer overflow exploits are trivial to execute" \
            "Remote code execution, privilege escalation" \
            "Enable ASLR immediately" \
            "sysctl -w kernel.randomize_va_space=2" \
            "https://www.kernel.org/doc/Documentation/sysctl/kernel.txt"
    fi

    # Core Dumps
    local core=$(ulimit -c 2>/dev/null || echo "?")
    if [[ "$core" == "0" ]]; then
        add_result "system" "Core Dumps" "PASS" "MEDIUM" \
            "Disabled" \
            "" "" "" "" "" ""
    else
        add_result "system" "Core Dumps" "WARN" "MEDIUM" \
            "Allowed (limit: $core)" \
            "Core dumps can contain sensitive data (passwords, keys, memory contents)" \
            "If attacker gains access, core dumps could leak confidential information" \
            "Data exposure, credential theft" \
            "Disable core dumps" \
            "echo '* hard core 0' >> /etc/security/limits.conf" \
            "https://man7.org/linux/man-pages/man5/limits.conf.5.html"
    fi

    # Time Sync
    if timedatectl status 2>/dev/null | grep -q "NTP enabled: yes"; then
        add_result "system" "Time Sync" "PASS" "MEDIUM" \
            "NTP synchronized" \
            "" "" "" "" "" ""
    else
        add_result "system" "Time Sync" "WARN" "MEDIUM" \
            "Time not synchronized" \
            "Incorrect time causes log correlation issues and TLS certificate validation failures" \
            "Forensic analysis becomes unreliable; SSL/TLS connections may fail" \
            "Compliance violations, security monitoring gaps" \
            "Enable NTP synchronization" \
            "timedatectl set-ntp true" \
            "https://www.freedesktop.org/software/systemd/man/timedatectl.html"
    fi
}

audit_ssh() {
    print_section "SSH Configuration" "🔑"

    local sshd_config="/etc/ssh/sshd_config"
    if [[ ! -f "$sshd_config" ]]; then
        add_result "ssh" "SSH Config" "SKIP" "INFO" \
            "sshd_config not found" \
            "" "" "" "" "" ""
        return
    fi

    # Root Login
    local root_login=$(grep -i "^PermitRootLogin" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$root_login" == "no" ]]; then
        add_result "ssh" "Root Login" "PASS" "CRITICAL" \
            "Disabled" \
            "" "" "" "" "" ""
    elif [[ "$root_login" == "without-password" ]] || [[ "$root_login" == "prohibit-password" ]]; then
        add_result "ssh" "Root Login" "WARN" "CRITICAL" \
            "Key-only ($root_login)" \
            "Root login is restricted to SSH keys only" \
            "If root SSH key is compromised, attacker gets full access" \
            "Complete system compromise" \
            "Disable root login entirely and use sudo" \
            "PermitRootLogin no" \
            "https://man.openbsd.org/sshd_config#PermitRootLogin"
    else
        add_result "ssh" "Root Login" "FAIL" "CRITICAL" \
            "Enabled ($root_login)" \
            "Direct root login via SSH is a major security risk" \
            "Brute force attacks targeting root are extremely common" \
            "If root password is cracked, attacker has full system access" \
            "Disable root login and use regular user with sudo" \
            "PermitRootLogin no" \
            "https://man.openbsd.org/sshd_config#PermitRootLogin"
    fi

    # Password Auth
    local pass_auth=$(grep -i "^PasswordAuthentication" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$pass_auth" == "no" ]]; then
        add_result "ssh" "Password Auth" "PASS" "HIGH" \
            "Disabled — key-only" \
            "" "" "" "" "" ""
    else
        add_result "ssh" "Password Auth" "FAIL" "HIGH" \
            "Enabled" \
            "Password authentication is vulnerable to brute force attacks" \
            "Automated bots constantly attempt SSH password guessing" \
            "Compromised credentials lead to unauthorized access" \
            "Disable password auth and use SSH keys" \
            "PasswordAuthentication no" \
            "https://man.openbsd.org/sshd_config#PasswordAuthentication"
    fi

    # SSH Port
    local ssh_port=$(grep -i "^Port" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$ssh_port" == "22" ]] || [[ -z "$ssh_port" ]]; then
        add_result "ssh" "SSH Port" "WARN" "MEDIUM" \
            "Default port 22" \
            "Port 22 is constantly scanned by automated bots" \
            "High volume of brute force attempts fills logs" \
            "Resource waste, log noise, potential DoS" \
            "Change to non-standard port" \
            "Port 2222" \
            "https://man.openbsd.org/sshd_config#Port"
    else
        add_result "ssh" "SSH Port" "PASS" "MEDIUM" \
            "Port $ssh_port" \
            "" "" "" "" "" ""
    fi

    # Empty Passwords
    local empty_pass=$(grep -i "^PermitEmptyPasswords" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$empty_pass" == "yes" ]]; then
        add_result "ssh" "Empty Passwords" "FAIL" "CRITICAL" \
            "Allowed!" \
            "Accounts with empty passwords can be accessed by anyone" \
            "Any attacker can login without credentials" \
            "Complete system compromise" \
            "Disable empty passwords immediately" \
            "PermitEmptyPasswords no" \
            "https://man.openbsd.org/sshd_config#PermitEmptyPasswords"
    else
        add_result "ssh" "Empty Passwords" "PASS" "CRITICAL" \
            "Disabled" \
            "" "" "" "" "" ""
    fi

    # X11 Forwarding
    local x11=$(grep -i "^X11Forwarding" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ "$x11" == "yes" ]]; then
        add_result "ssh" "X11 Forwarding" "WARN" "MEDIUM" \
            "Enabled" \
            "X11 forwarding can be used for keylogging or screen capture" \
            "Attacker could monitor graphical sessions" \
            "Data theft, credential capture" \
            "Disable X11 forwarding if not needed" \
            "X11Forwarding no" \
            "https://man.openbsd.org/sshd_config#X11Forwarding"
    else
        add_result "ssh" "X11 Forwarding" "PASS" "MEDIUM" \
            "Disabled" \
            "" "" "" "" "" ""
    fi

    # Max Auth Tries
    local max_auth=$(grep -i "^MaxAuthTries" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ -n "$max_auth" ]] && [[ "$max_auth" -le 4 ]]; then
        add_result "ssh" "Max Auth Tries" "PASS" "MEDIUM" \
            "$max_auth" \
            "" "" "" "" "" ""
    else
        add_result "ssh" "Max Auth Tries" "WARN" "MEDIUM" \
            "${max_auth:-6} (recommend ≤4)" \
            "Too many authentication attempts allowed per connection" \
            "Brute force attacks can try more passwords per connection" \
            "Increased risk of password guessing" \
            "Reduce max auth tries" \
            "MaxAuthTries 3" \
            "https://man.openbsd.org/sshd_config#MaxAuthTries"
    fi

    # Login Grace Time
    local grace=$(grep -i "^LoginGraceTime" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ -n "$grace" ]] && [[ "$grace" -le 60 ]]; then
        add_result "ssh" "Login Grace" "PASS" "LOW" \
            "${grace}s" \
            "" "" "" "" "" ""
    else
        add_result "ssh" "Login Grace" "WARN" "LOW" \
            "${grace:-120}s (recommend ≤60)" \
            "Long login grace time ties up resources" \
            "Slowloris-style attacks can exhaust connections" \
            "Denial of service" \
            "Reduce login grace time" \
            "LoginGraceTime 30" \
            "https://man.openbsd.org/sshd_config#LoginGraceTime"
    fi

    # Client Alive
    if grep -q "^ClientAliveInterval" "$sshd_config" 2>/dev/null; then
        add_result "ssh" "Client Alive" "PASS" "LOW" \
            "Configured" \
            "" "" "" "" "" ""
    else
        add_result "ssh" "Client Alive" "WARN" "LOW" \
            "Not configured" \
            "Without keepalive, zombie connections persist" \
            "Idle sessions waste resources" \
            "Resource exhaustion" \
            "Configure client alive interval" \
            "ClientAliveInterval 300" \
            "https://man.openbsd.org/sshd_config#ClientAliveInterval"
    fi

    # Access Restriction
    if grep -q "^AllowUsers\|^AllowGroups" "$sshd_config" 2>/dev/null; then
        add_result "ssh" "Access Restriction" "PASS" "HIGH" \
            "Configured" \
            "" "" "" "" "" ""
    else
        add_result "ssh" "Access Restriction" "WARN" "HIGH" \
            "No AllowUsers/AllowGroups" \
            "Any valid user can login via SSH" \
            "Compromised service accounts could be used for SSH access" \
            "Unauthorized access" \
            "Restrict SSH access to specific users" \
            "AllowUsers admin deploy" \
            "https://man.openbsd.org/sshd_config#AllowUsers"
    fi

    # Host Key Perms
    for key in /etc/ssh/ssh_host_*_key; do
        [[ -f "$key" ]] || continue
        local key_perm=$(stat -c "%a" "$key" 2>/dev/null)
        if [[ "$key_perm" != "600" ]]; then
            add_result "ssh" "Host Key Perms" "FAIL" "HIGH" \
                "$key_perm (should be 600)" \
                "SSH host key permissions are too permissive" \
                "Private key could be read by unauthorized users" \
                "Server impersonation, MITM attacks" \
                "Fix key permissions" \
                "chmod 600 $key" \
                ""
            break
        fi
    done

    # Max Sessions
    local max_sessions=$(grep -i "^MaxSessions" "$sshd_config" 2>/dev/null | awk '{print $2}' | tr -d '"')
    if [[ -n "$max_sessions" ]] && [[ "$max_sessions" -le 10 ]]; then
        add_result "ssh" "Max Sessions" "PASS" "LOW" \
            "$max_sessions" \
            "" "" "" "" "" ""
    else
        add_result "ssh" "Max Sessions" "WARN" "LOW" \
            "${max_sessions:-10} (recommend ≤10)" \
            "Too many sessions per connection" \
            "Could be used for session multiplexing attacks" \
            "Resource exhaustion" \
            "Limit max sessions" \
            "MaxSessions 5" \
            "https://man.openbsd.org/sshd_config#MaxSessions"
    fi

    # Login Banner
    if grep -q "^Banner" "$sshd_config" 2>/dev/null; then
        add_result "ssh" "Login Banner" "PASS" "LOW" \
            "Configured" \
            "" "" "" "" "" ""
    else
        add_result "ssh" "Login Banner" "WARN" "LOW" \
            "Not configured" \
            "Login banner provides legal notice to users" \
            "Without banner, legal recourse may be limited" \
            "Compliance violations" \
            "Configure login banner" \
            "Banner /etc/issue.net" \
            "https://man.openbsd.org/sshd_config#Banner"
    fi
}

audit_firewall() {
    print_section "Firewall & Network" "🛡"

    # Firewall detection
    if command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q "Status: active"; then
        add_result "firewall" "UFW" "PASS" "CRITICAL" \
            "Active" \
            "" "" "" "" "" ""
    elif command -v firewall-cmd &>/dev/null && firewall-cmd --state 2>/dev/null | grep -q "running"; then
        add_result "firewall" "Firewalld" "PASS" "CRITICAL" \
            "Active" \
            "" "" "" "" "" ""
    elif command -v nft &>/dev/null && nft list ruleset 2>/dev/null | grep -q "table"; then
        add_result "firewall" "nftables" "PASS" "CRITICAL" \
            "Active" \
            "" "" "" "" "" ""
    elif iptables -L -n 2>/dev/null | grep -q "DROP\|REJECT"; then
        add_result "firewall" "iptables" "PASS" "CRITICAL" \
            "Active" \
            "" "" "" "" "" ""
    else
        add_result "firewall" "Firewall" "FAIL" "CRITICAL" \
            "No firewall detected" \
            "Without a firewall, all network ports are exposed to the internet" \
            "Any running service is directly accessible from anywhere" \
            "Unauthorized access, data breach, DDoS" \
            "Enable and configure a firewall" \
            "ufw enable && ufw default deny incoming" \
            "https://help.ubuntu.com/community/UFW"
    fi

    # IP Forwarding
    local ip_forward=$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)
    if [[ "$ip_forward" == "0" ]]; then
        add_result "firewall" "IP Forwarding" "PASS" "MEDIUM" \
            "Disabled" \
            "" "" "" "" "" ""
    else
        add_result "firewall" "IP Forwarding" "WARN" "MEDIUM" \
            "Enabled" \
            "IP forwarding allows this server to route traffic between networks" \
            "If compromised, attacker could use this as a pivot point" \
            "Lateral movement, network reconnaissance" \
            "Disable unless this is a router/gateway" \
            "sysctl -w net.ipv4.ip_forward=0" \
            "https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt"
    fi

    # ICMP Redirects
    local icmp_redirect=$(cat /proc/sys/net/ipv4/conf/all/accept_redirects 2>/dev/null)
    if [[ "$icmp_redirect" == "0" ]]; then
        add_result "firewall" "ICMP Redirects" "PASS" "MEDIUM" \
            "Disabled" \
            "" "" "" "" "" ""
    else
        add_result "firewall" "ICMP Redirects" "WARN" "MEDIUM" \
            "Enabled" \
            "ICMP redirects can be used to manipulate routing tables" \
            "Attacker could redirect traffic through malicious hosts" \
            "Man-in-the-middle attacks" \
            "Disable ICMP redirects" \
            "sysctl -w net.ipv4.conf.all.accept_redirects=0" \
            "https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt"
    fi

    # Source Routing
    local source_route=$(cat /proc/sys/net/ipv4/conf/all/accept_source_route 2>/dev/null)
    if [[ "$source_route" == "0" ]]; then
        add_result "firewall" "Source Routing" "PASS" "MEDIUM" \
            "Disabled" \
            "" "" "" "" "" ""
    else
        add_result "firewall" "Source Routing" "WARN" "MEDIUM" \
            "Enabled" \
            "Source routing allows packets to specify their own route" \
            "Attacker could bypass network security controls" \
            "Firewall bypass, network reconnaissance" \
            "Disable source routing" \
            "sysctl -w net.ipv4.conf.all.accept_source_route=0" \
            "https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt"
    fi

    # SYN Cookies
    local syn_cookies=$(cat /proc/sys/net/ipv4/tcp_syncookies 2>/dev/null)
    if [[ "$syn_cookies" == "1" ]]; then
        add_result "firewall" "SYN Cookies" "PASS" "HIGH" \
            "Enabled" \
            "" "" "" "" "" ""
    else
        add_result "firewall" "SYN Cookies" "FAIL" "HIGH" \
            "Disabled" \
            "SYN cookies protect against SYN flood DDoS attacks" \
            "Without SYN cookies, server is vulnerable to SYN flood" \
            "Denial of service, service unavailability" \
            "Enable SYN cookies" \
            "sysctl -w net.ipv4.tcp_syncookies=1" \
            "https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt"
    fi

    # Reverse Path Filter
    local rp_filter=$(cat /proc/sys/net/ipv4/conf/all/rp_filter 2>/dev/null)
    if [[ "$rp_filter" == "1" ]]; then
        add_result "firewall" "Reverse Path" "PASS" "MEDIUM" \
            "Enabled" \
            "" "" "" "" "" ""
    else
        add_result "firewall" "Reverse Path" "WARN" "MEDIUM" \
            "Disabled" \
            "Reverse path filtering prevents IP spoofing" \
            "Without it, attacker could send packets with spoofed source IPs" \
            "IP spoofing, network reconnaissance" \
            "Enable reverse path filtering" \
            "sysctl -w net.ipv4.conf.all.rp_filter=1" \
            "https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt"
    fi

    # Broadcast ICMP
    local broadcast_icmp=$(cat /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts 2>/dev/null)
    if [[ "$broadcast_icmp" == "1" ]]; then
        add_result "firewall" "Broadcast ICMP" "PASS" "LOW" \
            "Ignored" \
            "" "" "" "" "" ""
    else
        add_result "firewall" "Broadcast ICMP" "WARN" "LOW" \
            "Not ignored" \
            "Responding to broadcast ICMP can be used for smurf attacks" \
            "Amplification attacks against your network" \
            "DDoS amplification" \
            "Ignore broadcast ICMP" \
            "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1" \
            "https://www.kernel.org/doc/Documentation/networking/ip-sysctl.txt"
    fi

    # IPv6 Redirects
    if [[ -f /proc/sys/net/ipv6/conf/all/accept_redirects ]]; then
        local ipv6_redirect=$(cat /proc/sys/net/ipv6/conf/all/accept_redirects 2>/dev/null)
        if [[ "$ipv6_redirect" == "0" ]]; then
            add_result "firewall" "IPv6 Redirects" "PASS" "MEDIUM" \
                "Disabled" \
                "" "" "" "" "" ""
        else
            add_result "firewall" "IPv6 Redirects" "WARN" "MEDIUM" \
                "Enabled" \
                "IPv6 redirects can be used for MITM attacks" \
                "Attacker could redirect IPv6 traffic" \
                "Man-in-the-middle on IPv6" \
                "Disable IPv6 redirects" \
                "sysctl -w net.ipv6.conf.all.accept_redirects=0" \
                ""
        fi
    fi
}

audit_ips() {
    print_section "Intrusion Prevention" "🛡"

    # Fail2ban
    if command -v fail2ban-client &>/dev/null; then
        if fail2ban-client status 2>/dev/null | grep -q "Number of jail"; then
            local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g')
            add_result "ips" "Fail2ban" "PASS" "HIGH" \
                "Active — jails: $jails" \
                "" "" "" "" "" ""
        else
            add_result "ips" "Fail2ban" "WARN" "HIGH" \
                "Installed but not running" \
                "Fail2ban is installed but not actively protecting" \
                "Brute force attacks not being blocked" \
                "Enable and configure fail2ban" \
                "systemctl enable --now fail2ban" \
                "https://github.com/fail2ban/fail2ban"
        fi
    else
        add_result "ips" "Fail2ban" "FAIL" "HIGH" \
            "Not installed" \
            "Fail2ban automatically blocks IPs after failed login attempts" \
            "Brute force attacks continue unchecked" \
            "Credential theft, unauthorized access" \
            "Install and configure fail2ban" \
            "apt install fail2ban && systemctl enable --now fail2ban" \
            "https://github.com/fail2ban/fail2ban"
    fi

    # CrowdSec
    if command -v cscli &>/dev/null; then
        if cscli metrics 2>/dev/null | grep -q "Processing"; then
            add_result "ips" "CrowdSec" "PASS" "HIGH" \
                "Active" \
                "" "" "" "" "" ""
        else
            add_result "ips" "CrowdSec" "WARN" "HIGH" \
                "Installed but not running" \
                "" "" "" "" "" ""
        fi
    fi
}

audit_auth() {
    print_section "Authentication & Access" "🔐"

    # Failed Logins
    local failed_logins=0
    if [[ -f /var/log/auth.log ]]; then
        failed_logins=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
    elif [[ -f /var/log/secure ]]; then
        failed_logins=$(grep -c "Failed password" /var/log/secure 2>/dev/null || echo "0")
    fi

    if [[ "$failed_logins" -gt 100 ]]; then
        add_result "auth" "Failed Logins (24h)" "FAIL" "HIGH" \
            "$failed_logins attempts" \
            "High number of failed login attempts indicates active brute force attack" \
            "Attackers are actively trying to compromise accounts" \
            "If successful, unauthorized access to system" \
            "Install fail2ban and review SSH security" \
            "fail2ban-client status sshd" \
            ""
    elif [[ "$failed_logins" -gt 20 ]]; then
        add_result "auth" "Failed Logins (24h)" "WARN" "MEDIUM" \
            "$failed_logins attempts" \
            "Moderate failed login attempts detected" \
            "Could be brute force probing" \
            "Potential unauthorized access attempts" \
            "Monitor and consider fail2ban" \
            "journalctl -u sshd --since '24 hours ago' | grep 'Failed'" \
            ""
    else
        add_result "auth" "Failed Logins (24h)" "PASS" "MEDIUM" \
            "$failed_logins attempts" \
            "" "" "" "" "" ""
    fi

    # Sudo Logging
    if grep -q "logfile=" /etc/sudoers 2>/dev/null || \
       grep -q "logfile=" /etc/sudoers.d/* 2>/dev/null; then
        add_result "auth" "Sudo Logging" "PASS" "HIGH" \
            "Configured" \
            "" "" "" "" "" ""
    else
        add_result "auth" "Sudo Logging" "WARN" "HIGH" \
            "Not configured" \
            "Without sudo logging, privileged commands are not auditable" \
            "Cannot track who ran what commands as root" \
            "Compliance violations, forensic gaps" \
            "Configure sudo logging" \
            "echo 'Defaults logfile=/var/log/sudo.log' >> /etc/sudoers.d/logging" \
            "https://www.sudo.ws/docs/man/sudoers.man/"
    fi

    # Password Policy
    if [[ -f /etc/security/pwquality.conf ]]; then
        local minlen=$(grep "^minlen" /etc/security/pwquality.conf 2>/dev/null | cut -d= -f2 | tr -d ' ')
        if [[ -n "$minlen" ]] && [[ "$minlen" -ge 14 ]]; then
            add_result "auth" "Password Policy" "PASS" "MEDIUM" \
                "minlen=$minlen" \
                "" "" "" "" "" ""
        else
            add_result "auth" "Password Policy" "WARN" "MEDIUM" \
                "minlen=${minlen:-8} (recommend ≥14)" \
                "Weak password policy allows easily crackable passwords" \
                "Brute force and dictionary attacks more likely to succeed" \
                "Unauthorized access" \
                "Strengthen password policy" \
                "minlen = 14" \
                "https://man7.org/linux/man-pages/man5/pwquality.conf.5.html"
        fi
    fi

    # Account Lockout
    if [[ -f /etc/security/faillock.conf ]]; then
        if grep -q "^deny" /etc/security/faillock.conf 2>/dev/null; then
            add_result "auth" "Account Lockout" "PASS" "MEDIUM" \
                "Configured" \
                "" "" "" "" "" ""
        else
            add_result "auth" "Account Lockout" "WARN" "MEDIUM" \
                "Not configured" \
                "Without account lockout, brute force attacks can continue indefinitely" \
                "Password guessing attacks never get blocked" \
                "Credential theft" \
                "Configure account lockout" \
                "echo 'deny = 5' >> /etc/security/faillock.conf" \
                "https://man7.org/linux/man-pages/man5/faillock.conf.5.html"
        fi
    fi

    # UID 0 Accounts
    local uid0=$(awk -F: '$3 == 0 {print $1}' /etc/passwd 2>/dev/null)
    local uid0_count=$(echo "$uid0" | wc -l)
    if [[ "$uid0_count" -eq 1 ]] && [[ "$uid0" == "root" ]]; then
        add_result "auth" "UID 0 Accounts" "PASS" "CRITICAL" \
            "Only root" \
            "" "" "" "" "" ""
    else
        add_result "auth" "UID 0 Accounts" "FAIL" "CRITICAL" \
            "$uid0_count accounts with UID 0: $uid0" \
            "Only root should have UID 0 (full system privileges)" \
            "Multiple UID 0 accounts could be backdoors" \
            "Complete system compromise" \
            "Investigate and remove non-root UID 0 accounts" \
            "awk -F: '\$3 == 0 {print \$1}' /etc/passwd" \
            ""
    fi

    # SUID Files
    local suid_count=$(find /usr/bin /usr/sbin /usr/local/bin /usr/local/sbin -type f -perm -4000 2>/dev/null | wc -l)
    add_result "auth" "SUID Files" "INFO" "INFO" \
        "$suid_count files found" \
        "" "" "" "" "" ""
}

# ... (additional audit functions would continue here)

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
  "tool": "nawasec-audit-linux",
  "version": "$VERSION",
  "framework": "$FRAMEWORK_VERSION",
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "os": "$OS_PRETTY",
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
<title>NawaSec Audit — Linux Security Report</title>
<style>
:root{--bg:#06060f;--card:#0d0d1a;--border:#1a1a2e;--text:#e2e8f0;--muted:#64748b;--pass:#10b981;--warn:#f59e0b;--fail:#ef4444;--info:#3b82f6;--critical:#ef4444;--high:#f59e0b;--medium:#3b82f6;--low:#64748b}
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
<h1>🔒 NawaSec Audit — Linux Security</h1>
<p class="sub">$(hostname) — $(date) — v${VERSION}</p>
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
        case "$status" in PASS) bc="b-pass";; WARN) bc="b-warn";; FAIL) bc="b-fail";; SKIP) bc="b-skip";; esac

        local sev_class=""
        local sev_badge=""
        if [[ -n "$severity" ]] && [[ "$severity" != "INFO" ]]; then
            sev_class="s-$(echo "$severity" | tr '[:upper:]' '[:lower:]')"
            sev_badge="<span class='sev ${sev_class}'>${severity}</span>"
        fi

        echo "<tr><td><span class='badge ${bc}'>${status}</span>${sev_badge}</td><td>${name}</td><td>${msg}" >> "$REPORT_HTML"
        [[ -n "$explanation" ]] && echo "<div class='expl'>ℹ️ ${explanation}</div>" >> "$REPORT_HTML"
        [[ -n "$risk" ]] && echo "<div class='risk'>⚠️ Risk: ${risk}</div>" >> "$REPORT_HTML"
        [[ -n "$recommendation" ]] && echo "<div class='rem'>🔧 ${recommendation}</div>" >> "$REPORT_HTML"
        [[ -n "$example" ]] && echo "<div class='example'>\$ ${example}</div>" >> "$REPORT_HTML"
        echo "</td></tr>" >> "$REPORT_HTML"
    done

    echo "</tbody></table>" >> "$REPORT_HTML"
    echo "<footer>NawaSec Audit v${VERSION} — Linux Security — Generated $(date) — https://github.com/kangaman/nawasec-audit</footer>" >> "$REPORT_HTML"
    echo "</body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — Linux Security Report                       ║
║  Version: ${VERSION} (Framework: ${FRAMEWORK_VERSION})       ║
╚══════════════════════════════════════════════════════════════╝

Hostname: $(hostname)
Date:     $(date)
OS:       $OS_PRETTY
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
  NawaSec Audit v${VERSION} — Linux Security
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
    detect_os

    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "${C}${BOLD}"
        echo "  ╔═══════════════════════════════════════════════════════╗"
        echo "  ║  NawaSec Audit — Linux Security                      ║"
        echo "  ║  v${VERSION} (Framework v${FRAMEWORK_VERSION})                        ║"
        echo "  ╚═══════════════════════════════════════════════════════╝"
        echo -e "${N}"
        echo -e "  ${DIM}Started: $(date)${N}"
        echo -e "  ${DIM}OS: $OS_PRETTY${N}"
        echo ""
    fi

    # Run audits
    audit_system
    audit_ssh
    audit_firewall
    audit_ips
    audit_auth
    # Additional audit functions would be called here

    # Calculate & output
    calculate_score
    print_summary

    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]]  && generate_txt

    exit 0
}

main "$@"
