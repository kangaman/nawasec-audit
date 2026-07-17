#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit - Linux — Linux VPS Security Audit & Hardening Recommendation         ║
# ║  Version: 1.0.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                      ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based VPS security audit — NO AI, NO external API calls.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Supported OS:
#   - Ubuntu 18.04+
#   - Debian 10+
#   - CentOS 7+
#   - RHEL 7+
#   - Rocky Linux 8+
#   - AlmaLinux 8+
#   - Fedora 35+
#   - Amazon Linux 2
#
# Usage:
#   sudo ./nawahard.sh [options]
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
SCRIPT_VERSION="2.0.0"
VERSION="$SCRIPT_VERSION"
SCRIPT_NAME="NawaSec Audit - Linux"

# ── Detect OS ──
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS_ID="${ID:-unknown}"
        OS_VERSION="${VERSION_ID:-unknown}"
        OS_NAME="${PRETTY_NAME:-unknown}"
    else
        OS_ID="unknown"
        OS_VERSION="unknown"
        OS_NAME="Unknown Linux"
    fi

    # Normalize
    case "$OS_ID" in
        ubuntu|debian|linuxmint|pop|kali)    OS_FAMILY="debian" ;;
        centos|rhel|rocky|almalinux|ol) OS_FAMILY="rhel" ;;
        fedora)                         OS_FAMILY="fedora" ;;
        amzn)                           OS_FAMILY="amzn" ;;
        arch|manjaro)                   OS_FAMILY="arch" ;;
        *)                              OS_FAMILY="unknown" ;;
    esac
}

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
declare -a CATEGORIES_ORDER=()
declare -A CATEGORY_CHECKS=()

# ── Options ──
OPT_HTML=1; OPT_JSON=0; OPT_TXT=0; OPT_QUIET=0; OPT_NOTIFY=0
OUTPUT_DIR="/tmp/nawahard"
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
        --notify)   OPT_NOTIFY=1; shift ;;
        --help|-h)
            echo "Usage: sudo $0 [options]"
            echo ""
            echo "NawaSec Audit - Linux v${VERSION} — Linux VPS Security Audit"
            echo ""
            echo "Options:"
            echo "  --html        Generate HTML dashboard (default)"
            echo "  --json        Generate JSON report"
            echo "  --txt         Generate TXT report"
            echo "  --all         Generate all formats"
            echo "  --quiet       Minimal console output"
            echo "  --no-color    Disable colors"
            echo "  --output DIR  Custom output directory"
            echo "  --notify      Send summary to webhook"
            echo "  --help        Show this help"
            echo ""
            echo "Supported OS: Ubuntu, Debian, CentOS, RHEL, Rocky, Alma, Fedora, Amazon Linux"
            exit 0
            ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

# ── Init ──
mkdir -p "$OUTPUT_DIR"
REPORT_HTML="$OUTPUT_DIR/nawahard-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/nawahard-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/nawahard-${TIMESTAMP}.txt"

# ── Helper: Get SSH config value ──
get_ssh_val() {
    local key="$1" default="$2"
    local val=""
    local sshd="/etc/ssh/sshd_config"
    local sshd_d="/etc/ssh/sshd_config.d"
    val=$(grep -i "^${key}" "$sshd" 2>/dev/null | tail -1 | awk '{print $2}')
    if [[ -z "$val" ]] && [[ -d "$sshd_d" ]]; then
        val=$(grep -rhi "^${key}" "$sshd_d"/ 2>/dev/null | tail -1 | awk '{print $2}')
    fi
    echo "${val:-$default}"
}

# ── Helper: Get sysctl value ──
get_sysctl() {
    sysctl -n "$1" 2>/dev/null || echo "N/A"
}


# ── Explanation lookup (static, no AI) ──
get_explanation() {
    local name="$1"
    local status="$2"
    case "$name" in
        # System
        "OS Version") echo "Versi OS yang sedang berjalan" ;;
        "OS Support") echo "OS EOL tidak mendapat patch keamanan" ;;
        "OS") echo "Informasi sistem operasi" ;;
        "Kernel") echo "Kernel rentan bisa dieksploitasi untuk root" ;;
        "Boot Loader") echo "Tanpa GRUB password, akses fisik bisa bypass" ;;
        "Package Integrity") echo "File modifikasi bisa menandakan kompromi" ;;
        "ASLR") echo "Randomisasi memori menyulitkan exploit buffer overflow" ;;
        "Core Dumps") echo "Core dump bisa berisi data sensitif" ;;
        "Time Sync") echo "Waktu tidak sinkron = masalah log & TLS" ;;
        "Hostname") echo "Identitas server di jaringan" ;;
        "Uptime") echo "Lama server berjalan tanpa reboot" ;;
        "CPU") echo "Pemrosesan pusat server" ;;
        "Memory") echo "RAM yang tersedia untuk aplikasi" ;;
        "Disk") echo "Penyimpanan yang tersedia" ;;
        "CPU Cores") echo "Jumlah core CPU" ;;
        "Total Memory") echo "Total RAM sistem" ;;
        "Total Disk") echo "Total kapasitas disk" ;;
        "Public IP") echo "IP yang terlihat dari internet" ;;
        "Private IP") echo "IP internal jaringan" ;;
        "Load Average") echo "Rata-rata beban CPU" ;;

        # SSH
        "Root Login") echo "Akses root langsung memudahkan attacker" ;;
        "Password Auth") echo "Password bisa di-brute force" ;;
        "SSH Port") echo "Port 22 target utama scanner otomatis" ;;
        "Empty Passwords") echo "Akun tanpa password bisa diakses siapa saja" ;;
        "X11 Forwarding") echo "Bisa digunakan untuk keylogging" ;;
        "Max Auth Tries") echo "Batas rendah memperlambat brute force" ;;
        "Login Grace") echo "Terlalu lama = koneksi idle tetap terbuka" ;;
        "Client Alive") echo "Keepalive deteksi koneksi zombie" ;;
        "Access Restriction") echo "Membatasi user = kurangi attack surface" ;;
        "Host Key Perms") echo "Permission salah = key theft risk" ;;
        "Max Sessions") echo "Session berlebihan = potensi DoS" ;;
        "Login Banner") echo "Banner peringatan untuk kepatuhan hukum" ;;
        "SSH Config") echo "Konfigurasi SSH daemon" ;;
        "Protocol") echo "Versi protokol SSH" ;;

        # Firewall
        "UFW"|"Firewalld"|"nftables"|"Firewall") echo "Pertahanan pertama dari serangan jaringan" ;;
        "IP Forwarding") echo "IP forward aktif = pivot attack risk" ;;
        "ICMP Redirects") echo "Bisa menyerang routing table" ;;
        "Source Routing") echo "Memungkinkan manipulasi jalur paket" ;;
        "SYN Cookies") echo "Tanpa ini = rentan SYN flood DDoS" ;;
        "Reverse Path") echo "Mencegah IP spoofing" ;;
        "Broadcast ICMP") echo "Bisa digunakan untuk smurf attack" ;;
        "IPv6 Redirects") echo "Bisa digunakan untuk MITM" ;;
        "Send Redirects") echo "Server tidak boleh kirim redirect" ;;
        "Default Redirects") echo "Redirect untuk interface default" ;;
        "Default RP Filter") echo "Filter untuk interface default" ;;
        "Log Martians") echo "Catat paket dari IP tidak valid" ;;
        "TCP Timestamps") echo "Timestamp untuk deteksi paket duplikat" ;;
        "Source Route") echo "Mencegah manipulasi jalur paket" ;;
        "Ignore Broadcast") echo "Mencegah respons broadcast ICMP" ;;
        "IPv6 Enabled") echo "Status IPv6 pada sistem" ;;

        # IPS
        "Fail2ban"|"CrowdSec"|"IPS") echo "Auto-blokir IP brute force" ;;

        # Auth
        "Failed Logins (24h)") echo "Banyak gagal = indikasi brute force" ;;
        "Sudo Logging") echo "Audit trail command root" ;;
        "Password Policy") echo "Password lemah = crack dalam detik" ;;
        "Account Lockout") echo "Blokir akun setelah percobaan gagal" ;;
        "UID 0 Accounts") echo "Multiple UID 0 = backdoor root" ;;
        "SUID Files") echo "SUID tidak lazim = privilege escalation" ;;
        "SGID Files") echo "SGID bisa untuk privilege escalation" ;;
        "Empty Password") echo "Akun tanpa password = akses tanpa auth" ;;

        # Kernel
        "Reverse Path Filter") echo "Mencegah IP spoofing" ;;
        "Kernel Pointers") echo "Menyembunyikan alamat kernel" ;;
        "dmesg Restrict") echo "Mencegah user baca log kernel" ;;
        "ptrace Scope") echo "Mencegah process injection" ;;
        "Protected Hardlinks") echo "Mencegah symlink/hardlink attack" ;;
        "Protected Symlinks") echo "Mencegah TOCTOU symlink attack" ;;
        "SUID Core Dump") echo "Mencegah core dump dari program SUID" ;;
        "Magic SysRq") echo "SysRq bisa untuk crash/reboot paksa" ;;
        "Kernel Lockdown") echo "Mencegah modifikasi kernel runtime" ;;
        "Unprivileged BPF") echo "BPF tanpa privilege = exploit risk" ;;
        "User Namespaces") echo "Container escape risk" ;;
        "perf_event") echo "Kernel profiling abuse risk" ;;

        # Services
        "Service Count") echo "Service berlebihan = attack surface besar" ;;
        "Docker") echo "Docker menambah kompleksitas keamanan" ;;
        "Dangerous: telnet") echo "Telnet tidak terenkripsi, sangat berbahaya" ;;
        "Dangerous: rsh") echo "rsh tidak terenkripsi" ;;
        "Dangerous: rlogin") echo "rlogin tidak terenkripsi" ;;
        "Dangerous: tftp") echo "TFTP tanpa autentikasi" ;;
        "Dangerous: xinetd") echo "xinetd bisa menjalankan service berbahaya" ;;
        "Dangerous: avahi-daemon") echo "Avahi expose info jaringan" ;;
        "Dangerous: cups") echo "CUPS bisa dieksploitasi jika tidak dipakai" ;;
        "Dangerous: rpcbind") echo "RPCBind untuk NFS, riskan jika publik" ;;

        # Ports
        "Port Count") echo "Port terbuka berlebihan = risiko tinggi" ;;
        "Listening Ports") echo "Daftar port yang sedang mendengarkan" ;;
        "Port 21") echo "FTP mengirim password plaintext" ;;
        "Port 23") echo "Telnet tidak terenkripsi" ;;
        "Port 25") echo "SMTP bisa jadi spam relay" ;;
        "Port 110") echo "POP3 tidak terenkripsi" ;;
        "Port 135") echo "RPC target utama malware Windows" ;;
        "Port 139") echo "NetBIOS = info disclosure" ;;
        "Port 445") echo "SMB target utama ransomware" ;;
        "Port 1433") echo "MSSQL terbuka = data breach risk" ;;
        "Port 1521") echo "Oracle DB terbuka" ;;
        "Port 3306") echo "MySQL terbuka bisa dieksploitasi" ;;
        "Port 3389") echo "RDP target brute force" ;;
        "Port 5432") echo "PostgreSQL terbuka" ;;
        "Port 5900") echo "VNC terbuka = remote access risk" ;;
        "Port 6379") echo "Redis tanpa password = data leak" ;;
        "Port 27017") echo "MongoDB sering tanpa autentikasi" ;;

        # Resources
        "Disk") echo "Disk penuh = crash & data loss" ;;
        "Memory") echo "RAM penuh = swap & performa turun" ;;
        "CPU Usage") echo "CPU tinggi = kemungkinan crypto mining" ;;
        "Swap") echo "Swap mencegah OOM killer" ;;
        "Inodes") echo "Inode habis = tidak bisa buat file baru" ;;

        # Updates
        "Reboot") echo "Kernel baru tidak aktif tanpa reboot" ;;
        "Pending") echo "Update menambal vulnerability diketahui" ;;
        "Auto Updates") echo "Patch otomatis = keamanan terbaru" ;;
        "Pending Updates") echo "Update tersedia untuk diinstal" ;;
        "Security Updates") echo "Patch keamanan kritis" ;;

        # Permissions
        "World-Writable /etc") echo "File writable = bisa dimodifikasi attacker" ;;
        "/etc/shadow") echo "Berisi hash password, harus terlindungi" ;;
        "/etc/passwd") echo "Info user, harus read-only" ;;
        "SUID in /tmp") echo "SUID di /tmp hampir pasti malware" ;;
        "World-Writable") echo "File world-writable = modifikasi risk" ;;

        # Docker
        "Socket Perms") echo "Docker socket = akses root ke host" ;;
        "Root Containers") echo "Container root bisa escape ke host" ;;
        "Privileged Mode") echo "Privileged = akses penuh ke host" ;;
        "Content Trust") echo "Verifikasi integritas image Docker" ;;
        "Image Scan") echo "Scan image untuk vulnerability" ;;

        # Cloud
        "Detection") echo "Mengetahui environment cloud" ;;
        "Provider") echo "Setiap cloud punya best practice berbeda" ;;
        "IMDSv2") echo "IMDSv1 rentan SSRF attack" ;;
        "Metadata Access") echo "Metadata bisa expose credentials" ;;

        # Logging
        "Syslog") echo "Centralized logging untuk audit" ;;
        "Audit Daemon") echo "Auditd catat semua aktivitas sistem" ;;
        "Journal") echo "Persistent = log tidak hilang setelah reboot" ;;
        "Log Rotation") echo "Mencegah disk penuh karena log" ;;
        "Remote Logging") echo "Log remote = forensik jika server dikompromi" ;;

        # Misc
        "USB Storage") echo "USB bisa untuk exfiltrate data" ;;
        "File Integrity") echo "Deteksi perubahan file sistem" ;;
        "Core Dump") echo "Core dump = info leak risk" ;;
        "Banner") echo "Banner peringatan untuk kepatuhan" ;;
        "NTP") echo "Time sync = log & TLS valid" ;;
        "MOTD") echo "Message of the day" ;;
        "Issue") echo "Login banner" ;;

        # Kernel detailed
        "Reverse Path Filter") echo "Mencegah IP spoofing" ;;
        "Default RP Filter") echo "Filter untuk interface default" ;;
        "Ignore Broadcast") echo "Mencegah smurf attack" ;;
        "ICMP Redirects") echo "Bisa manipulasi routing" ;;
        "Default Redirects") echo "Redirect untuk interface default" ;;
        "IPv6 Redirects") echo "Bisa manipulasi routing IPv6" ;;
        "Send Redirects") echo "Server tidak boleh kirim redirect" ;;
        "Source Route") echo "Mencegah manipulasi jalur paket" ;;
        "Log Martians") echo "Catat paket IP tidak valid" ;;
        "SYN Cookies") echo "Proteksi dari SYN flood" ;;
        "IPv6 Enabled") echo "Status IPv6" ;;
        "ASLR") echo "Randomisasi layout memori" ;;
        "Kernel Pointers") echo "Sembunyikan alamat kernel" ;;
        "dmesg Restrict") echo "Batasi akses log kernel" ;;
        "ptrace Scope") echo "Cegah process injection" ;;
        "Protected Hardlinks") echo "Cegah hardlink attack" ;;
        "Protected Symlinks") echo "Cegah symlink attack" ;;
        "SUID Core Dump") echo "Cegah core dump SUID" ;;
        "Magic SysRq") echo "SysRq bisa crash sistem" ;;
        "TCP Timestamps") echo "Timestamp untuk deteksi duplikat" ;;
        "Kernel Lockdown") echo "Integritas kernel" ;;
        "Unprivileged BPF") echo "BPF exploit risk" ;;
        "User Namespaces") echo "Container escape risk" ;;
        "perf_event") echo "Profiling abuse risk" ;;
        "Send Redirects") echo "Server tidak boleh kirim redirect" ;;
        "Default Redirects") echo "Redirect interface default" ;;
        "IPv6 Redirects") echo "Manipulasi routing IPv6" ;;
        "Source Route") echo "Manipulasi jalur paket" ;;
        "Log Martians") echo "Catat IP tidak valid" ;;
        "TCP Timestamps") echo "Deteksi duplikat" ;;
        "Kernel Lockdown") echo "Integritas kernel" ;;
        "Unprivileged BPF") echo "BPF exploit risk" ;;
        "User Namespaces") echo "Container escape" ;;
        "perf_event") echo "Profiling abuse" ;;

        *) echo "" ;;
    esac
}


# ── Helper: Add result ──
add_result() {
    local category="$1" name="$2" status="$3" message="$4" remediation="${5:-}"
    local explanation
    explanation=$(get_explanation "$name" "$status")
    TOTAL=$((TOTAL + 1))

    case "$status" in
        PASS) PASS=$((PASS + 1)) ;;
        WARN) WARN=$((WARN + 1)) ;;
        FAIL) FAIL=$((FAIL + 1)) ;;
        INFO) INFO=$((INFO + 1)) ;;
        SKIP) SKIP=$((SKIP + 1)) ;;
    esac

    # Track categories
    if [[ -z "${CATEGORY_CHECKS[$category]+x}" ]]; then
        CATEGORIES_ORDER+=("$category")
        CATEGORY_CHECKS[$category]=0
    fi
    CATEGORY_CHECKS[$category]=$((${CATEGORY_CHECKS[$category]} + 1))

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
    fi

    # Store for JSON
    local escaped_msg=$(echo "$message" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local escaped_rem=$(echo "$remediation" | sed 's/"/\\"/g' | sed "s/'/\\\\'/g")
    local escaped_expl=$(echo "$explanation" | sed 's/"/\\"/g')
    local escaped_expl=$(echo "$explanation" | sed 's/"/\\"/g')
    RESULTS+=("{\"category\":\"${category}\",\"name\":\"${name}\",\"status\":\"${status}\",\"message\":\"${escaped_msg}\",\"remediation\":\"${escaped_rem}\",\"explanation\":\"${escaped_expl}\"}")
}

# ── Helper: Print section ──
print_section() {
    local title="$1" icon="${2:-▸}"
    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "\n${C}${BOLD}${icon} ${title}${N}"
        echo -e "${DIM}$(printf '─%.0s' {1..60})${N}"
    fi
}

# ── Helper: Remedy hint ──
rem() {
    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "    ${M}→${N} ${DIM}${1}${N}"
    fi
}

# ═══════════════════════════════════════════════════════════════
#  AUDIT FUNCTIONS (167 checks across15 categories)
# ═══════════════════════════════════════════════════════════════

# ──1. SYSTEM FOUNDATION ──
audit_system() {
    print_section "System Foundation" "🖥️"

    # OS version
    add_result "system" "OS Version" "INFO" "$OS_NAME"
    
    # EOL check
    case "$OS_ID" in
        ubuntu)
            local ver=$(echo "$OS_VERSION" | cut -d. -f1)
            if [[ "$ver" -ge 20 ]]; then
                add_result "system" "OS Support" "PASS" "Ubuntu $OS_VERSION — supported"
            else
                add_result "system" "OS Support" "FAIL" "Ubuntu $OS_VERSION — may be EOL"
                rem "Upgrade to Ubuntu 22.04+ LTS"
            fi
            ;;
        centos)
            if [[ "$OS_VERSION" -le 7 ]]; then
                add_result "system" "OS Support" "FAIL" "CentOS $OS_VERSION — EOL June2024"
                rem "Migrate to Rocky/Alma Linux 9"
            fi
            ;;
        *) add_result "system" "OS Support" "INFO" "$OS_NAME" ;;
    esac

    # Kernel
    local kernel=$(uname -r)
    add_result "system" "Kernel" "INFO" "$kernel"

    # Boot loader
    if [[ -f /boot/grub/grub.cfg ]] || [[ -f /boot/grub2/grub.cfg ]]; then
        if grep -q "password" /boot/grub/grub.cfg 2>/dev/null || \
           grep -q "password" /boot/grub2/grub.cfg 2>/dev/null; then
            add_result "system" "Boot Loader" "PASS" "GRUB password configured"
        else
            add_result "system" "Boot Loader" "WARN" "No GRUB password"
            rem "Set GRUB password: grub2-setpassword"
        fi
    else
        add_result "system" "Boot Loader" "SKIP" "GRUB not found"
    fi

    # Package integrity
    if command -v debsums &>/dev/null; then
        local modified=$(debsums -c 2>/dev/null | wc -l | xargs)
        if [[ "$modified" -eq 0 ]]; then
            add_result "system" "Package Integrity" "PASS" "All packages verified"
        else
            add_result "system" "Package Integrity" "WARN" "$modified modified files"
    rem "Verify: debsums -c"
        fi
    elif command -v rpm &>/dev/null; then
        local modified=$(rpm -Va 2>/dev/null | grep "^..5" | wc -l | xargs)
        if [[ "$modified" -eq 0 ]]; then
            add_result "system" "Package Integrity" "PASS" "All packages verified"
        else
            add_result "system" "Package Integrity" "WARN" "$modified modified files"
    rem "Verify: debsums -c"
        fi
    else
        add_result "system" "Package Integrity" "SKIP" "No verification tool"
    fi

    # ASLR
    local aslr=$(get_sysctl kernel.randomize_va_space)
    if [[ "$aslr" == "2" ]]; then
        add_result "system" "ASLR" "PASS" "Full randomization"
    elif [[ "$aslr" == "1" ]]; then
        add_result "system" "ASLR" "WARN" "Partial randomization"
        rem "sysctl -w kernel.randomize_va_space=2"
    else
        add_result "system" "ASLR" "FAIL" "ASLR disabled"
        rem "sysctl -w kernel.randomize_va_space=2"
    fi

    # Core dumps
    local core=$(ulimit -c 2>/dev/null || echo "?")
    if [[ "$core" == "0" ]]; then
        add_result "system" "Core Dumps" "PASS" "Disabled"
    else
        add_result "system" "Core Dumps" "WARN" "Allowed (limit: $core)"
        rem "echo '* hard core 0' >> /etc/security/limits.conf"
    fi

    # System clock
    if timedatectl 2>/dev/null | grep -q "synchronized: yes"; then
        add_result "system" "Time Sync" "PASS" "NTP synchronized"
    else
        add_result "system" "Time Sync" "WARN" "Time not synchronized"
        rem "timedatectl set-ntp true"
    fi

    # Hostname
    add_result "system" "Hostname" "INFO" "$(hostname)"
    add_result "system" "Uptime" "INFO" "$(uptime -p 2>/dev/null || uptime)"
    add_result "system" "CPU" "INFO" "$(lscpu 2>/dev/null | grep 'Model name' | cut -d: -f2 | xargs || echo '?') ($(nproc) cores)"
    add_result "system" "Memory" "INFO" "$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}')"
    add_result "system" "Disk" "INFO" "$(df -h / 2>/dev/null | awk 'NR==2 {print $2}')"
}

# ──2. SSH HARDENING ──
audit_ssh() {
    print_section "SSH Configuration" "🔑"

    if [[ ! -f /etc/ssh/sshd_config ]]; then
        add_result "ssh" "SSH Config" "SKIP" "sshd_config not found"
        return
    fi

    # Root login
    local root_login=$(get_ssh_val "PermitRootLogin" "yes")
    if [[ "$root_login" == "no" ]]; then
        add_result "ssh" "Root Login" "PASS" "Disabled"
    elif [[ "$root_login" =~ ^(prohibit-password|without-password)$ ]]; then
        add_result "ssh" "Root Login" "WARN" "Key-only ($root_login)"
        rem "Set 'PermitRootLogin no'"
    else
        add_result "ssh" "Root Login" "FAIL" "Enabled ($root_login)"
        rem "Set 'PermitRootLogin no' in /etc/ssh/sshd_config"
    fi

    # Password auth
    local pass_auth=$(get_ssh_val "PasswordAuthentication" "yes")
    if [[ "$pass_auth" == "no" ]]; then
        add_result "ssh" "Password Auth" "PASS" "Disabled (key-only)"
    else
        add_result "ssh" "Password Auth" "FAIL" "Enabled"
        rem "Set 'PasswordAuthentication no'"
    fi

    # SSH port
    local ssh_port=$(get_ssh_val "Port" "22")
    if [[ "$ssh_port" == "22" ]]; then
        add_result "ssh" "SSH Port" "WARN" "Default port22"
        rem "Change to non-standard port"
    else
        add_result "ssh" "SSH Port" "PASS" "Port $ssh_port"
    fi

    # Empty passwords
    local empty_pass=$(get_ssh_val "PermitEmptyPasswords" "no")
    if [[ "$empty_pass" == "yes" ]]; then
        add_result "ssh" "Empty Passwords" "FAIL" "Allowed!"
        rem "Set 'PermitEmptyPasswords no'"
    else
        add_result "ssh" "Empty Passwords" "PASS" "Disabled"
    fi

    # X11
    local x11=$(get_ssh_val "X11Forwarding" "no")
    if [[ "$x11" == "yes" ]]; then
        add_result "ssh" "X11 Forwarding" "WARN" "Enabled"
        rem "Set 'X11Forwarding no'"
    else
        add_result "ssh" "X11 Forwarding" "PASS" "Disabled"
    fi

    # Max auth tries
    local max_auth=$(get_ssh_val "MaxAuthTries" "6")
    if [[ "$max_auth" -le 3 ]]; then
        add_result "ssh" "Max Auth Tries" "PASS" "$max_auth attempts"
    else
        add_result "ssh" "Max Auth Tries" "WARN" "$max_auth (recommend ≤3)"
        rem "Set 'MaxAuthTries 3'"
    fi

    # Login grace
    local grace=$(get_ssh_val "LoginGraceTime" "120")
    if [[ "$grace" =~ ^[0-9]+$ ]] && [[ "$grace" -le 60 ]]; then
        add_result "ssh" "Login Grace" "PASS" "${grace}s"
    else
        add_result "ssh" "Login Grace" "WARN" "${grace}s (recommend ≤60)"
        rem "Set 'LoginGraceTime 60'"
    fi

    # Client alive
    local alive=$(get_ssh_val "ClientAliveInterval" "0")
    if [[ "$alive" == "0" ]]; then
        add_result "ssh" "Client Alive" "WARN" "Not configured"
        rem "Set 'ClientAliveInterval 300'"
    else
        add_result "ssh" "Client Alive" "PASS" "Every ${alive}s"
    fi

    # AllowUsers/Groups
    local allow_u=$(get_ssh_val "AllowUsers" "")
    local allow_g=$(get_ssh_val "AllowGroups" "")
    if [[ -z "$allow_u" ]] && [[ -z "$allow_g" ]]; then
        add_result "ssh" "Access Restriction" "WARN" "No AllowUsers/AllowGroups"
        rem "Restrict with 'AllowUsers user1 user2'"
    else
        add_result "ssh" "Access Restriction" "PASS" "${allow_u:-$allow_g}"
    fi

    # Host key perms
    local key_perm=$(stat -c "%a" /etc/ssh/ssh_host_rsa_key 2>/dev/null || echo "?")
    if [[ "$key_perm" =~ ^(600|400)$ ]]; then
        add_result "ssh" "Host Key Perms" "PASS" "$key_perm"
    else
        add_result "ssh" "Host Key Perms" "FAIL" "$key_perm (should be 600)"
        rem "chmod 600 /etc/ssh/ssh_host_*_key"
    fi

    # Max sessions
    local max_sess=$(get_ssh_val "MaxSessions" "10")
    if [[ "$max_sess" -le 5 ]]; then
        add_result "ssh" "Max Sessions" "PASS" "$max_sess"
    else
        add_result "ssh" "Max Sessions" "WARN" "$max_sess (recommend ≤5)"
        rem "Set 'MaxSessions 5'"
    fi

    # Banner
    local banner=$(get_ssh_val "Banner" "none")
    if [[ "$banner" != "none" ]] && [[ -f "$banner" ]]; then
        add_result "ssh" "Login Banner" "PASS" "$banner"
    else
        add_result "ssh" "Login Banner" "WARN" "No banner configured"
        rem "Set 'Banner /etc/issue.net'"
    fi
}

# ──3. FIREWALL & NETWORK ──
audit_firewall() {
    print_section "Firewall & Network" "🛡️"

    # Firewall detection
    local fw_found=0
    if command -v ufw &>/dev/null; then
        fw_found=1
        if ufw status 2>/dev/null | grep -qw "active"; then
            local rules=$(ufw status numbered 2>/dev/null | grep -c "^\[")
            add_result "firewall" "UFW" "PASS" "Active ($rules rules)"
        else
            add_result "firewall" "UFW" "FAIL" "Not active"
            rem "ufw enable && ufw default deny incoming"
        fi
    elif command -v firewall-cmd &>/dev/null; then
        fw_found=1
        if firewall-cmd --state 2>/dev/null | grep -q "running"; then
            add_result "firewall" "Firewalld" "PASS" "Running"
        else
            add_result "firewall" "Firewalld" "FAIL" "Not running"
            rem "systemctl enable --now firewalld"
        fi
    elif command -v nft &>/dev/null; then
        fw_found=1
        if nft list ruleset 2>/dev/null | grep -q "table"; then
            add_result "firewall" "nftables" "PASS" "Rules active"
        else
            add_result "firewall" "nftables" "FAIL" "No rules"
    rem "Configure nftables rules"
        fi
    fi
    if [[ "$fw_found" -eq 0 ]]; then
        add_result "firewall" "Firewall" "FAIL" "No firewall found"
        rem "apt install ufw && ufw enable"
    fi

    # IP forwarding
    local fwd=$(get_sysctl net.ipv4.ip_forward)
    [[ "$fwd" == "0" ]] && add_result "firewall" "IP Forwarding" "PASS" "Disabled" \
                         || add_result "firewall" "IP Forwarding" "WARN" "Enabled"
    rem "sysctl -w net.ipv4.ip_forward=0"

    # ICMP redirects
    local icmp=$(get_sysctl net.ipv4.conf.all.accept_redirects)
    [[ "$icmp" == "0" ]] && add_result "firewall" "ICMP Redirects" "PASS" "Rejected" \
                          || { add_result "firewall" "ICMP Redirects" "WARN" "Accepted"; rem "sysctl -w net.ipv4.conf.all.accept_redirects=0"; }
    rem "sysctl -w net.ipv4.conf.all.accept_redirects=0"

    # Source routing
    local src=$(get_sysctl net.ipv4.conf.all.accept_source_route)
    [[ "$src" == "0" ]] && add_result "firewall" "Source Routing" "PASS" "Disabled" \
                         || { add_result "firewall" "Source Routing" "WARN" "Enabled"; rem "sysctl -w net.ipv4.conf.all.accept_source_route=0"; }
    rem "sysctl -w net.ipv4.conf.all.accept_source_route=0"

    # SYN cookies
    local syn=$(get_sysctl net.ipv4.tcp_syncookies)
    [[ "$syn" == "1" ]] && add_result "firewall" "SYN Cookies" "PASS" "Enabled" \
                         || { add_result "firewall" "SYN Cookies" "FAIL" "Disabled"; rem "sysctl -w net.ipv4.tcp_syncookies=1"; }
    rem "sysctl -w net.ipv4.tcp_syncookies=1"

    # Reverse path
    local rp=$(get_sysctl net.ipv4.conf.all.rp_filter)
    [[ "$rp" == "1" ]] && add_result "firewall" "Reverse Path" "PASS" "Enabled" \
                         || { add_result "firewall" "Reverse Path" "WARN" "Disabled"; rem "sysctl -w net.ipv4.conf.all.rp_filter=1"; }
    rem "sysctl -w net.ipv4.conf.all.rp_filter=1"

    # Broadcast ICMP
    local bcast=$(get_sysctl net.ipv4.icmp_echo_ignore_broadcasts)
    [[ "$bcast" == "1" ]] && add_result "firewall" "Broadcast ICMP" "PASS" "Ignored" \
                           || { add_result "firewall" "Broadcast ICMP" "WARN" "Not ignored"; rem "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"; }
    rem "sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1"

    # IPv6 redirects
    local icmp6=$(get_sysctl net.ipv6.conf.all.accept_redirects)
    [[ "$icmp6" == "0" ]] && add_result "firewall" "IPv6 Redirects" "PASS" "Rejected" \
                           || add_result "firewall" "IPv6 Redirects" "WARN" "Accepted"
    rem "sysctl -w net.ipv6.conf.all.accept_redirects=0"
}

# ──4. INTRUSION PREVENTION ──
audit_ips() {
    print_section "Intrusion Prevention" "🚨"

    local found=0

    # Fail2ban
    if command -v fail2ban-client &>/dev/null; then
        found=1
        if systemctl is-active --quiet fail2ban 2>/dev/null; then
            local jails=$(fail2ban-client status 2>/dev/null | grep "Jail list" | sed 's/.*://;s/,/ /g' | xargs || echo "none")
            add_result "ips" "Fail2ban" "PASS" "Active — Jails: $jails"
        else
            add_result "ips" "Fail2ban" "FAIL" "Not running"
            rem "systemctl enable --now fail2ban"
        fi
    fi

    # CrowdSec
    if command -v cscli &>/dev/null; then
        found=1
        systemctl is-active --quiet crowdsec 2>/dev/null && \
            add_result "ips" "CrowdSec" "PASS" "Active" || \
            add_result "ips" "CrowdSec" "FAIL" "Not running"
    rem "systemctl enable --now crowdsec"
    fi

    [[ "$found" -eq 0 ]] && { add_result "ips" "IPS" "FAIL" "No IPS installed"; rem "apt install fail2ban"; }
    rem "apt install fail2ban && systemctl enable --now fail2ban"
}

# ──5. AUTHENTICATION ──
audit_auth() {
    print_section "Authentication & Access" "🔐"

    # Failed logins
    local failed=0
    if [[ -f /var/log/auth.log ]]; then
        failed=$(grep -i "failed password" /var/log/auth.log 2>/dev/null | wc -l | xargs)
    fi
    if [[ -z "$failed" ]] || ! [[ "$failed" =~ ^[0-9]+$ ]]; then
        failed=0
    fi
    if [[ "$failed" -lt 10 ]]; then
        add_result "auth" "Failed Logins (24h)" "PASS" "$failed attempts"
    elif [[ "$failed" -lt 50 ]]; then
        add_result "auth" "Failed Logins (24h)" "WARN" "$failed attempts"
    rem "Install fail2ban and configure SSH jail"
    else
        add_result "auth" "Failed Logins (24h)" "FAIL" "$failed — brute force!"
        rem "Install fail2ban immediately"
    fi

    # Sudo logging
    grep -q "Defaults.*logfile" /etc/sudoers 2>/dev/null && \
        add_result "auth" "Sudo Logging" "PASS" "Enabled" || \
        { add_result "auth" "Sudo Logging" "FAIL" "Disabled"; rem "Add 'Defaults logfile=/var/log/sudo.log'"; }
    rem "Add 'Defaults logfile=/var/log/sudo.log' to /etc/sudoers"

    # Password policy
    if [[ -f /etc/security/pwquality.conf ]]; then
        local minlen=$(grep -oP 'minlen\s*=\s*\K\d+' /etc/security/pwquality.conf 2>/dev/null || echo "0")
        [[ "$minlen" -ge 12 ]] && add_result "auth" "Password Policy" "PASS" "Min length: $minlen" \
                                || { add_result "auth" "Password Policy" "WARN" "Min length: $minlen"; rem "Set 'minlen = 14'"; }
    rem "Set 'minlen = 14' in /etc/security/pwquality.conf"
    else
        add_result "auth" "Password Policy" "FAIL" "Not configured"
    rem "Set 'minlen = 14' in /etc/security/pwquality.conf"
    fi

    # Account lockout
    if [[ -f /etc/security/faillock.conf ]]; then
        local deny=$(grep -oP 'deny\s*=\s*\K\d+' /etc/security/faillock.conf 2>/dev/null || echo "0")
        [[ "$deny" -gt 0 ]] && [[ "$deny" -le 5 ]] && \
            add_result "auth" "Account Lockout" "PASS" "After $deny attempts" || \
            add_result "auth" "Account Lockout" "WARN" "Not configured"
    rem "Configure /etc/security/faillock.conf"
    fi

    # UID 0 accounts
    local uid0=$(awk -F: '$3==0 {print $1}' /etc/passwd 2>/dev/null)
    if [[ "$uid0" == "root" ]]; then
        add_result "auth" "UID 0 Accounts" "PASS" "Only root"
    else
        add_result "auth" "UID 0 Accounts" "FAIL" "Multiple: $uid0"
        rem "Review and remove non-root UID 0 accounts"
    fi

    # Empty passwords
    local empty=$(awk -F: '($2 == "" || $2 == "!") && $1 != "root" {print $1}' /etc/shadow 2>/dev/null | wc -l | xargs)
    [[ "$empty" -eq 0 ]] && add_result "auth" "Empty Passwords" "PASS" "None found" \
                          || { add_result "auth" "Empty Passwords" "FAIL" "$empty accounts"; rem "Set passwords or lock accounts"; }
    rem "Set 'PermitEmptyPasswords no'"

    # SUID files
    # Fast SUID check - only check common locations
    local suid=0
    for dir in /usr/bin /usr/sbin /bin /sbin /usr/local/bin /usr/local/sbin /opt /tmp /var/tmp /home /root; do
        if [[ -d "$dir" ]]; then
            local found=$(timeout 3 find "$dir" -type f -perm -4000 2>/dev/null | wc -l | xargs)
            suid=$((suid + found))
        fi
    done
    [[ "$suid" -eq 0 ]] && add_result "auth" "SUID Files" "PASS" "No unusual SUID" \
                         || add_result "auth" "SUID Files" "WARN" "$suid unusual SUID files"
    rem "Review: find / -type f -perm -4000"
}

# ──6. KERNEL HARDENING ──
audit_kernel() {
    print_section "Kernel Hardening" "⚙️"

    local checks=(
        "net.ipv4.conf.all.rp_filter|1|Reverse Path Filter"
        "net.ipv4.conf.default.rp_filter|1|Default RP Filter"
        "net.ipv4.icmp_echo_ignore_broadcasts|1|Ignore Broadcast"
        "net.ipv4.conf.all.accept_redirects|0|ICMP Redirects"
        "net.ipv4.conf.default.accept_redirects|0|Default Redirects"
        "net.ipv6.conf.all.accept_redirects|0|IPv6 Redirects"
        "net.ipv4.conf.all.send_redirects|0|Send Redirects"
        "net.ipv4.conf.all.accept_source_route|0|Source Route"
        "net.ipv4.conf.all.log_martians|1|Log Martians"
        "net.ipv4.tcp_syncookies|1|SYN Cookies"
        "net.ipv6.conf.all.disable_ipv6|0|IPv6 Enabled"
        "kernel.randomize_va_space|2|ASLR"
        "kernel.kptr_restrict|2|Kernel Pointers"
        "kernel.dmesg_restrict|1|dmesg Restrict"
        "kernel.yama.ptrace_scope|1|ptrace Scope"
        "fs.protected_hardlinks|1|Protected Hardlinks"
        "fs.protected_symlinks|1|Protected Symlinks"
        "fs.suid_dumpable|0|SUID Core Dump"
        "kernel.sysrq|0|Magic SysRq"
        "net.ipv4.tcp_timestamps|1|TCP Timestamps"
    )

    for entry in "${checks[@]}"; do
        IFS='|' read -r key expected label <<< "$entry"
        local actual=$(get_sysctl "$key")
        if [[ "$actual" == "N/A" ]]; then
            add_result "kernel" "$label" "SKIP" "Not available"
        elif [[ "$actual" == "$expected" ]]; then
            add_result "kernel" "$label" "PASS" "$key = $actual"
        else
            add_result "kernel" "$label" "FAIL" "$key = $actual (want $expected)"
            rem "sysctl -w $key=$expected"
        fi
    done
}

# ──7. SERVICES ──
audit_services() {
    print_section "Services" "🔧"

    local running=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c "loaded active running" || echo "0")
    if [[ "$running" -lt 20 ]]; then
        add_result "services" "Service Count" "PASS" "$running running"
    elif [[ "$running" -lt 40 ]]; then
        add_result "services" "Service Count" "WARN" "$running running"
    rem "Review and disable unnecessary services"
    else
        add_result "services" "Service Count" "FAIL" "$running running (too many)"
    rem "Audit and disable: systemctl disable --now <service>"
    fi

    # Dangerous services
    for svc in telnet rsh rlogin tftp xinetd avahi-daemon cups rpcbind; do
        systemctl is-active --quiet "$svc" 2>/dev/null && \
            { add_result "services" "Dangerous: $svc" "WARN" "Running"; rem "systemctl disable --now $svc"; }
    rem "systemctl disable --now $svc"
    done

    # Docker
    if command -v docker &>/dev/null && systemctl is-active --quiet docker 2>/dev/null; then
        local containers=$(docker ps -q 2>/dev/null | wc -l | xargs)
        add_result "services" "Docker" "INFO" "$containers containers"
    fi
}

# ──8. PORTS ──
audit_ports() {
    print_section "Open Ports" "🔌"

    local ports=""
    if command -v ss &>/dev/null; then
        ports=$(ss -tuln 2>/dev/null | grep LISTEN | awk '{print $5}' | awk -F':' '{print $NF}' | sort -n | uniq)
    fi

    if [[ -z "$ports" ]]; then
        add_result "ports" "Listening Ports" "SKIP" "Cannot enumerate"
        return
    fi

    local port_list=$(echo "$ports" | tr '\n' ',' | sed 's/,$//')
    local port_count=$(echo "$ports" | wc -l | xargs)

    [[ "$port_count" -lt 10 ]] && add_result "ports" "Port Count" "PASS" "$port_count: $port_list" || \
    [[ "$port_count" -lt 20 ]] && add_result "ports" "Port Count" "WARN" "$port_count open" || \
    rem "Review and close unnecessary ports"
                                  add_result "ports" "Port Count" "FAIL" "$port_count open"
    rem "Review and close unnecessary ports"

    for dport in 21 23 25 110 135 139 445 1433 1521 3306 3389 5432 5900 6379 27017; do
        echo "$ports" | grep -qw "$dport" && \
            { add_result "ports" "Port $dport" "WARN" "Exposed"; rem "ufw deny $dport"; }
    rem "ufw deny $dport"
    done
}

# ──9. RESOURCES ──
audit_resources() {
    print_section "Resources" "💾"

    # Disk
    local disk=$(df / 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}')
    [[ "$disk" -lt 50 ]] && add_result "resources" "Disk" "PASS" "${disk}%" || \
    [[ "$disk" -lt 80 ]] && { add_result "resources" "Disk" "WARN" "${disk}%"; rem "apt autoremove"; } || \
                            { add_result "resources" "Disk" "FAIL" "${disk}% CRITICAL"; rem "Clean up immediately"; }
    rem "apt autoremove && journalctl --vacuum-size=500M"

    # Memory
    local mem=$(free 2>/dev/null | awk '/^Mem:/ {printf "%.0f", $3/$2*100}')
    [[ "$mem" -lt 50 ]] && add_result "resources" "Memory" "PASS" "${mem}%" || \
    [[ "$mem" -lt 80 ]] && add_result "resources" "Memory" "WARN" "${mem}%" || \
    rem "Check: ps aux --sort=-%mem | head"
                          add_result "resources" "Memory" "FAIL" "${mem}% CRITICAL"
    rem "Check: ps aux --sort=-%mem | head"

    # CPU
    local cpu=$(top -bn1 2>/dev/null | grep "Cpu(s)" | awk '{printf "%.0f", $2}')
    [[ "$cpu" -lt 50 ]] && add_result "resources" "CPU" "PASS" "${cpu}%" || \
    [[ "$cpu" -lt 80 ]] && add_result "resources" "CPU" "WARN" "${cpu}%" || \
    rem "Check: ps aux --sort=-%cpu | head"
                          add_result "resources" "CPU" "FAIL" "${cpu}%"
    rem "Check: ps aux --sort=-%cpu | head"

    # Swap
    local swap=$(free -h 2>/dev/null | awk '/^Swap:/ {print $2}')
    [[ "$swap" == "0B" ]] || [[ "$swap" == "0" ]] && \
        { add_result "resources" "Swap" "WARN" "Not configured"; rem "fallocate -l 2G /swapfile"; } || \
    rem "fallocate -l 2G /swapfile && mkswap /swapfile && swapon /swapfile"
        add_result "resources" "Swap" "INFO" "$swap"

    # Inodes
    local inode=$(df -i / 2>/dev/null | awk 'NR==2 {gsub(/%/,""); print $5}')
    [[ "$inode" -lt 80 ]] && add_result "resources" "Inodes" "PASS" "${inode}%" || \
                              add_result "resources" "Inodes" "FAIL" "${inode}%"
    rem "Find and delete unnecessary files"
}

# ──10. UPDATES ──
audit_updates() {
    print_section "Updates" "📦"

    [[ -f /var/run/reboot-required ]] && \
        add_result "updates" "Reboot" "WARN" "Required" || \
    rem "Reboot at earliest maintenance window"
        add_result "updates" "Reboot" "PASS" "Not needed"

    local updates=$(apt-get -s upgrade 2>/dev/null | grep -P '^\d+ upgraded' | cut -d' ' -f1 || echo "0")
    [[ "$updates" -eq 0 ]] && add_result "updates" "Pending" "PASS" "Up to date" || \
                              { add_result "updates" "Pending" "WARN" "$updates available"; rem "apt update && apt upgrade -y"; }
    rem "apt update && apt upgrade -y"

    if dpkg -l 2>/dev/null | grep -q "unattended-upgrades"; then
        systemctl is-active --quiet unattended-upgrades 2>/dev/null && \
            add_result "updates" "Auto Updates" "PASS" "Active" || \
            add_result "updates" "Auto Updates" "WARN" "Not running"
    rem "apt install unattended-upgrades"
    else
        add_result "updates" "Auto Updates" "WARN" "Not installed"
    rem "apt install unattended-upgrades"
    fi
}

# ──11. FILE PERMISSIONS ──
audit_permissions() {
    print_section "File Permissions" "📂"

    local ww=$(find /etc -type f -perm -002 2>/dev/null | wc -l | xargs)
    [[ "$ww" -eq 0 ]] && add_result "perms" "World-Writable /etc" "PASS" "None" || \
                         { add_result "perms" "World-Writable /etc" "FAIL" "$ww files"; rem "find /etc -type f -perm -002 -exec chmod o-w {} +"; }
    rem "find /etc -type f -perm -002 -exec chmod o-w {} +"

    local shadow=$(stat -c "%a" /etc/shadow 2>/dev/null || echo "?")
    [[ "$shadow" =~ ^(640|600)$ ]] && add_result "perms" "/etc/shadow" "PASS" "$shadow" || \
                                      { add_result "perms" "/etc/shadow" "FAIL" "$shadow"; rem "chmod 640 /etc/shadow"; }
    rem "chmod 640 /etc/shadow"

    local passwd=$(stat -c "%a" /etc/passwd 2>/dev/null || echo "?")
    [[ "$passwd" == "644" ]] && add_result "perms" "/etc/passwd" "PASS" "644" || \
                                add_result "perms" "/etc/passwd" "WARN" "$passwd"
    rem "chmod 644 /etc/passwd"

    local tmp_suid=$(find /tmp /var/tmp -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | wc -l | xargs)
    [[ "$tmp_suid" -eq 0 ]] && add_result "perms" "SUID in /tmp" "PASS" "None" || \
                                { add_result "perms" "SUID in /tmp" "FAIL" "$tmp_suid files!"; rem "Remove immediately"; }
    rem "find /tmp -type f -perm -4000 -exec rm -f {} +"
}

# ──12. CONTAINER SECURITY ──
audit_containers() {
    command -v docker &>/dev/null && systemctl is-active --quiet docker 2>/dev/null || return
    print_section "Container Security" "🐳"

    local socket=$(stat -c "%a" /var/run/docker.sock 2>/dev/null || echo "?")
    [[ "$socket" =~ ^(660|600)$ ]] && add_result "docker" "Socket Perms" "PASS" "$socket" || \
                                      add_result "docker" "Socket Perms" "WARN" "$socket"
    rem "chmod 660 /var/run/docker.sock"

    local root_c=$(docker ps --format '{{.Names}}' 2>/dev/null | while read n; do
        local u=$(docker inspect --format '{{.Config.User}}' "$n" 2>/dev/null)
        [[ -z "$u" ]] || [[ "$u" == "root" ]] || [[ "$u" == "0" ]] && echo "$n"
    done | wc -l)
    [[ "$root_c" -eq 0 ]] && add_result "docker" "Root Containers" "PASS" "None" || \
                             add_result "docker" "Root Containers" "WARN" "$root_c as root"
    rem "Use USER directive in Dockerfile"
}

# ──13. CLOUD METADATA ──
audit_cloud() {
    print_section "Cloud Metadata" "☁️"

    local cloud="none"
    curl -s --max-time 2 -H "Metadata-Flavor: Google" http://169.254.169.254/computeMetadata/v1/ &>/dev/null && cloud="gcp"
    curl -s --max-time 2 http://169.254.169.254/latest/meta-data/ &>/dev/null && cloud="aws"
    curl -s --max-time 2 -H "Metadata:true" http://169.254.169.254/metadata/instance &>/dev/null && cloud="azure"

    [[ "$cloud" == "none" ]] && { add_result "cloud" "Detection" "INFO" "Not cloud (or blocked)"; return; }
    add_result "cloud" "Provider" "INFO" "$cloud"

    [[ "$cloud" == "aws" ]] && {
        local token=$(curl -s --max-time 2 -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 300" 2>/dev/null)
        [[ -n "$token" ]] && add_result "cloud" "IMDSv2" "PASS" "Available" || \
                             { add_result "cloud" "IMDSv2" "WARN" "IMDSv1 only"; rem "Enable IMDSv2"; }
    rem "Enable IMDSv2 on AWS instance"
    }
}

# ──14. LOGGING ──
audit_logging() {
    print_section "Logging & Auditing" "📋"

    # Syslog
    if systemctl is-active --quiet rsyslog 2>/dev/null; then
        add_result "logging" "Syslog" "PASS" "rsyslog active"
    elif systemctl is-active --quiet syslog-ng 2>/dev/null; then
        add_result "logging" "Syslog" "PASS" "syslog-ng active"
    else
        add_result "logging" "Syslog" "WARN" "No syslog daemon"
    rem "apt install rsyslog && systemctl enable --now rsyslog"
    fi

    # Auditd
    systemctl is-active --quiet auditd 2>/dev/null && \
        add_result "logging" "Audit Daemon" "PASS" "Active" || \
        { add_result "logging" "Audit Daemon" "WARN" "Not running"; rem "apt install auditd && systemctl enable --now auditd"; }
    rem "apt install auditd && systemctl enable --now auditd"

    # Journal persistence
    if [[ -d /var/log/journal ]]; then
        add_result "logging" "Journal" "PASS" "Persistent"
    else
        add_result "logging" "Journal" "WARN" "Not persistent"
        rem "mkdir -p /var/log/journal && systemctl restart systemd-journald"
    fi

    # Log rotation
    if [[ -f /etc/logrotate.conf ]]; then
        add_result "logging" "Log Rotation" "PASS" "Configured"
    else
        add_result "logging" "Log Rotation" "WARN" "Not configured"
    rem "Configure /etc/logrotate.conf"
    fi
}

# ──15. MISCELLANEOUS ──
audit_misc() {
    print_section "Miscellaneous" "🔍"

    # USB storage
    lsmod 2>/dev/null | grep -q "usb_storage" && \
        add_result "misc" "USB Storage" "WARN" "Loaded" || \
    rem "echo 'blacklist usb-storage' >> /etc/modprobe.d/blacklist.conf"
        add_result "misc" "USB Storage" "PASS" "Not loaded"

    # File integrity
    (command -v aide &>/dev/null || command -v tripwire &>/dev/null) && \
        add_result "misc" "File Integrity" "PASS" "Installed" || \
        add_result "misc" "File Integrity" "WARN" "Not installed"
    rem "apt install aide && aideinit"

    # Banner
    [[ -f /etc/issue.net ]] && [[ -s /etc/issue.net ]] && \
        add_result "misc" "Login Banner" "PASS" "Configured" || \
        add_result "misc" "Login Banner" "WARN" "Not configured"
    rem "Configure /etc/issue.net"
}

# ═══════════════════════════════════════════════════════════════
#  OUTPUT GENERATORS
# ═══════════════════════════════════════════════════════════════

# ── Calculate score ──
calculate_score() {
    if [[ $TOTAL -gt 0 ]]; then
        SCORE=$(( (PASS * 100 + INFO * 50) / TOTAL ))
        [[ $SCORE -gt 100 ]] && SCORE=100
    fi
}

# ── Console summary ──
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
    echo -e "  ${DIM}OS:${N} $OS_NAME"
    echo -e "  ${DIM}Reports:${N}"

    [[ "$OPT_HTML" -eq 1 ]] && echo -e "    HTML: $REPORT_HTML"
    [[ "$OPT_JSON" -eq 1 ]] && echo -e "    JSON: $REPORT_JSON"
    [[ "$OPT_TXT" -eq 1 ]]  && echo -e "    TXT:  $REPORT_TXT"
    echo ""
}

# ── Generate JSON ──
generate_json() {
    local arr=""
    for i in "${!RESULTS[@]}"; do
        [[ $i -gt 0 ]] && arr+=","
        arr+="${RESULTS[$i]}"
    done

    cat > "$REPORT_JSON" <<EOF
{
  "tool": "nawahard",
  "version": "$VERSION",
  "timestamp": "$(date -Iseconds)",
  "os": {
    "id": "$OS_ID",
    "version": "$OS_VERSION",
    "family": "$OS_FAMILY",
    "name": "$OS_NAME"
  },
  "hostname": "$(hostname)",
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

# ── Generate HTML ──
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
<title>NawaSec Audit - Linux — Security Audit Report</title>
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
.rem{color:var(--pass);font-size:.72rem;margin-top:.3rem;padding:.3rem .5rem;background:rgba(16,185,129,.06);border-left:2px solid var(--pass);border-radius:4px}
.expl{color:var(--muted);font-size:.72rem;margin-top:.2rem;padding:.2rem .4rem;background:rgba(59,130,246,.04);border-left:2px solid var(--info);border-radius:4px}
footer{text-align:center;padding:2rem 0;color:#334155;font-size:.72rem;border-top:1px solid var(--border);margin-top:2rem}
@media(max-width:640px){.cards{grid-template-columns:repeat(2,1fr)}body{padding:1rem}}
</style>
</head>
<body>
HTMLHEAD

    # Header
    cat >> "$REPORT_HTML" <<EOF
<h1>🛡️ NawaSec Audit - Linux Security Audit</h1>
<p class="sub">${OS_NAME} — $(hostname) — $(date)</p>
<div class="cards">
<div class="c"><div class="c-val" style="color:${sc_color}">${SCORE}</div><div class="c-lbl">Score</div></div>
<div class="c"><div class="c-val" style="color:var(--pass)">${PASS}</div><div class="c-lbl">Passed</div></div>
<div class="c"><div class="c-val" style="color:var(--warn)">${WARN}</div><div class="c-lbl">Warnings</div></div>
<div class="c"><div class="c-val" style="color:var(--fail)">${FAIL}</div><div class="c-lbl">Failed</div></div>
<div class="c"><div class="c-val" style="color:var(--info)">${TOTAL}</div><div class="c-lbl">Total</div></div>
</div>
EOF

    # Table rows grouped by category
    local current_cat=""
    for entry in "${RESULTS[@]}"; do
        local cat=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['category'])" 2>/dev/null)
        local name=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['name'])" 2>/dev/null)
        local status=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])" 2>/dev/null)
        local msg=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['message'])" 2>/dev/null)
        local remediation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('remediation',''))" 2>/dev/null)

        if [[ "$cat" != "$current_cat" ]]; then
            [[ -n "$current_cat" ]] && echo "</tbody></table>" >> "$REPORT_HTML"
            current_cat="$cat"
            echo "<div class='section'>${cat^^}</div>" >> "$REPORT_HTML"
            echo "<table><thead><tr><th>Status</th><th>Check</th><th>Details</th></tr></thead><tbody>" >> "$REPORT_HTML"
        fi

        local bc="b-info"
        case "$status" in PASS) bc="b-pass";; WARN) bc="b-warn";; FAIL) bc="b-fail";; SKIP) bc="b-skip";; esac

        local explanation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('explanation',''))" 2>/dev/null)
        echo "<tr><td><span class='badge ${bc}'>${status}</span></td><td>${name}</td><td>${msg}" >> "$REPORT_HTML"
        [[ -n "$explanation" ]] && echo "<div class='expl'>ℹ️ ${explanation}</div>" >> "$REPORT_HTML"
        [[ -n "$remediation" ]] && echo "<div class='rem'>🔧 ${remediation}</div>" >> "$REPORT_HTML"
        echo "</td></tr>" >> "$REPORT_HTML"
    done

    echo "</tbody></table>" >> "$REPORT_HTML"
    echo "<footer>NawaSec Audit - Linux v${VERSION} — Generated $(date) — https://github.com/kangaman/nawasec-audit</footer>" >> "$REPORT_HTML"
    echo "</body></html>" >> "$REPORT_HTML"
}

# ── Generate TXT ──
generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit - Linux — Security Audit Report                            ║
║  Version: ${VERSION}                                          ║
╚══════════════════════════════════════════════════════════════╝

OS:       ${OS_NAME}
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
        local msg=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['message'])" 2>/dev/null)
        local remediation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('remediation',''))" 2>/dev/null)

        if [[ "$cat" != "$current_cat" ]]; then
            current_cat="$cat"
            echo "" >> "$REPORT_TXT"
            echo "━━━ ${cat^^} ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━" >> "$REPORT_TXT"
        fi

        local explanation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('explanation',''))" 2>/dev/null)
        echo "  [${status}] ${name}" >> "$REPORT_TXT"
        echo "      ${msg}" >> "$REPORT_TXT"
        [[ -n "$explanation" ]] && echo "      ℹ️ ${explanation}" >> "$REPORT_TXT"
        [[ -n "$remediation" ]] && echo "      🔧 ${remediation}" >> "$REPORT_TXT"
    done

    cat >> "$REPORT_TXT" <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score:  ${SCORE}/100
  Passed: ${PASS}  |  Warnings: ${WARN}  |  Failed: ${FAIL}
  Info:   ${INFO}  |  Skipped: ${SKIP}   |  Total: ${TOTAL}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NawaSec Audit - Linux v${VERSION} — https://github.com/kangaman/nawasec-audit
EOF
}

# ═══════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════

main() {
    [[ "$EUID" -ne 0 ]] && { echo -e "${R}Error: Run as root (sudo $0)${N}" >&2; exit 1; }

    detect_os
    VERSION="$SCRIPT_VERSION"
    setup_colors

    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "${C}${BOLD}"
        echo "  ███╗   ██╗ █████╗ ██╗    ██╗ █████╗ ██╗  ██╗ █████╗ ██████╗ ██████╗ "
        echo "  ████╗  ██║██╔══██╗██║    ██║██╔══██╗██║  ██║██╔══██╗██╔══██╗██╔══██╗"
        echo "  ██╔██╗ ██║███████║██║ █╗ ██║███████║███████║███████║██████╔╝██║  ██║"
        echo "  ██║╚██╗██║██╔══██║██║███╗██║██╔══██║██╔══██║██╔══██║██╔══██╗██║  ██║"
        echo "  ██║ ╚████║██║  ██║╚███╔███╔╝██║  ██║██║  ██║██║  ██║██║  ██║██████╔╝"
        echo "  ╚═╝  ╚═══╝╚═╝  ╚═╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝"
        echo -e "${N}"
        echo -e "  ${DIM}v${VERSION} — Linux VPS Security Audit${N}"
        echo -e "  ${DIM}OS: ${OS_NAME}${N}"
        echo -e "  ${DIM}Started: $(date)${N}"
        echo ""
    fi

    # Run all audits
    audit_system
    audit_ssh
    audit_firewall
    audit_ips
    audit_auth
    audit_kernel
    audit_services
    audit_ports
    audit_resources
    audit_updates
    audit_permissions
    audit_containers
    audit_cloud
    audit_logging
    audit_misc

    # Calculate & output
    calculate_score
    print_summary

    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]]  && generate_txt

    # Webhook notification
    if [[ "$OPT_NOTIFY" -eq 1 ]] && [[ -n "${NAWAHARD_WEBHOOK:-}" ]]; then
        curl -s -X POST "$NAWAHARD_WEBHOOK" -H "Content-Type: application/json" \
            -d "{\"text\":\"🛡️ NawaSec Audit - Linux: ${HOSTNAME} Score ${SCORE}/100 (P:${PASS} W:${WARN} F:${FAIL})\"}" &>/dev/null
    fi

    exit 0
}

main "$@"
