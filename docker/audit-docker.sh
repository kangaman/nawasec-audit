#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — Docker Security Audit                                ║
# ║  Version: 2.1.0                                                        ║
# ║  Framework: 2.0.0                                                      ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based Docker security audit — NO AI, NO external API calls.
# Read-only: Does NOT modify any configuration or containers.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-docker.sh [options]
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
SCRIPT_NAME="NawaSec Audit - Docker"
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

# ═══════════════════════════════════════════════════════════════
#  OPTIONS
# ═══════════════════════════════════════════════════════════════

OPT_HTML=1; OPT_JSON=0; OPT_TXT=0; OPT_QUIET=0
OUTPUT_DIR="/tmp/nawasec-docker"
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
            echo "NawaSec Audit - Docker v${VERSION}"
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
REPORT_HTML="$OUTPUT_DIR/nawasec-docker-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/nawasec-docker-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/nawasec-docker-${TIMESTAMP}.txt"

# ═══════════════════════════════════════════════════════════════
#  STANDARD add_result FUNCTION (NawaSec Template)
# ═══════════════════════════════════════════════════════════════
#
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
    local esc_msg=$(echo "$message" | sed 's/\"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_expl=$(echo "$explanation" | sed 's/\"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_risk=$(echo "$risk" | sed 's/\"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_impact=$(echo "$impact" | sed 's/\"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_rec=$(echo "$recommendation" | sed 's/\"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_ex=$(echo "$example" | sed 's/\"/\\"/g' | sed "s/'/\\\\'/g")
    local esc_ref=$(echo "$reference" | sed 's/\"/\\"/g' | sed "s/'/\\\\'/g")

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
#  DOCKER DETECTION
# ═══════════════════════════════════════════════════════════════

DOCKER_BIN=""
DOCKERD_CONF="/etc/docker/daemon.json"
HOST_HOSTNAME="$(hostname)"
DOCKER_ROOTLESS=""

detect_docker() {
    # Detect docker binary
    if command -v docker &>/dev/null; then
        DOCKER_BIN="$(command -v docker)"
    elif [[ -x /usr/bin/docker ]]; then
        DOCKER_BIN="/usr/bin/docker"
    elif [[ -x /usr/local/bin/docker ]]; then
        DOCKER_BIN="/usr/local/bin/docker"
    else
        DOCKER_BIN=""
    fi

    # Detect rootless mode
    if [[ -n "${DOCKER_HOST:-}" ]]; then
        DOCKER_ROOTLESS="yes"
    elif [[ -f "$HOME/.config/docker/daemon.json" ]]; then
        DOCKER_ROOTLESS="yes"
    else
        DOCKER_ROOTLESS="no"
    fi
}

# Read a value from daemon.json safely using python3 because jq may not exist.
# Args: key path as dot path, e.g. "log-driver"
# Output: first matching value or empty
daemon_json_read() {
    local key="$1"
    if [[ ! -f "$DOCKERD_CONF" ]]; then
        echo ""
        return
    fi
    python3 - <<'PY' "$DOCKERD_CONF" "$key" 2>/dev/null || true
import sys, json
try:
    path = sys.argv[1].split(".")
    with open(sys.argv[2], "r") as fh:
        data = json.load(fh)
    cur = data
    for p in path:
        if isinstance(cur, dict) and p in cur:
            cur = cur[p]
        else:
            cur = None
            break
    print("" if cur is None else json.dumps(cur))
except Exception:
    print("")
PY
}

# Args: key, expected value. Returns 0/1 for pass/fail on key check.
daemon_json_equals() {
    local key="$1"; shift
    local expected="$1"
    local actual
    actual=$(daemon_json_read "$key")
    if [[ "$actual" == "$expected" ]]; then
        return 0
    fi
    return 1
}

# ═══════════════════════════════════════════════════════════════
#  AUDIT FUNCTIONS
# ═══════════════════════════════════════════════════════════════

# ── 1. Docker Detection ──
audit_detection() {
    print_section "Docker Detection" "🔍"

    # Binary
    if [[ -n "$DOCKER_BIN" ]]; then
        local ver
        ver=$("$DOCKER_BIN" --version 2>/dev/null | awk -F'[, ]+' '{print $3}' | tr -d 'v,' || true)
        add_result "detection" "Docker Daemon" "INFO" "INFO" \
            "$DOCKER_BIN ($ver)" \
            "" "" "" "" "" ""
    else
        add_result "detection" "Docker Daemon" "FAIL" "CRITICAL" \
            "Docker binary not found" \
            "Docker engine appears to be missing" \
            "Cannot audit Docker environment on this host" \
            "Install Docker Engine or verify PATH" \
            "apt install docker-ce" \
            "https://docs.docker.com/engine/install/"
        add_result "detection" "Docker Socket" "SKIP" "INFO" \
            "Skipped: docker missing" \
            "" "" "" "" ""
        return 1
    fi

    # Runtime API reachability
    local socket="/var/run/docker.sock"
    if [[ -S "$socket" ]]; then
        add_result "detection" "Docker Socket" "PASS" "INFO" \
            "Present: $socket" \
            "" "" "" "" "" ""
    else
        add_result "detection" "Docker Socket" "WARN" "MEDIUM" \
            "Not found: $socket" \
            "" "" "" "" "" ""
    fi

    return 0
}

# ── 2. Daemon Configuration ──
audit_daemon_config() {
    print_section "Daemon Configuration" "⚙️"

    # daemon.json exists
    if [[ ! -f "$DOCKERD_CONF" ]]; then
        add_result "daemon" "Daemon Config File" "WARN" "MEDIUM" \
            "Missing: $DOCKERD_CONF" \
            "daemon.json centralizes Docker security settings" \
            "Daemon runs without hardening applied" \
            "Create /etc/docker/daemon.json with security-relevant keys" \
            '{ "icc": false, "userns-remap": "default", "seccomp-profile": ... }' \
            "https://docs.docker.com/engine/reference/commandline/dockerd/"
        return
    fi

    add_result "daemon" "Daemon Config File" "PASS" "INFO" \
        "Present: $DOCKERD_CONF" \
        "" "" "" "" "" ""

    # JSON validity
    if python3 -m json.tool "$DOCKERD_CONF" >/dev/null 2>&1; then
        add_result "daemon" "Daemon JSON Validity" "PASS" "INFO" \
            "Valid JSON" \
            "" "" "" "" "" ""
    else
        add_result "daemon" "Daemon JSON Validity" "FAIL" "HIGH" \
            "Invalid JSON syntax" \
            "Docker daemon may refuse to start with broken config" \
            "Daemon fails to load custom hardening" \
            "Fix JSON syntax in $DOCKERD_CONF" \
            "python3 -m json.tool /etc/docker/daemon.json" \
            ""
        return
    fi

    # userns-remap
    if [[ "$(daemon_json_read "userns-remap")" != "" ]]; then
        add_result "daemon" "User Namespace Remap" "PASS" "HIGH" \
            "Enabled: $(daemon_json_read "userns-remap")" \
            "User namespaces isolate container root from host root" \
            "Container breakout can escape to non-root" \
            "Container root mapped to unprivileged host UID" \
            '"userns-remap": "default"' \
            "https://docs.docker.com/engine/security/userns-remap/"
    else
        add_result "daemon" "User Namespace Remap" "FAIL" "HIGH" \
            "Disabled/missing" \
            "Without userns-remap, container root maps to host root" \
            "Container breakout gives host root access" \
            "Enable user namespace remapping for all users" \
            '"userns-remap": "default"' \
            "https://docs.docker.com/engine/security/userns-remap/"
    fi

    # seccomp
    local seccomp_profile
    seccomp_profile=$(daemon_json_read "seccomp-profile")
    if [[ "$seccomp_profile" != "" && "$seccomp_profile" != "null" ]]; then
        add_result "daemon" "Seccomp Profile" "PASS" "HIGH" \
            "Custom profile configured" \
            "Seccomp filters syscalls to reduce kernel attack surface" \
            "Malicious container could execute unauthorized syscalls" \
            "Restrict dangerous syscalls per workload" \
            '"seccomp-profile": "/etc/docker/seccomp-default.json"' \
            "https://docs.docker.com/engine/security/seccomp/"
    else
        add_result "daemon" "Seccomp Profile" "WARN" "MEDIUM" \
            "Default seccomp active / unset" \
            "Default profile is acceptable but may not cover custom hardening" \
            "Unrestricted syscall set increases risk" \
            "Provide a custom seccomp profile" \
            "docker run --security-opt seccomp=profile.json ..." \
            "https://docs.docker.com/engine/security/seccomp/"
    fi

    # apparmor
    if [[ -f /etc/apparmor.d/docker ]]; then
        add_result "daemon" "AppArmor Profile" "PASS" "HIGH" \
            "Docker AppArmor profile installed" \
            "AppArmor confines container syscalls and filesystem access" \
            "Container escape is more difficult with MAC enforcement" \
            "Ensure docker-default profile is loaded" \
            "apparmor_parser -r /etc/apparmor.d/docker" \
            "https://docs.docker.com/engine/security/apparmor/"
    else
        add_result "daemon" "AppArmor Profile" "WARN" "MEDIUM" \
            "No AppArmor profile found" \
            "Mandatory access control is not applied to containers" \
            "Compliance audits may flag missing MAC enforcement" \
            "Install AppArmor and verify docker-default profile" \
            "apt install apparmor" \
            "https://docs.docker.com/engine/security/apparmor/"
    fi

    # live-restore
    local live
    live=$(daemon_json_read "live-restore")
    if [[ "$live" == "true" ]]; then
        add_result "daemon" "Live Restore" "PASS" "MEDIUM" \
            "Enabled" \
            "live-restore keeps containers running during daemon restart" \
            "Container disruption increases operational risk" \
            "Containers survive transient daemon upgrades" \
            '"live-restore": true' \
            "https://docs.docker.com/engine/reference/commandline/dockerd/#daemon-configuration-options"
    else
        add_result "daemon" "Live Restore" "INFO" "LOW" \
            "Disabled or not set" \
            "" \
            "" \
            "" \
            '"live-restore": true' \
            ""
    fi

    # TLS daemon
    local tls
    tls=$(daemon_json_read "tls")
    if [[ "$tls" == "true" || "$tls" == "1" ]]; then
        add_result "daemon" "Daemon TLS" "PASS" "HIGH" \
            "TLS enabled for daemon API" \
            "TLS encrypts Docker API traffic" \
            "API could be intercepted without TLS" \
            "Enable TLS with signed certificates" \
            '"tls": true, "tlscacert": "...", "tlscert": "...", "tlskey": "..."' \
            "https://docs.docker.com/engine/security/https/"
    else
        local listen
        listen=$(daemon_json_read "hosts")
        if [[ "$listen" == *"2375"* ]]; then
            add_result "daemon" "Daemon TLS" "FAIL" "HIGH" \
                "Plain TCP exposed" \
                "Docker TCP socket without TLS leaks API" \
                "Unauthenticated container/pod creation possible" \
                "Remove TCP listener or enforce TLS" \
                '"hosts": ["unix:///var/run/docker.sock"]' \
                "https://docs.docker.com/engine/security/https/"
        else
            add_result "daemon" "Daemon TLS" "WARN" "MEDIUM" \
                "Not explicitly configured" \
                "" \
                "" \
                "" \
                '"tls": true' \
                ""
        fi
    fi
}

# ── 3. Docker Socket Permissions ──
audit_socket_permissions() {
    print_section "Docker Socket Permissions" "🔌"

    local socket="/var/run/docker.sock"
    if [[ ! -S "$socket" ]]; then
        add_result "socket" "Docker Socket" "SKIP" "INFO" \
            "Socket missing" \
            "Cannot evaluate permissions without docker.sock" \
            "" "" "" ""
        return
    fi

    local mode owner group
    mode=$(stat -c '%a' "$socket" 2>/dev/null || echo "")
    owner=$(stat -c '%U' "$socket" 2>/dev/null || echo "")
    group=$(stat -c '%G' "$socket" 2>/dev/null || echo "")

    add_result "socket" "Socket Permissions" "INFO" "INFO" \
        "$mode $owner:$group" \
        "" "" "" "" "" ""

    # 660 is acceptable; writeable by group is risky unless docker group is controlled
    if [[ "$mode" == "660" || "$mode" == "600" ]]; then
        add_result "socket" "Socket Permission Hardening" "PASS" "HIGH" \
            "Restricted permissions ($mode)" \
            "Only root or specific group should access docker.sock" \
            "Any local user with socket access can control Docker" \
            "Restrict to 660 with docker group managed tightly" \
            "chmod 660 /var/run/docker.sock && chgrp docker /var/run/docker.sock" \
            ""
    else
        add_result "socket" "Socket Permission Hardening" "WARN" "HIGH" \
            "Socket too open ($mode)" \
            "World-accessible socket is equivalent to root" \
            "Host compromise via low-privilege user" \
            "Set 660 and manage docker group membership" \
            "chmod 660 /var/run/docker.sock" \
            ""
    fi

    # Owner check
    if [[ "$owner" == "root" ]]; then
        add_result "socket" "Socket Owner" "PASS" "INFO" \
            "root" \
            "" "" "" "" "" ""
    else
        add_result "socket" "Socket Owner" "WARN" "MEDIUM" \
            "$owner" \
            "Root must own socket for privilege boundary" \
            "Non-root owners may expose daemon to privilege bypass" \
            "chown root:docker /var/run/docker.sock" \
            "" ""
    fi
}

# ── 4. Mode Checks (rootless/daemon root) ──
audit_modes() {
    print_section "Runtime Modes" "🛡️"

    if [[ "$DOCKER_ROOTLESS" == "yes" ]]; then
        add_result "modes" "Rootless Mode" "PASS" "HIGH" \
            "Rootless mode detected" \
            "Rootless mode avoids running daemon as root" \
            "Running dockerd as root gives full host control" \
            "Reduces daemon exposure and increases isolation" \
            "dockerd-rootless.sh" \
            "https://docs.docker.com/engine/security/rootless/"
    else
        add_result "modes" "Rootless Mode" "WARN" "MEDIUM" \
            "Not in rootless mode" \
            "Rootless Docker reduces daemon privilege" \
            "Daemon runs as root, increasing host risk" \
            "Evaluate rootless mode for non-critical environments" \
            "dockerd-rootless.sh" \
            "https://docs.docker.com/engine/security/rootless/"
    fi

    # cgroup namespace
    local cgroupns
    cgroupns=$(daemon_json_read "cgroupns")
    if [[ "$cgroupns" == "" || "$cgroupns" == "private" ]]; then
        add_result "modes" "Cgroup Namespace" "PASS" "HIGH" \
            "Private or default isolation" \
            "Per-container cgroup namespace restricts resource visibility" \
            "Processes see wider host cgroup tree without isolation" \
            "Container cgroups should not escape parent limits" \
            "docker run --cgroupns=private ..." \
            "https://docs.docker.com/engine/security/security/"
    else
        add_result "modes" "Cgroup Namespace" "WARN" "MEDIUM" \
            "Shared cgroup namespace" \
            "" \
            "" \
            "" \
            "docker run --cgroupns=private ..." \
            ""
    fi

    # PID default/host exposure via daemon config is rare; we inspect runtime via ps if available.
    # Instead, check if host PID namespace is forced by default in daemon.json runtime default.
    local pid_in_host
    pid_in_host=$(daemon_json_read "default-runtime" )
    # null means default runtime, not PID host; leave as info note.
    add_result "modes" "Default Runtime Namespace" "INFO" "LOW" \
        "Default runtime isolation" \
        "" "" "" "" "" ""
}

# ── 5. Container Privileges & Capabilities ──
audit_privileges() {
    print_section "Container Privileges & Capabilities" "🚨"

    local socket="/var/run/docker.sock"
    if [[ ! -S "$socket" ]]; then
        add_result "priv" "Container Privilege Audit" "SKIP" "INFO" \
            "Skipped: docker socket missing" \
            "" "" "" "" "" ""
        return
    fi

    if ! "$DOCKER_BIN" info >/dev/null 2>&1; then
        add_result "priv" "Container Privilege Audit" "SKIP" "INFO" \
            "Skipped: docker not reachable" \
            "" "" "" "" "" ""
        return
    fi

    local privileged_seen=0
    local total_running=0
    local unsafe_seen=0

    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        total_running=$((total_running + 1))

        # privileged
        local privileged
        privileged=$("$DOCKER_BIN" inspect --format '{{.HostConfig.Privileged}}' "$cid" 2>/dev/null || true)
        if [[ "$privileged" == "true" ]]; then
            privileged_seen=1
            local name
            name=$("$DOCKER_BIN" inspect --format '{{.Name}}' "$cid" 2>/dev/null || true)
            add_result "priv" "Privileged Container" "FAIL" "HIGH" \
                "$name running with --privileged" \
                "Privileged containers disable most isolation" \
                "Full device access allows host compromise" \
                "Avoid --privileged; grant only required capabilities" \
                "docker run --cap-add=... --security-opt=no-new-privileges ..." \
                "https://docs.docker.com/engine/security/security/"
        fi

        # read-only rootfs
        local ro
        ro=$("$DOCKER_BIN" inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$cid" 2>/dev/null || true)
        if [[ "$ro" == "true" ]]; then
            add_result "priv" "Read-Only Rootfs" "PASS" "MEDIUM" \
                "$cid — read-only" \
                "Read-only rootfs reduces persistence options" \
                "Writeable rootfs aids persistence/implant" \
                "Prefer :ro mounts and --read-only" \
                "docker run --read-only ..." \
                "https://docs.docker.com/engine/reference/run/#read-only-root-filesystem"
        else
            add_result "priv" "Read-Only Rootfs" "WARN" "MEDIUM" \
                "$cid — writeable rootfs" \
                "Writeable rootfs allows filesystem changes inside container" \
                "Malware or attackers can drop binaries" \
                "Enable --read-only and use tmpfs/volumes for mutable paths" \
                "docker run --read-only --tmpfs /tmp ..." \
                "https://docs.docker.com/engine/reference/run/#read-only-root-filesystem"
        fi

        # security opts
        local secopts
        secopts=$("$DOCKER_BIN" inspect --format '{{json .HostConfig.SecurityOpt}}' "$cid" 2>/dev/null || true)
        local has_seccomp="no"
        if [[ "$secopts" == *"seccomp"* ]]; then
            has_seccomp="yes"
        else
            # default security opt usually implies seccomp/default profile unless overridden
            :
        fi

        local has_apparmor="no"
        if [[ "$secopts" == *"apparmor"* ]]; then
            has_apparmor="yes"
        fi

        if [[ "$has_seccomp" == "yes" || "$has_apparmor" == "yes" ]]; then
            add_result "priv" "Mandatory Access Controls" "PASS" "MEDIUM" \
                "$cid — security options present" \
                "MAC profiles reduce kernel exposure" \
                "Unconstrained kernel calls increase breakout risk" \
                "Keep seccomp/apparmor defaults unless overridden" \
                "docker run --security-opt apparmor=docker-default ..." \
                ""
        else
            add_result "priv" "Mandatory Access Controls" "WARN" "MEDIUM" \
                "$cid — default MAC may apply" \
                "Verify per-container MAC enforcement" \
                "Override SecurityOpt can disable MACs" \
                "Explicitly set security options" \
                "docker run --security-opt seccomp=default.json --security-opt apparmor=docker-default ..." \
                ""
        fi

        # no-new-privileges
        if [[ "$secopts" == *"no-new-privileges"* ]]; then
            add_result "priv" "No New Privileges" "PASS" "MEDIUM" \
                "$cid — no-new-privileges enabled" \
                "Prevents setuid binaries from gaining root inside container" \
                "SUID binaries can escalate privileges" \
                "Baseline defense-in-depth control" \
                "docker run --security-opt=no-new-privileges ..." \
                "https://docs.docker.com/engine/security/security/"
        else
            add_result "priv" "No New Privileges" "WARN" "LOW" \
                "$cid — not set" \
                "Without no-new-privileges, SUID escalation may work" \
                "Container processes could gain higher privileges" \
                "Enable without breaking workload SUID actions" \
                "docker run --security-opt=no-new-privileges ..." \
                "https://docs.docker.com/engine/security/security/"
        fi

        # user namespace outside container
        local userns
        userns=$("$DOCKER_BIN" inspect --format '{{.HostConfig.UsernsMode}}' "$cid" 2>/dev/null || true)
        if [[ "$userns" != "host" && "$userns" != "" ]]; then
            add_result "priv" "User Namespace Mode" "PASS" "HIGH" \
                "$cid — userns: $userns" \
                "User namespace remaps container UIDs/GIDs" \
                "Host namespace reuse dramatically widens breakout impact" \
                "Prefer non-host userns mode" \
                "docker run --userns=private ..." \
                "https://docs.docker.com/engine/security/userns-remap/"
        else
            add_result "priv" "User Namespace Mode" "WARN" "MEDIUM" \
                "$cid — userns: ${userns:-unset}" \
                "Host userns reduces UID isolation" \
                "Container root can map to host UID 0" \
                "Avoid host userns in multi-tenant environments" \
                "docker run --userns=private ..." \
                "https://docs.docker.com/engine/security/userns-remap/"
        fi

        # capabilities except
        local capdrop
        capdrop=$("$DOCKER_BIN" inspect --format '{{json .HostConfig.CapDrop}}' "$cid" 2>/dev/null || true)
        local capadd
        capadd=$("$DOCKER_BIN" inspect --format '{{json .HostConfig.CapAdd}}' "$cid" 2>/dev/null || true)

        local has_drop="no"
        if [[ "$capdrop" != "[]" && -n "$capdrop" ]]; then
            has_drop="yes"
        fi

        if [[ "$has_drop" == "yes" && "$capadd" != *"ALL"* && "$capadd" != *"SYS_ADMIN"* ]]; then
            add_result "priv" "Capability Restrictions" "PASS" "HIGH" \
                "$cid — capabilities restricted" \
                "Dropping capabilities limits container kernel access" \
                "Default capability set includes powerful syscalls" \
                "Drop ALL and add only required caps" \
                "docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ..." \
                "https://docs.docker.com/engine/security/security/"
        else
            add_result "priv" "Capability Restrictions" "WARN" "HIGH" \
                "$cid — capabilities not restricted" \
                "Default cap set allows powerful operations" \
                "SYS_ADMIN or over-permissive caps allow breakout" \
                "Drop ALL caps and allowlist required ones" \
                "docker run --cap-drop=ALL --cap-add=NET_BIND_SERVICE ..." \
                "https://docs.docker.com/engine/security/security/"
        fi

        # pid namespace
        local pidmode
        pidmode=$("$DOCKER_BIN" inspect --format '{{.HostConfig.PidMode}}' "$cid" 2>/dev/null || true)
        if [[ "$pidmode" == "host" ]]; then
            add_result "priv" "PID Namespace" "FAIL" "HIGH" \
                "$cid — host PID namespace" \
                "Host PID namespace exposes host processes" \
                "Process enumeration and signal injection possible" \
                "Remove --pid=host unless workload explicitly requires it" \
                "docker run --pid=private ..." \
                "https://docs.docker.com/engine/security/security/"
        else
            add_result "priv" "PID Namespace" "PASS" "MEDIUM" \
                "$cid — isolated PID namespace" \
                "" "" "" "" "" ""
        fi

        # cgroup limits
        local cpus memsw
        cpus=$("$DOCKER_BIN" inspect --format '{{.HostConfig.NanoCpus}}' "$cid" 2>/dev/null || echo "-1")
        memsw=$("$DOCKER_BIN" inspect --format '{{.HostConfig.MemorySwap}}' "$cid" 2>/dev/null || echo "-1")
        local memory
        memory=$("$DOCKER_BIN" inspect --format '{{.HostConfig.Memory}}' "$cid" 2>/dev/null || echo "-1")

        if [[ "$cpus" != "-1" || "$memory" != "-1" || "$memsw" != "-1" ]]; then
            add_result "resource" "Resource Limits" "PASS" "MEDIUM" \
                "$cid — limits defined" \
                "CPU/memory limits prevent denial-of-service" \
                "Unlimited resources can starve host/neighbors" \
                "Set NanoCpus/Memory/MemorySwap per container" \
                "docker run --cpus=1 --memory=512m ..." \
                "https://docs.docker.com/engine/reference/run/#cpu-share-constraint"
        else
            add_result "resource" "Resource Limits" "WARN" "MEDIUM" \
                "$cid — no limits" \
                "Unlimited CPU/memory can exhaust host" \
                "Resource exhaustion leads to DoS" \
                "Assign NanoCpus/Memory/MemorySwap" \
                "docker run --cpus=1 --memory=512m ..." \
                "https://docs.docker.com/engine/reference/run/#cpu-share-constraint"
        fi
    done < <("$DOCKER_BIN" ps -q 2>/dev/null || true)

    if [[ "$total_running" -eq 0 ]]; then
        add_result "priv" "Running Containers" "INFO" "INFO" \
            "No running containers" \
            "" "" "" "" "" ""
    fi
}

# ── 6. Network Security ──
audit_network() {
    print_section "Network Security" "🌐"

    local socket="/var/run/docker.sock"
    if [[ ! -S "$socket" ]]; then
        add_result "net" "Network Audit" "SKIP" "INFO" \
            "Skipped: docker not available" \
            "" "" "" "" "" ""
        return
    fi

    if ! "$DOCKER_BIN" info >/dev/null 2>&1; then
        add_result "net" "Network Audit" "SKIP" "INFO" \
            "Skipped: docker not reachable" \
            "" "" "" "" "" ""
        return
    fi

    # bridge
    if [[ "$(daemon_json_read "bridge")" == "" || "$(daemon_json_read "bridge")" == "null" ]]; then
        add_result "net" "Default Bridge Active" "WARN" "MEDIUM" \
            "Default docker0 bridge active" \
            "Default bridge relies on insecure IP allocation and NAT" \
            "Unrestricted broadcast unless managed carefully" \
            "Use user-defined bridge networks and disable default bridge" \
            '"bridge": null' \
            "https://docs.docker.com/network/bridge/"
    else
        add_result "net" "Default Bridge Active" "INFO" "LOW" \
            "Default bridge dissabled/overridden" \
            "" "" "" "" "" ""
    fi

    # icc
    local icc
    icc=$(daemon_json_read "icc")
    if [[ "$icc" == "false" ]]; then
        add_result "net" "Inter-Container Communication" "PASS" "HIGH" \
            "ICC disabled" \
            "ICC restricts containers from talking to each other" \
            "Any compromised container can probe neighbors" \
            "Disable ICC and use explicit networks" \
            '"icc": false' \
            "https://docs.docker.com/network/icc/"
    else
        add_result "net" "Inter-Container Communication" "FAIL" "HIGH" \
            "ICC enabled or not disabled" \
            "ICC lets all containers on default bridge communicate freely" \
            "Lateral movement across containers becomes trivial" \
            "Disable ICC and use custom networks" \
            '"icc": false' \
            "https://docs.docker.com/network/icc/"
    fi

    # inspect containers
    while IFS= read -r cid; do
        [[ -z "$cid" ]] && continue
        local name
        name=$("$DOCKER_BIN" inspect --format '{{.Name}}' "$cid" 2>/dev/null || true)

        # network mode
        local nmode
        nmode=$("$DOCKER_BIN" inspect --format '{{.HostConfig.NetworkMode}}' "$cid" 2>/dev/null || true)
        if [[ "$nmode" == "host" ]]; then
            add_result "net" "Network Mode" "FAIL" "HIGH" \
                "$name — host network" \
                "Host network removes isolation from host network stack" \
                "Container binds directly to host interfaces" \
                "Avoid host mode; use bridge/overlay networks" \
                "docker run --network=bridge ..." \
                "https://docs.docker.com/network/host/"
        elif [[ "$nmode" == "none" ]]; then
            add_result "net" "Network Mode" "PASS" "INFO" \
                "$name — none" \
                "" "" "" "" "" ""
        else
            add_result "net" "Network Mode" "PASS" "MEDIUM" \
                "$name — $nmode" \
                "" "" "" "" "" ""
        fi

        # exposed ports summary
        local ports
        ports=$("$DOCKER_BIN" inspect --format '{{json .NetworkSettings.Ports}}' "$cid" 2>/dev/null || true)
        if [[ "$ports" != "{}" && -n "$ports" && "$ports" != "null" ]]; then
            add_result "net" "Published Ports" "INFO" "MEDIUM" \
                "$name — $ports" \
                "Exposed ports increase attack surface" \
                "Exposed services can be discovered and exploited" \
                "Bind to 127.0.0.1 or secure LB instead of 0.0.0.0" \
                "docker run -p 127.0.0.1:80:80 ..." \
                "https://docs.docker.com/network/published/"
        else
            add_result "net" "Published Ports" "PASS" "LOW" \
                "$name — none published" \
                "" "" "" "" "" ""
        fi

        # volumes flag
        local vols
        vols=$("$DOCKER_BIN" inspect --format '{{json .Mounts}}' "$cid" 2>/dev/null || true)
        if [[ "$vols" != "[]" && -n "$vols" && "$vols" != "null" ]]; then
            local sensitive_count
            sensitive_count=$(echo "$vols" | grep -oiE '/etc|/var|/root|/home|/run|/proc|/sys' | wc -l || true)
            if [[ "$sensitive_count" -gt 0 ]]; then
                add_result "net" "Volume Mounts" "WARN" "HIGH" \
                    "$name — sensitive host mounts detected" \
                    "Mounting host paths expands container access" \
                    "Container escape may include sensitive host filesystem" \
                    "Bind only necessary paths with ro and relabel/extended confinement" \
                    "docker run -v /app/config:/config:ro ..." \
                    "https://docs.docker.com/engine/security/security/"
            else
                add_result "net" "Volume Mounts" "PASS" "LOW" \
                    "$name — volumes present, not obviously sensitive" \
                    "" "" "" "" "" ""
            fi
        else
            add_result "net" "Volume Mounts" "PASS" "LOW" \
                "$name — no bind mounts" \
                "" "" "" "" "" ""
        fi
    done < <("$DOCKER_BIN" ps -q 2>/dev/null || true)
}

# ── 7. Image Vulnerabilities ──
audit_images() {
    print_section "Image Security" "🖼️"

    local socket="/var/run/docker.sock"
    if [[ ! -S "$socket" ]]; then
        add_result "image" "Image Audit" "SKIP" "INFO" \
            "Skipped: docker not available" \
            "" "" "" "" "" ""
        return
    fi

    if ! "$DOCKER_BIN" info >/dev/null 2>&1; then
        add_result "image" "Image Audit" "SKIP" "INFO" \
            "Skipped: docker not reachable" \
            "" "" "" "" "" ""
        return
    fi

    while IFS= read -r img; do
        [[ -z "$img" ]] && continue

        local repotag
        repotag=$(docker inspect --format '{{.RepoTags}}' "$img" 2>/dev/null || true)
        local hash
        hash=$(docker inspect --format '{{.Id}}' "$img" 2>/dev/null || true)
        local created
        created=$(docker inspect --format '{{.Created}}' "$img" 2>/dev/null || true)

        add_result "image" "Image Reference" "INFO" "LOW" \
            "${repotag:-<none>:<none>} (${hash:0:12})" \
            "" "" "" "" "" ""

        # old base image flag
        local ts
        ts=$(date -d "$created" +%s 2>/dev/null || echo "")
        local now
        now=$(date +%s)
        if [[ -n "$ts" ]]; then
            local age=$(( (now - ts) / 86400 ))
            if [[ "$age" -gt 365 ]]; then
                add_result "image" "Image Age" "WARN" "MEDIUM" \
                    "${hash:0:12} — ${age} days" \
                    "Old base images may contain known CVEs" \
                    "Unpatched libraries increase exploitation risk" \
                    "Rebuild and retag images regularly" \
                    "docker pull ... && docker build ..." \
                    "https://docs.docker.com/build/building/multi-stage/"
            else
                add_result "image" "Image Age" "PASS" "LOW" \
                    "${hash:0:12} — ${age} days" \
                    "" "" "" "" "" ""
            fi
        fi

        # dangling check via repo tags missing
        if [[ "$repotag" == "[]" ]]; then
            add_result "image" "Dangling Image" "WARN" "LOW" \
                "${hash:0:12}" \
                "Dangling images increase attack surface and storage" \
                "Stale layers may register as vulnerable" \
                "Prune old images" \
                "docker image prune -f" \
                "https://docs.docker.com/engine/reference/commandline/image_prune/"
        fi

        # root user in final image
        local user
        user=$(docker inspect --format '{{.Config.User}}' "$img" 2>/dev/null || echo "")
        if [[ -z "$user" || "$user" == "root" ]]; then
            add_result "image" "Container User" "WARN" "HIGH" \
                "${repotag:-unknown} — root" \
                "Images running by default as root" \
                "Container processes run as root inside image filesystem" \
                "Set USER to non-root in Dockerfile" \
                "USER 1000" \
                "https://docs.docker.com/develop/develop-images/dockerfile_best-practices/"
        else
            add_result "image" "Container User" "PASS" "HIGH" \
                "${repotag:-unknown} — $user" \
                "" "" "" "" "" ""
        fi

    done < <(docker images -q 2>/dev/null || true)

    # summary metric
    local image_count
    image_count=$("$DOCKER_BIN" images -q 2>/dev/null | wc -l || true)
    if [[ "$image_count" -gt 20 ]]; then
        add_result "image" "Image Inventory Size" "INFO" "LOW" \
            "$image_count images present" \
            "" \
            "Large image inventories expand potential CVE surface" \
            "" \
            "docker image prune -a --filter until=720h" \
            "https://docs.docker.com/engine/reference/commandline/image_prune/"
    else
        add_result "image" "Image Inventory Size" "INFO" "LOW" \
            "$image_count images present" \
            "" "" "" "" "" "" ""
    fi
}

# ── 8. Logging / Runtime Metadata ──
audit_logging() {
    print_section "Logging & Runtime Metadata" "📄"

    local log
    log=$(daemon_json_read "log-driver")
    if [[ "$log" == "" || "$log" == "null" ]]; then
        add_result "log" "Logging Driver" "INFO" "LOW" \
            "Default (json-file)" \
            "Default driver may lack central log control" \
            "Log files can fill disk and hide forensic data" \
            "Configure centralized logging under audit policy" \
            '"log-driver": "json-file"' \
            "https://docs.docker.com/config/containers/logging/configure/"
    else
        add_result "log" "Logging Driver" "PASS" "MEDIUM" \
            "$log" \
            "Explicit logging driver helps retention and compliance" \
            "Weak logger causes loss of telemetry" \
            "Consider fluentd/awslogs/splunk for production" \
            '"log-driver": "json-file"' \
            "https://docs.docker.com/config/containers/logging/configure/"
    fi

    # default runtime check via policy is optional; keep as informational.
    add_result "log" "Runtime Metadata" "INFO" "LOW" \
        "Metadata logged as available" \
        "" "" "" "" "" ""
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
  "tool": "nawasec-audit-docker",
  "version": "$VERSION",
  "framework": "$FRAMEWORK_VERSION",
  "timestamp": "$(date -Iseconds)",
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
<title>NawaSec Audit — Docker Security Report</title>
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
<h1>🔒 NawaSec Audit — Docker Security</h1>
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
        [[ -n "$example" ]] && echo "<div class='example'>\\$ ${example}</div>" >> "$REPORT_HTML"
        echo "</td></tr>" >> "$REPORT_HTML"
    done

    echo "</tbody></table>" >> "$REPORT_HTML"
    echo "<footer>NawaSec Audit v${VERSION} — Docker Security — Generated $(date) — https://github.com/kangaman/nawasec-audit</footer>" >> "$REPORT_HTML"
    echo "</body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — Docker Security Report                       ║
║  Version: ${VERSION} (Framework: ${FRAMEWORK_VERSION})       ║
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
        [[ -n "$example" ]] && echo "      \\$ ${example}" >> "$REPORT_TXT"
    done

    cat >> "$REPORT_TXT" <<EOF

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Score:  ${SCORE}/100
  Passed: ${PASS}  |  Warnings: ${WARN}  |  Failed: ${FAIL}
  Info:   ${INFO}  |  Skipped: ${SKIP}   |  Total: ${TOTAL}
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  NawaSec Audit v${VERSION} — Docker Security
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
    detect_docker

    if [[ "$OPT_QUIET" -eq 0 ]]; then
        echo -e "${C}${BOLD}"
        echo "  ╔═══════════════════════════════════════════════════════╗"
        echo "  ║  NawaSec Audit — Docker Security                     ║"
        echo "  ║  v${VERSION} (Framework v${FRAMEWORK_VERSION})                        ║"
        echo "  ╚═══════════════════════════════════════════════════════╝"
        echo -e "${N}"
        echo -e "  ${DIM}Started: $(date)${N}"
        echo ""
    fi

    audit_detection || true
    audit_daemon_config || true
    audit_socket_permissions || true
    audit_modes || true
    audit_privileges || true
    audit_network || true
    audit_images || true
    audit_logging || true

    calculate_score

    if [[ "$OPT_JSON" -eq 1 ]]; then
        generate_json
    fi
    if [[ "$OPT_HTML" -eq 1 ]]; then
        generate_html
    fi
    if [[ "$OPT_TXT" -eq 1 ]]; then
        generate_txt
    fi

    print_summary

    # Return non-zero if any FAILs, useful for CI wrappers
    [[ "$FAIL" -gt 0 ]] && exit 2 || exit 0
}

main "$@"
