#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — Database Security Audit                                ║
# ║  Version: 2.1.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based Database security audit — NO AI, NO external API calls.
# Supports: MySQL 5.7+/8.0+, MariaDB 10.3+, PostgreSQL 12+
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-database.sh [options]
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
SCRIPT_NAME="NawaSec Audit - Database"
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
OUTPUT_DIR="/tmp/nawasec-database"
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
            echo "NawaSec Audit - Database v${VERSION}"
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
REPORT_HTML="$OUTPUT_DIR/nawasec-database-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/nawasec-database-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/nawasec-database-${TIMESTAMP}.txt"

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

DB_TYPE=""
DB_VERSION=""
DB_CONF=""
DB_BIN=""
MYSQL_BIN=""
PGSQL_BIN=""
MARIADB_BIN=""

detect_database() {
    print_section "Database Detection" "🔍"

    # Detect MySQL
    if command -v mysql &>/dev/null; then
        MYSQL_BIN=$(command -v mysql)
        DB_BIN="$MYSQL_BIN"
        DB_TYPE="mysql"
        DB_VERSION=$(mysql --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
        DB_CONF="/etc/mysql/mysql.conf.d/mysqld.cnf"
        [[ ! -f "$DB_CONF" ]] && DB_CONF="/etc/my.cnf"
        [[ ! -f "$DB_CONF" ]] && DB_CONF="/etc/mysql/my.cnf"
        add_result "detection" "MySQL Binary" "PASS" "INFO" \
            "Found: $MYSQL_BIN" "" "" "" "" ""
    fi

    # Detect MariaDB
    if command -v mariadb &>/dev/null; then
        MARIADB_BIN=$(command -v mariadb)
        DB_BIN="$MARIADB_BIN"
        DB_TYPE="mariadb"
        DB_VERSION=$(mariadb --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
        DB_CONF="/etc/mysql/mariadb.conf.d/50-server.cnf"
        [[ ! -f "$DB_CONF" ]] && DB_CONF="/etc/my.cnf"
        add_result "detection" "MariaDB Binary" "PASS" "INFO" \
            "Found: $MARIADB_BIN" "" "" "" "" ""
    fi

    # Detect PostgreSQL
    if command -v psql &>/dev/null; then
        PGSQL_BIN=$(command -v psql)
        if [[ -z "$DB_TYPE" ]]; then
            DB_BIN="$PGSQL_BIN"
            DB_TYPE="postgresql"
            DB_VERSION=$(psql --version 2>/dev/null | grep -oP '[\d.]+' | head -1)
            DB_CONF=$(su - postgres -c "psql -t -c 'SHOW config_file'" 2>/dev/null | tr -d ' ')
            [[ -z "$DB_CONF" ]] && DB_CONF="/etc/postgresql/*/main/postgresql.conf"
            add_result "detection" "PostgreSQL Binary" "PASS" "INFO" \
                "Found: $PGSQL_BIN" "" "" "" "" ""
        else
            add_result "detection" "PostgreSQL Binary" "INFO" "INFO" \
                "Found: $PGSQL_BIN (secondary)" "" "" "" "" ""
        fi
    fi

    # Check if any database found
    if [[ -z "$DB_TYPE" ]]; then
        add_result "detection" "Database" "FAIL" "CRITICAL" \
            "No database server found" \
            "No MySQL, MariaDB, or PostgreSQL detected on this system" \
            "Cannot perform database audit" \
            "Install a database server: apt install mysql-server OR apt install postgresql" \
            "apt install mysql-server" \
            "https://dev.mysql.com/doc/refman/8.0/en/installing.html"
        return 1
    fi

    # Version info
    if [[ -n "$DB_VERSION" ]]; then
        add_result "detection" "Database Version" "INFO" "INFO" \
            "$DB_TYPE $DB_VERSION" "" "" "" "" ""
    fi

    # Check service status
    local svc_name="$DB_TYPE"
    [[ "$DB_TYPE" == "mariadb" ]] && svc_name="mariadb"
    [[ "$DB_TYPE" == "postgresql" ]] && svc_name="postgresql"

    if systemctl is-active --quiet "$svc_name" 2>/dev/null; then
        add_result "detection" "Service Status" "PASS" "INFO" \
            "Running" "" "" "" "" ""
    else
        add_result "detection" "Service Status" "FAIL" "CRITICAL" \
            "Not running" \
            "Database service is not active" \
            "Applications cannot connect to database" \
            "Start service: systemctl start $svc_name" \
            "systemctl start $svc_name" \
            ""
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════
#  MYSQL/MARIADB AUDIT
# ═══════════════════════════════════════════════════════════════

audit_mysql() {
    print_section "MySQL/MariaDB Security" "🔒"

    if [[ -z "$DB_CONF" ]] || [[ ! -f "$DB_CONF" ]]; then
        add_result "config" "Config File" "WARN" "HIGH" \
            "Config file not found" \
            "Cannot audit MySQL configuration without config file" \
            "Security settings may be unknown" \
            "Check MySQL installation and config path" \
            "mysqld --help --verbose 2>/dev/null | grep -A1 'Default options'" \
            ""
        return 1
    fi

    add_result "config" "Config File" "PASS" "INFO" \
        "$DB_CONF" "" "" "" "" ""

    # ── 1. Network & Binding ──
    print_section "Network Configuration" "🌐"

    local bind=$(grep -i "^bind-address" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$bind" == "127.0.0.1" ]] || [[ "$bind" == "localhost" ]]; then
        add_result "network" "Bind Address" "PASS" "HIGH" \
            "$bind — Localhost only" \
            "Database only accepts connections from local machine" \
            "" "" "" ""
    elif [[ -z "$bind" ]]; then
        add_result "network" "Bind Address" "WARN" "HIGH" \
            "Not set — defaults to 0.0.0.0" \
            "MySQL will listen on all interfaces including public" \
            "Unauthorized remote access to database" \
            "Add 'bind-address = 127.0.0.1' to $DB_CONF" \
            "bind-address = 127.0.0.1" \
            "https://dev.mysql.com/doc/refman/8.0/en/server-options.html"
    elif [[ "$bind" == "0.0.0.0" ]] || [[ "$bind" == "*" ]]; then
        add_result "network" "Bind Address" "FAIL" "HIGH" \
            "$bind — All interfaces" \
            "Database listens on all network interfaces" \
            "Anyone who can reach the port can attempt connection" \
            "Bind to localhost if remote access not needed: bind-address = 127.0.0.1" \
            "bind-address = 127.0.0.1" \
            "https://dev.mysql.com/doc/refman/8.0/en/server-options.html"
    else
        add_result "network" "Bind Address" "INFO" "MEDIUM" \
            "$bind — Specific interface" "" "" "" "" ""
    fi

    local port=$(grep -i "^port" "$DB_CONF" 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ')
    if [[ -z "$port" ]]; then
        port="3306 (default)"
    fi
    local clean_port=$(echo "$port" | tr -d "\t" | awk "{print \$1}")
        add_result "network" "Port" "INFO" "INFO" \
                "${clean_port:-5432}" "" "" "" "" ""

    local skip_networking=$(grep -i "^skip-networking" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$skip_networking" == "1" ]] || [[ "$skip_networking" == "ON" ]]; then
        add_result "network" "Skip Networking" "PASS" "HIGH" \
            "Enabled — TCP/IP disabled" \
            "Network connections disabled, only socket connections allowed" \
            "" "" "" ""
    else
        add_result "network" "Skip Networking" "INFO" "INFO" \
            "Not enabled" "" "" "" "" ""
    fi

    # ── 2. Authentication & Users ──
    print_section "Authentication & Users" "👤"

    local skip_grant=$(grep -i "^skip-grant-tables" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$skip_grant" == "1" ]] || [[ "$skip_grant" == "ON" ]]; then
        add_result "auth" "Skip Grant Tables" "FAIL" "CRITICAL" \
            "ENABLED — No authentication!" \
            "skip-grant-tables bypasses all authentication checks" \
            "Anyone can connect without password and have full privileges" \
            "DISABLE IMMEDIATELY: Remove or comment out skip-grant-tables in $DB_CONF" \
            "# skip-grant-tables  (must be commented out)" \
            "https://dev.mysql.com/doc/refman/8.0/en/server-options.html"
    else
        add_result "auth" "Skip Grant Tables" "PASS" "CRITICAL" \
            "Disabled — Normal authentication active" "" "" "" "" ""
    fi

    local old_passwords=$(grep -i "^old_passwords" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$old_passwords" == "1" ]] || [[ "$old_passwords" == "ON" ]]; then
        add_result "auth" "Old Passwords" "FAIL" "HIGH" \
            "Enabled — Weak password hashing" \
            "Uses pre-4.1 password hashing (16-byte)" \
            "Passwords easily crackable" \
            "Disable: SET GLOBAL old_passwords = 0; and update user passwords" \
            "SET GLOBAL old_passwords = 0;" \
            "https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html"
    else
        add_result "auth" "Old Passwords" "PASS" "HIGH" \
            "Disabled — Modern password hashing" "" "" "" "" ""
    fi

    local native_auth=$(grep -i "default_authentication_plugin\|authentication_policy" "$DB_CONF" 2>/dev/null | head -1)
    if echo "$native_auth" | grep -qi "mysql_native_password"; then
        add_result "auth" "Authentication Plugin" "WARN" "MEDIUM" \
            "mysql_native_password — Consider caching_sha2_password" \
            "mysql_native_password uses SHA1 which is weaker than SHA256" \
            "Weaker password hashing" \
            "Consider using caching_sha2_password for MySQL 8.0+" \
            "default_authentication_plugin=caching_sha2_password" \
            "https://dev.mysql.com/doc/refman/8.0/en/caching-sha2-pluggable-authentication.html"
    fi

    # ── 3. Privileges ──
    print_section "Privileges & Access Control" "🔐"

    local secure_file_priv=$(grep -i "^secure-file-priv" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$secure_file_priv" == "NULL" ]] || [[ "$secure_file_priv" == "" ]]; then
        if [[ -z "$secure_file_priv" ]]; then
            add_result "privileges" "secure-file-priv" "WARN" "MEDIUM" \
                "Not set — LOAD_FILE/INTO OUTFILE unrestricted" \
                "Without secure-file-priv, SQL can read/write any file" \
                "Data exfiltration or file overwrite via SQL injection" \
                "Set secure-file-priv = /var/lib/mysql-files/" \
                "secure-file-priv = /var/lib/mysql-files/" \
                "https://dev.mysql.com/doc/refman/8.0/en/server-system-variables.html"
        else
            add_result "privileges" "secure-file-priv" "PASS" "MEDIUM" \
                "Set to NULL — File operations disabled" "" "" "" "" ""
        fi
    else
        add_result "privileges" "secure-file-priv" "PASS" "MEDIUM" \
            "Set to: $secure_file_priv" "" "" "" "" ""
    fi

    local local_infile=$(grep -i "^local-infile" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$local_infile" == "1" ]] || [[ "$local_infile" == "ON" ]]; then
        add_result "privileges" "local-infile" "FAIL" "HIGH" \
            "Enabled — LOAD DATA LOCAL allowed" \
            "LOAD DATA LOCAL INFILE can read client files via SQL" \
            "File read via SQL injection or malicious server" \
            "Disable: local-infile = 0" \
            "local-infile = 0" \
            "https://dev.mysql.com/doc/refman/8.0/en/load-data-local-security.html"
    else
        add_result "privileges" "local-infile" "PASS" "HIGH" \
            "Disabled — LOAD DATA LOCAL blocked" "" "" "" "" ""
    fi

    # ── 4. Logging ──
    print_section "Logging & Auditing" "📝"

    local log_error=$(grep -i "^log-error" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ -n "$log_error" ]]; then
        add_result "logging" "Error Log" "PASS" "MEDIUM" \
            "Enabled: $log_error" "" "" "" "" ""
    else
        add_result "logging" "Error Log" "WARN" "MEDIUM" \
            "Not configured" \
            "Error log helps detect issues and security events" \
            "Security incidents may go unnoticed" \
            "Add: log-error = /var/log/mysql/error.log" \
            "log-error = /var/log/mysql/error.log" \
            ""
    fi

    local general_log=$(grep -i "^general_log" "$DB_CONF" 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$general_log" == "1" ]] || [[ "$general_log" == "ON" ]]; then
        add_result "logging" "General Log" "WARN" "LOW" \
            "Enabled — All queries logged" \
            "General log records ALL queries including passwords" \
            "Performance impact and sensitive data in logs" \
            "Disable in production, enable only for debugging" \
            "general_log = 0" \
            ""
    else
        add_result "logging" "General Log" "PASS" "LOW" \
            "Disabled" "" "" "" "" ""
    fi

    local slow_log=$(grep -i "^slow_query_log" "$DB_CONF" 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$slow_log" == "1" ]] || [[ "$slow_log" == "ON" ]]; then
        add_result "logging" "Slow Query Log" "PASS" "LOW" \
            "Enabled — Slow queries logged" "" "" "" "" ""
    else
        add_result "logging" "Slow Query Log" "INFO" "LOW" \
            "Disabled — Consider enabling for performance monitoring" "" "" "" "" ""
    fi

    # ── 5. TLS/SSL ──
    print_section "TLS/SSL Encryption" "🔒"

    local ssl=$(grep -i "^ssl\|^require-secure-transport" "$DB_CONF" 2>/dev/null | head -1)
    if echo "$ssl" | grep -qi "= 1\|= ON\|REQUIRED"; then
        add_result "tls" "SSL/TLS" "PASS" "HIGH" \
            "Enabled" "" "" "" "" ""
    else
        add_result "tls" "SSL/TLS" "WARN" "HIGH" \
            "Not configured or disabled" \
            "Without TLS, data transmitted in plaintext" \
            "Credentials and data can be intercepted" \
            "Enable SSL: require-secure-transport = ON" \
            "require-secure-transport = ON" \
            "https://dev.mysql.com/doc/refman/8.0/en/using-encrypted-connections.html"
    fi

    # ── 6. Dangerous Settings ──
    print_section "Dangerous Settings" "⚠️"

    local symbolic_links=$(grep -i "^symbolic-links" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$symbolic_links" == "1" ]] || [[ "$symbolic_links" == "ON" ]]; then
        add_result "dangerous" "Symbolic Links" "WARN" "MEDIUM" \
            "Enabled — Symlinks allowed" \
            "Symlinks can be exploited for file access outside data directory" \
            "Potential data access or denial of service" \
            "Disable: symbolic-links = 0" \
            "symbolic-links = 0" \
            ""
    else
        add_result "dangerous" "Symbolic Links" "PASS" "MEDIUM" \
            "Disabled" "" "" "" "" ""
    fi

    local allow_suspicious=$(grep -i "^allow-suspicious-udfs" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ "$allow_suspicious" == "1" ]] || [[ "$allow_suspicious" == "ON" ]]; then
        add_result "dangerous" "Suspicious UDFs" "FAIL" "HIGH" \
            "Enabled — Untrusted UDFs allowed" \
            "User-defined functions from untrusted sources can execute arbitrary code" \
            "Remote code execution" \
            "Disable: allow-suspicious-udfs = 0" \
            "allow-suspicious-udfs = 0" \
            ""
    else
        add_result "dangerous" "Suspicious UDFs" "PASS" "HIGH" \
            "Disabled" "" "" "" "" ""
    fi

    # ── 7. Connection Limits ──
    print_section "Connection Limits" "🔗"

    local max_connections=$(grep -i "^max_connections" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ -n "$max_connections" ]]; then
        if [[ "$max_connections" -gt 1000 ]]; then
            add_result "connections" "Max Connections" "WARN" "MEDIUM" \
                "$max_connections — Very high limit" \
                "Excessive max connections can lead to resource exhaustion" \
                "Potential DoS via connection flooding" \
                "Set reasonable limit: max_connections = 151 (default) or lower" \
                "max_connections = 151" \
                ""
        else
            add_result "connections" "Max Connections" "PASS" "MEDIUM" \
                "$max_connections" "" "" "" "" ""
        fi
    else
        add_result "connections" "Max Connections" "INFO" "MEDIUM" \
            "Not set — Using default (151)" "" "" "" "" ""
    fi

    local max_connect_errors=$(grep -i "^max_connect_errors" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ -n "$max_connect_errors" ]] && [[ "$max_connect_errors" -gt 100 ]]; then
        add_result "connections" "Max Connect Errors" "INFO" "LOW" \
            "$max_connect_errors — High threshold" \
            "Host blocked after this many consecutive connection errors" \
            "" "" "" ""
    fi

    local wait_timeout=$(grep -i "^wait_timeout" "$DB_CONF" 2>/dev/null | awk -F= '{print $2}' | tr -d ' ')
    if [[ -n "$wait_timeout" ]] && [[ "$wait_timeout" -gt 28800 ]]; then
        add_result "connections" "Wait Timeout" "WARN" "LOW" \
            "$wait_timeout seconds — Very long idle timeout" \
            "Idle connections consume server resources" \
            "Resource exhaustion under high connection churn" \
            "Set to 300-3600 seconds for production" \
            "wait_timeout = 600" \
            ""
    fi
}

# ═══════════════════════════════════════════════════════════════
#  POSTGRESQL AUDIT
# ═══════════════════════════════════════════════════════════════

audit_postgresql() {
    print_section "PostgreSQL Security" "🔒"

    local pg_conf="$DB_CONF"
    if [[ -z "$pg_conf" ]] || [[ ! -f "$pg_conf" ]]; then
        # Try common paths
        for path in /etc/postgresql/*/main/postgresql.conf /var/lib/pgsql/data/postgresql.conf; do
            if [[ -f "$path" ]]; then
                pg_conf="$path"
                break
            fi
        done
    fi

    if [[ -z "$pg_conf" ]] || [[ ! -f "$pg_conf" ]]; then
        add_result "config" "Config File" "WARN" "HIGH" \
            "PostgreSQL config not found" \
            "Cannot audit without postgresql.conf" \
            "Security settings may be unknown" \
            "Check PostgreSQL installation" \
            "" ""
        return 1
    fi

    add_result "config" "Config File" "PASS" "INFO" \
        "$pg_conf" "" "" "" "" ""

    local pg_hba="${pg_conf%/*}/pg_hba.conf"
    [[ ! -f "$pg_hba" ]] && pg_hba=$(find /etc/postgresql -name "pg_hba.conf" 2>/dev/null | head -1)

    # ── 1. Network ──
    print_section "Network Configuration" "🌐"

    local listen=$(grep -i "^listen_addresses" "$pg_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '")
    if [[ "$listen" == "localhost" ]] || [[ "$listen" == "127.0.0.1" ]]; then
        add_result "network" "Listen Addresses" "PASS" "HIGH" \
            "localhost — Localhost only" "" "" "" "" ""
    elif [[ -z "$listen" ]] || [[ "$listen" == "*" ]]; then
        add_result "network" "Listen Addresses" "WARN" "HIGH" \
            "All interfaces — Remote connections allowed" \
            "PostgreSQL will accept connections from any network" \
            "Unauthorized remote access" \
            "Set: listen_addresses = 'localhost'" \
            "listen_addresses = 'localhost'" \
            "https://www.postgresql.org/docs/current/runtime-config-connection.html"
    fi

    local port=$(grep -i "^port" "$pg_conf" 2>/dev/null | head -1 | awk -F= '{print $2}' | awk '{print $1}' | tr -d " \t\n")
        [[ -z "$port" ]] && port="5432"
        add_result "network" "Port" "INFO" "INFO" \
                "$port" "" "" "" "" ""

    # ── 2. Authentication ──
    print_section "Authentication" "👤"

    local pass_encryption=$(grep -i "^password_encryption" "$pg_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '")
    if [[ "$pass_encryption" == "scram-sha-256" ]]; then
        add_result "auth" "Password Encryption" "PASS" "HIGH" \
            "scram-sha-256 — Strongest" "" "" "" "" ""
    elif [[ "$pass_encryption" == "md5" ]]; then
        add_result "auth" "Password Encryption" "WARN" "HIGH" \
            "md5 — Consider scram-sha-256" \
            "MD5 is weaker than SCRAM-SHA-256" \
            "Password hash can be attacked offline" \
            "Set: password_encryption = scram-sha-256" \
            "password_encryption = scram-sha-256" \
            "https://www.postgresql.org/docs/current/auth-password.html"
    fi

    if [[ -f "$pg_hba" ]]; then
        add_result "auth" "pg_hba.conf" "PASS" "INFO" \
            "Found: $pg_hba" "" "" "" "" ""

        # Check for trust auth
        local trust_count=$(grep -c "^.*trust$" "$pg_hba" 2>/dev/null | tail -1) ; trust_count=${trust_count:-0}
        if [[ "$trust_count" -gt 0 ]]; then
            add_result "auth" "Trust Authentication" "FAIL" "CRITICAL" \
                "$trust_count trust entries found" \
                "Trust authentication allows ANY connection without password" \
                "Complete bypass of authentication" \
                "Replace 'trust' with 'scram-sha-256' or 'md5'" \
                "host all all 127.0.0.1/32 scram-sha-256" \
                "https://www.postgresql.org/docs/current/auth-pg-hba-conf.html"
        else
            add_result "auth" "Trust Authentication" "PASS" "CRITICAL" \
                "No trust entries found" "" "" "" "" ""
        fi

        # Check for peer auth
        local peer_count=$(grep -c "^.*peer$" "$pg_hba" 2>/dev/null | tail -1) ; peer_count=${peer_count:-0}
        if [[ "$peer_count" -gt 0 ]]; then
            add_result "auth" "Peer Authentication" "PASS" "HIGH" \
                "Peer auth used — OS user must match DB user" "" "" "" "" ""
        fi
    fi

    # ── 3. Logging ──
    print_section "Logging & Auditing" "📝"

    local log_connections=$(grep -i "^log_connections" "$pg_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '")
    if [[ "$log_connections" == "on" ]]; then
        add_result "logging" "Log Connections" "PASS" "MEDIUM" \
            "Enabled" "" "" "" "" ""
    else
        add_result "logging" "Log Connections" "WARN" "MEDIUM" \
            "Disabled" \
            "Connection attempts not logged" \
            "Unauthorized access attempts invisible" \
            "Enable: log_connections = on" \
            "log_connections = on" \
            ""
    fi

    local log_disconnections=$(grep -i "^log_disconnections" "$pg_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '")
    if [[ "$log_disconnections" == "on" ]]; then
        add_result "logging" "Log Disconnections" "PASS" "MEDIUM" \
            "Enabled" "" "" "" "" ""
    else
        add_result "logging" "Log Disconnections" "WARN" "LOW" \
            "Disabled" \
            "Session duration not tracked" \
            "Cannot detect long-running unauthorized sessions" \
            "Enable: log_disconnections = on" \
            "log_disconnections = on" \
            ""
    fi

    local log_statement=$(grep -i "^log_statement" "$pg_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '")
    case "$log_statement" in
        ddl|mod|all)
            add_result "logging" "Log Statement" "PASS" "MEDIUM" \
                "$log_statement — Statements logged" "" "" "" "" "" ;;
        none|"")
            add_result "logging" "Log Statement" "INFO" "MEDIUM" \
                "none — Only DDL/mod recommended for audit" "" "" "" "" "" ;;
    esac

    # ── 4. TLS/SSL ──
    print_section "TLS/SSL" "🔒"

    local ssl=$(grep -i "^ssl" "$pg_conf" 2>/dev/null | head -1 | awk -F= '{print $2}' | tr -d " '")
    if [[ "$ssl" == "on" ]]; then
        add_result "tls" "SSL" "PASS" "HIGH" \
            "Enabled" "" "" "" "" ""

        local ssl_min=$(grep -i "^ssl_min_protocol_version" "$pg_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '")
        if [[ -n "$ssl_min" ]]; then
            case "$ssl_min" in
                TLSv1.2|TLSv1.3)
                    add_result "tls" "Min TLS Version" "PASS" "HIGH" \
                        "$ssl_min — Secure minimum" "" "" "" "" "" ;;
                TLSv1|TLSv1.1)
                    add_result "tls" "Min TLS Version" "FAIL" "HIGH" \
                        "$ssl_min — Deprecated protocol" \
                        "TLS 1.0/1.1 have known vulnerabilities" \
                        "Man-in-the-middle attacks" \
                        "Set: ssl_min_protocol_version = 'TLSv1.2'" \
                        "ssl_min_protocol_version = 'TLSv1.2'" \
                        "" ;;
            esac
        fi
    else
        add_result "tls" "SSL" "WARN" "HIGH" \
            "Disabled" \
            "Connections transmit data in plaintext" \
            "Credentials and data can be intercepted" \
            "Enable SSL in postgresql.conf" \
            "ssl = on" \
            "https://www.postgresql.org/docs/current/ssl-tcp.html"
    fi

    # ── 5. Dangerous Settings ──
    print_section "Dangerous Settings" "⚠️"

    local data_checksums=$(grep -i "^data_checksums" "$pg_conf" 2>/dev/null | awk -F= '{print $2}' | tr -d " '")
    if [[ "$data_checksums" == "on" ]]; then
        add_result "dangerous" "Data Checksums" "PASS" "HIGH" \
            "Enabled — Storage corruption detection" "" "" "" "" ""
    else
        add_result "dangerous" "Data Checksums" "WARN" "MEDIUM" \
            "Disabled" \
            "Storage corruption not automatically detected" \
            "Silent data corruption possible" \
            "Enable during initdb: initdb --data-checksums" \
            "initdb --data-checksums" \
            "https://www.postgresql.org/docs/current/app-initdb.html"
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
  "tool": "nawasec-audit-database",
  "version": "$VERSION",
  "framework": "$FRAMEWORK_VERSION",
  "timestamp": "$(date -Iseconds)",
  "hostname": "$(hostname)",
  "database_type": "$DB_TYPE",
  "database_version": "$DB_VERSION",
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
<title>NawaSec Audit — Database Security Report</title>
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
<h1>🔒 NawaSec Audit — Database Security</h1>
<p class="sub">$(hostname) — $(date) — ${DB_TYPE^} ${DB_VERSION} — v${VERSION}</p>
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
    echo "<footer>NawaSec Audit v${VERSION} — Database Security — Generated $(date) — https://github.com/kangaman/nawasec-audit</footer>" >> "$REPORT_HTML"
    echo "</body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — Database Security Report                    ║
║  Version: ${VERSION} (Framework: ${FRAMEWORK_VERSION})       ║
╚══════════════════════════════════════════════════════════════╝

Hostname:       $(hostname)
Date:           $(date)
Database Type:  ${DB_TYPE^}
Database Ver:   ${DB_VERSION}
Score:          ${SCORE}/100

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
  NawaSec Audit v${VERSION} — Database Security
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
        echo "  ║  NawaSec Audit — Database Security                   ║"
        echo "  ║  v${VERSION} (Framework v${FRAMEWORK_VERSION})                        ║"
        echo "  ╚═══════════════════════════════════════════════════════╝"
        echo -e "${N}"
        echo -e "  ${DIM}Started: $(date)${N}"
        echo ""
    fi

    # Detect database
    detect_database || true

    # Run audit based on database type
    case "$DB_TYPE" in
        mysql|mariadb) audit_mysql ;;
        postgresql)    audit_postgresql ;;
    esac

    # Calculate & output
    calculate_score
    print_summary

    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]]  && generate_txt

    exit 0
}

main "$@"
