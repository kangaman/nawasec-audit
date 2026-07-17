#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — SSL/TLS Security Audit                                 ║
# ║  Version: 2.1.0                                                        ║
# ║  Framework: 2.0.0                                                      ║
# ║  License: MIT                                                          ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based SSL/TLS security audit — NO AI, NO external API calls.
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report

set -uo pipefail

VERSION="2.1.0"
FRAMEWORK_VERSION="2.0.0"
SCRIPT_NAME="NawaSec Audit - SSL/TLS"
DEFAULT_HOST="localhost"
DEFAULT_PORT="443"
DEFAULT_OUTPUT_DIR="/tmp/nawasec-ssl"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")

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
TARGET_HOST="$DEFAULT_HOST"
TARGET_PORT="$DEFAULT_PORT"
OUTPUT_DIR="$DEFAULT_OUTPUT_DIR"

while [[ $# -gt 0 ]]; do
    case $1 in
        --host) TARGET_HOST="$2"; shift 2 ;;
        --json) OPT_JSON=1; OPT_HTML=0; shift ;;
        --html) OPT_HTML=1; shift ;;
        --txt)  OPT_TXT=1; shift ;;
        --all)  OPT_HTML=1; OPT_JSON=1; OPT_TXT=1; shift ;;
        --quiet) OPT_QUIET=1; shift ;;
        --no-color) export NO_COLOR=1; shift ;;
        --output) OUTPUT_DIR="$2"; shift 2 ;;
        --help|-h)
            cat <<EOF
Usage: sudo $0 [options]

NawaSec Audit - SSL/TLS v${VERSION}
Framework: NawaSec Audit v${FRAMEWORK_VERSION}

Options:
  --host HOST:PORT   Remote host to scan (default: ${DEFAULT_HOST}:${DEFAULT_PORT})
  --html             Generate HTML dashboard (default)
  --json             Generate JSON report
  --txt              Generate TXT report
  --all              Generate all formats
  --quiet            Minimal console output
  --no-color         Disable colored output
  --output DIR       Custom output directory
  --help             Show this help

Examples:
  $0 --host example.com:443
  $0 --host 10.0.0.1:8443 --all
EOF
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"
REPORT_HTML="$OUTPUT_DIR/ssl-tls-audit-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/ssl-tls-audit-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/ssl-tls-audit-${TIMESTAMP}.txt"

# ═══════════════════════════════════════════════════════════════════════════
#  STANDARD add_result FUNCTION (NawaSec Template v2.1.0)
# ═══════════════════════════════════════════════════════════════════════════

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

    local esc_msg esc_expl esc_risk esc_impact esc_rec esc_ex esc_ref
    esc_msg=$(echo "$message" | sed 's/\\/\\\\/g; s/"/\\"/g')
    esc_expl=$(echo "$explanation" | sed 's/\\/\\\\/g; s/"/\\"/g')
    esc_risk=$(echo "$risk" | sed 's/\\/\\\\/g; s/"/\\"/g')
    esc_impact=$(echo "$impact" | sed 's/\\/\\\\/g; s/"/\\"/g')
    esc_rec=$(echo "$recommendation" | sed 's/\\/\\\\/g; s/"/\\"/g')
    esc_ex=$(echo "$example" | sed 's/\\/\\\\/g; s/"/\\"/g')
    esc_ref=$(echo "$reference" | sed 's/\\/\\\\/g; s/"/\\"/g')
    RESULTS+=("{\"category\":\"${category}\",\"name\":\"${name}\",\"status\":\"${status}\",\"severity\":\"${severity}\",\"message\":\"${esc_msg}\",\"explanation\":\"${esc_expl}\",\"risk\":\"${esc_risk}\",\"impact\":\"${esc_impact}\",\"recommendation\":\"${esc_rec}\",\"example\":\"${esc_ex}\",\"reference\":\"${esc_ref}\"}")
}

# ═══════════════════════════════════════════════════════════════════════════
#  STANDARD print_section FUNCTION
# ═══════════════════════════════════════════════════════════════════════════

print_section() {
    local title="$1"
    local icon="${2:-▸}"
    [[ "$OPT_QUIET" -eq 0 ]] && echo -e "\n${C}${BOLD}${icon} ${title}${N}" && echo -e "${DIM}$(printf '─%.0s' {1..60})${N}"
}

# ═══════════════════════════════════════════════════════════════════════════
#  GLOBALS
# ═══════════════════════════════════════════════════════════════════════════

SSL_CONNECT_OUT=""
TMP_CERT=""

# ═══════════════════════════════════════════════════════════════════════════
#  DETECTION
# ═══════════════════════════════════════════════════════════════════════════

audit_detection() {
    print_section "Detection" "🔍"

    if ! command -v openssl &>/dev/null; then
        add_result "detection" "OpenSSL Binary" "FAIL" "CRITICAL" \
            "OpenSSL not found" \
            "Cannot perform SSL/TLS audit without OpenSSL" \
            "No audit possible" \
            "Install: apt install openssl" \
            "apt install openssl" \
            "https://www.openssl.org/"
        return 1
    fi

    local openssl_ver
    openssl_ver=$(openssl version 2>/dev/null || echo "unknown")
    add_result "detection" "OpenSSL Binary" "PASS" "INFO" "Found: $openssl_ver" "" "" "" "" ""

    if ! command -v curl &>/dev/null; then
        add_result "detection" "curl" "FAIL" "CRITICAL" \
            "curl not found" \
            "curl is required for header checks" \
            "No header checks possible" \
            "Install: apt install curl" \
            "apt install curl" \
            "https://curl.se/"
        return 1
    fi

    add_result "detection" "Target" "PASS" "INFO" "$TARGET_HOST:$TARGET_PORT" "" "" "" "" ""

    SSL_CONNECT_OUT=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -servername "$TARGET_HOST" 2>&1 || true)
    if [[ -z "$SSL_CONNECT_OUT" ]]; then
        add_result "detection" "Connection" "FAIL" "CRITICAL" \
            "Cannot connect to $TARGET_HOST:$TARGET_PORT" \
            "Port may be closed" \
            "Verify SSL/TLS service is running" \
            "nc -zv $TARGET_HOST $TARGET_PORT" \
            ""
        return 1
    fi
    add_result "detection" "Connection" "PASS" "INFO" "Connected successfully" "" "" "" "" ""

    if echo "$SSL_CONNECT_OUT" | grep -qi "self signed"; then
        add_result "detection" "Certificate Type" "WARN" "MEDIUM" \
            "Self-signed certificate detected" \
            "Self-signed certs are not trusted by browsers" \
            "Use a CA-signed certificate" \
            "certbot --nginx -d example.com" \
            "https://letsencrypt.org/docs/free-ssl/"
    else
        add_result "detection" "Certificate Type" "PASS" "INFO" "CA-signed or enterprise" "" "" "" "" ""
    fi

    return 0
}

# ═══════════════════════════════════════════════════════════════════════════
#  TLS PROTOCOL VERSIONS
# ═══════════════════════════════════════════════════════════════════════════

check_tls_versions() {
    print_section "TLS Protocol Versions" "🔐"

    local out10
    out10=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -tls1 2>/dev/null || true)
    if echo "$out10" | grep -qi "Protocol\s*:\s*TLSv1\b"; then
        add_result "tls" "TLS 1.0" "FAIL" "HIGH" "TLS 1.0 enabled" \
            "TLS 1.0 is deprecated and vulnerable to BEAST, POODLE" \
            "Downgrade attacks, data decryption" \
            "Disable TLS 1.0: ssl_protocols TLSv1.2 TLSv1.3;" \
            "ssl_protocols TLSv1.2 TLSv1.3;" \
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
    else
        add_result "tls" "TLS 1.0" "PASS" "LOW" "TLS 1.0 disabled" "" "" "" "" ""
    fi

    local out11
    out11=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -tls1_1 2>/dev/null || true)
    if echo "$out11" | grep -qi "Protocol\s*:\s*TLSv1\.1\b"; then
        add_result "tls" "TLS 1.1" "FAIL" "HIGH" "TLS 1.1 enabled" \
            "TLS 1.1 is deprecated and vulnerable" \
            "Downgrade attacks, data decryption" \
            "Disable TLS 1.1: ssl_protocols TLSv1.2 TLSv1.3;" \
            "ssl_protocols TLSv1.2 TLSv1.3;" \
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
    else
        add_result "tls" "TLS 1.1" "PASS" "LOW" "TLS 1.1 disabled" "" "" "" "" ""
    fi

    local out12
    out12=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -tls1_2 2>/dev/null || true)
    if echo "$out12" | grep -qi "Protocol\s*:\s*TLSv1\.2\b"; then
        add_result "tls" "TLS 1.2" "PASS" "INFO" "TLS 1.2 enabled" \
            "TLS 1.2 is currently the minimum acceptable version" \
            "" "" "" "" ""
    else
        add_result "tls" "TLS 1.2" "FAIL" "HIGH" "TLS 1.2 disabled" \
            "TLS 1.2 provides necessary security for modern web" \
            "Weak encryption, incompatible clients" \
            "Enable TLS 1.2: ssl_protocols TLSv1.2 TLSv1.3;" \
            "ssl_protocols TLSv1.2 TLSv1.3;" \
            "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
    fi

    local out13
    out13=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -tls1_3 2>/dev/null || true)
    if echo "$out13" | grep -qi "Protocol\s*:\s*TLSv1\.3\b"; then
        add_result "tls" "TLS 1.3" "PASS" "INFO" "TLS 1.3 enabled" \
            "TLS 1.3 provides improved security and performance" \
            "" "" "" "" ""
    else
        add_result "tls" "TLS 1.3" "WARN" "MEDIUM" "TLS 1.3 disabled" \
            "TLS 1.3 removes legacy algorithms and improves handshake" \
            "Missed security/performance improvements" \
            "Enable TLS 1.3: ssl_protocols TLSv1.2 TLSv1.3;" \
            "ssl_protocols TLSv1.2 TLSv1.3;" \
            "https://www.rfc-editor.org/rfc/rfc8446.html"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  CIPHER SUITES
# ═══════════════════════════════════════════════════════════════════════════

get_cipher() {
    echo "$SSL_CONNECT_OUT" | grep -i "Cipher\s*:" | head -1 | sed 's/.*Cipher\s*:\s*//' | xargs
}

check_cipher_suites() {
    print_section "Cipher Suites" "🔑"

    local chosen_cipher
    chosen_cipher=$(get_cipher)

    if [[ -z "$chosen_cipher" ]] || [[ "$chosen_cipher" == "0000" ]]; then
        add_result "cipher" "Cipher Negotiation" "FAIL" "CRITICAL" \
            "No cipher negotiated" \
            "Server failed to negotiate a cipher suite" \
            "Connection failures, weak crypto" \
            "ECDHE-ECDSA-AES256-GCM-SHA384" \
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptography_Cheat_Sheet.html"
    else
        add_result "cipher" "Cipher Negotiation" "PASS" "INFO" "Negotiated: $chosen_cipher" "" "" "" "" ""
    fi

    local weak_pattern="NULL|EXPORT|DES|RC4|RC2|3DES|SHA1|MD5|anon|ADH|aNULL|eNULL"
    if [[ -n "$chosen_cipher" ]] && echo "$chosen_cipher" | grep -qiE "$weak_pattern"; then
        add_result "cipher" "Weak Cipher Detection" "FAIL" "HIGH" "Weak cipher negotiated" \
            "Server negotiated a weak or deprecated cipher suite" \
            "Traffic decryption, brute force attacks" \
            "Remove weak ciphers from configuration" \
            "!NULL !EXPORT !DES !RC4 !3DES" \
            "https://ssl-config.mozilla.org/"
    else
        add_result "cipher" "Weak Cipher Detection" "PASS" "LOW" "No weak ciphers" "" "" "" "" ""
    fi

    if [[ -n "$chosen_cipher" ]] && echo "$chosen_cipher" | grep -qiE "anon|ADH|aNULL"; then
        add_result "cipher" "Anonymous Cipher" "FAIL" "HIGH" "Anonymous authentication supported" \
            "Anonymous ciphers provide no authentication" \
            "Man-in-the-middle attacks" \
            "Disable anonymous cipher suites: !aNULL !eNULL" \
            "CipherString = DEFAULT@SECURITY=150" \
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptography_Cheat_Sheet.html"
    else
        add_result "cipher" "Anonymous Cipher" "PASS" "LOW" "No anonymous ciphers" "" "" "" "" ""
    fi

    if [[ -n "$chosen_cipher" ]] && echo "$chosen_cipher" | grep -qiE "ECDHE|DHE"; then
        add_result "cipher" "Forward Secrecy" "PASS" "MEDIUM" "Supported (ECDHE/DHE)" "" "" "" "" ""
    else
        add_result "cipher" "Forward Secrecy" "WARN" "MEDIUM" "Not clearly supported" \
            "Forward secrecy ensures session key independence" \
            "Historical session decryption if private key compromised" \
            "Enable ECDHE key exchange in cipher list" \
            "ECDHE-ECDSA-AES256-GCM-SHA384" \
            "https://en.wikipedia.org/wiki/Forward_secrecy"
    fi

    local out13
    out13=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -tls1_3 2>/dev/null || true)
    local cipher13
    cipher13=$(echo "$out13" | grep -i "Cipher\s*:" | head -1 | sed 's/.*Cipher\s*:\s*//' | xargs)
    if [[ -n "$cipher13" ]] && [[ "$cipher13" != "0000" ]]; then
        add_result "cipher" "TLS 1.3 Cipher" "PASS" "INFO" "Active: $cipher13" "" "" "" "" ""
    else
        add_result "cipher" "TLS 1.3 Cipher" "SKIP" "LOW" "TLS 1.3 not active" "" "" "" "" ""
    fi

    if [[ -n "$chosen_cipher" ]] && echo "$chosen_cipher" | grep -qi "GCM\|CHACHA20"; then
        add_result "cipher" "AEAD Cipher" "PASS" "MEDIUM" "AEAD in use" "" "" "" "" ""
    else
        add_result "cipher" "AEAD Cipher" "WARN" "MEDIUM" "No AEAD cipher negotiated" \
            "GCM/ChaCha20-Poly1305 provide authenticated encryption" \
            "Padding oracle attacks" \
            "Prefer AES-GCM or ChaCha20-Poly1305 ciphers" \
            "ECDHE-ECDSA-AES256-GCM-SHA384" \
            "https://cheatsheetseries.owasp.org/cheatsheets/Cryptography_Cheat_Sheet.html"
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  CERTIFICATE VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

get_cert_pem() {
    echo "$SSL_CONNECT_OUT" | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/' || true
}

check_certificate() {
    print_section "Certificate Validation" "📜"

    local cert_pem
    cert_pem=$(get_cert_pem)
    if [[ -z "$cert_pem" ]]; then
        add_result "certificate" "Certificate Retrieval" "FAIL" "CRITICAL" \
            "No certificate found" \
            "Cannot retrieve certificate from server" \
            "Audit incomplete" \
            "openssl s_client -connect $TARGET_HOST:$TARGET_PORT" \
            "https://www.openssl.org/docs/manmaster/man1/openssl-s_client.html"
        return 1
    fi
    add_result "certificate" "Certificate Retrieval" "PASS" "INFO" "Retrieved" "" "" "" "" ""

    local tmpcert
    tmpcert=$(mktemp)
    echo "$cert_pem" > "$tmpcert"
    TMP_CERT="$tmpcert"

    local cert_text
    cert_text=$(openssl x509 -in "$tmpcert" -noout -text 2>/dev/null || true)

    local subject issuer
    subject=$(openssl x509 -in "$tmpcert" -noout -subject 2>/dev/null | sed 's/subject=//' || true)
    issuer=$(openssl x509 -in "$tmpcert" -noout -issuer 2>/dev/null | sed 's/issuer=//' || true)
    add_result "certificate" "Subject DN" "PASS" "INFO" "$subject" "" "" "" "" ""
    add_result "certificate" "Issuer DN" "PASS" "INFO" "$issuer" "" "" "" "" ""
    add_result "certificate" "Serial Number" "PASS" "INFO" "$(openssl x509 -in "$tmpcert" -noout -serial 2>/dev/null | sed 's/serial=//')" "" "" "" "" ""

    local not_before not_after
    not_before=$(openssl x509 -in "$tmpcert" -noout -startdate 2>/dev/null | sed 's/notBefore=//' || true)
    not_after=$(openssl x509 -in "$tmpcert" -noout -enddate 2>/dev/null | sed 's/notAfter=//' || true)
    add_result "certificate" "Valid From" "PASS" "INFO" "$not_before" "" "" "" "" ""
    add_result "certificate" "Valid Until" "PASS" "INFO" "$not_after" "" "" "" "" ""

    local expiry_epoch now_epoch days_left
    expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || echo "0")
    now_epoch=$(date +%s)
    days_left=$(( (expiry_epoch - now_epoch) / 86400 ))

    if [[ "$expiry_epoch" -eq 0 ]]; then
        add_result "certificate" "Expiry Status" "FAIL" "HIGH" "Could not parse expiry" "" "" "" "" ""
    elif [[ "$days_left" -lt 0 ]]; then
        add_result "certificate" "Expiry Status" "FAIL" "CRITICAL" "EXPIRED (${days_left#-} days ago)" \
            "Expired certificates cause browser warnings and service disruption" \
            "Service downtime, user distrust, security alerts" \
            "Renew certificate immediately" \
            "certbot renew" \
            "https://letsencrypt.org/docs/free-ssl/"
    elif [[ "$days_left" -lt 7 ]]; then
        add_result "certificate" "Expiry Status" "WARN" "HIGH" "Expires in $days_left days (CRITICAL)" \
            "Certificate expiring within 7 days" \
            "Imminent service interruption" \
            "Renew certificate immediately" \
            "certbot renew" \
            "https://letsencrypt.org/docs/free-ssl/"
    elif [[ "$days_left" -lt 30 ]]; then
        add_result "certificate" "Expiry Status" "WARN" "MEDIUM" "Expires in $days_left days" \
            "Certificate nearing expiry" \
            "Service disruption if not renewed" \
            "Set up automatic renewal or renew soon" \
            "certbot renew --dry-run" \
            "https://letsencrypt.org/docs/free-ssl/"
    else
        add_result "certificate" "Expiry Status" "PASS" "INFO" "Valid for $days_left days" "" "" "" "" ""
    fi

    local chain_verify
    chain_verify=$(echo | timeout 10 openssl verify -CApath /etc/ssl/certs "$tmpcert" 2>&1 || true)
    if echo "$chain_verify" | grep -qiE "^${tmpcert}:\s*ok\b"; then
        add_result "certificate" "Certificate Chain" "PASS" "INFO" "Chain verified against system CAs" "" "" "" "" ""
    else
        add_result "certificate" "Certificate Chain" "WARN" "MEDIUM" "Chain verification incomplete" \
            "Incomplete chain causes warnings on some clients" \
            "Trust warnings, connection failures" \
            "Provide full certificate chain including intermediates" \
            "SSLCertificateChainFile /path/to/intermediate.pem" \
            "https://www.digitalocean.com/community/tutorials/openssl-essentials"
    fi

    local key_size
    key_size=$(echo "$cert_text" | grep -i "Public Key:" | grep -oP 'Public-Key:\s*\K[0-9]+' || echo "")
    if [[ -n "$key_size" ]]; then
        if [[ "$key_size" -ge 4096 ]]; then
            add_result "certificate" "Public Key Size" "PASS" "INFO" "${key_size} bits" "" "" "" "" ""
        elif [[ "$key_size" -ge 2048 ]]; then
            add_result "certificate" "Public Key Size" "PASS" "INFO" "${key_size} bits" "" "" "" "" ""
        else
            add_result "certificate" "Public Key Size" "FAIL" "HIGH" "${key_size} bits (too small)" \
                "Key sizes below 2048 bits are considered weak" \
                "Factoring attack, key compromise" \
                "Use 2048-bit minimum RSA or 256-bit ECC" \
                "openssl genrsa -out key.pem 4096" \
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptography_Cheat_Sheet.html"
        fi
    else
        add_result "certificate" "Public Key Size" "WARN" "MEDIUM" "Could not determine key size" "" "" "" "" ""
    fi

    local sig_alg
    sig_alg=$(echo "$cert_text" | grep -i "Signature Algorithm:" | head -1 | sed 's/.*Signature Algorithm:\s*//' || true)
    if [[ -n "$sig_alg" ]]; then
        if echo "$sig_alg" | grep -qiE "sha1|md5"; then
            add_result "certificate" "Signature Algorithm" "FAIL" "HIGH" "$sig_alg" \
                "SHA-1 and MD5 are cryptographically broken" \
                "Certificate forgery" \
                "Reissue with SHA-256 or stronger" \
                "sha256WithRSAEncryption" \
                "https://cheatsheetseries.owasp.org/cheatsheets/Cryptography_Cheat_Sheet.html"
        else
            add_result "certificate" "Signature Algorithm" "PASS" "INFO" "$sig_alg" "" "" "" "" ""
        fi
    else
        add_result "certificate" "Signature Algorithm" "SKIP" "LOW" "Could not determine" "" "" "" "" ""
    fi

    # SANs
    local sans
    sans=$(echo "$cert_text" | grep -A1 "Subject Alternative Name:" | tail -1 | sed 's/DNS://g' | tr ',' '\n' | sed 's/^[[:space:]]*//' | grep -v '^$' || true)
    if [[ -n "$sans" ]]; then
        local san_count
        san_count=$(echo "$sans" | wc -l)
        add_result "certificate" "Subject Alt Names" "PASS" "INFO" "${san_count} SAN(s)" "" "" "" "" ""

        if echo "$sans" | grep -qiE '\*\.|^\*$'; then
            add_result "certificate" "Wildcard Certificate" "WARN" "MEDIUM" "Wildcard cert detected" \
                "Wildcard certificates cover all subdomains" \
                "Broad blast radius if leaked" \
                "Use SAN entries for specific subdomains" \
                "DNS:example.com, DNS:www.example.com" \
                "https://cheatsheetseries.owasp.org/cheatsheets/Transport_Layer_Protection_Cheat_Sheet.html"
        else
            add_result "certificate" "Wildcard Certificate" "PASS" "LOW" "No wildcard SANs" "" "" "" "" ""
        fi
    else
        add_result "certificate" "Subject Alt Names" "FAIL" "HIGH" "No SANs found" \
            "Modern browsers require Subject Alternative Names" \
            "Certificate validation failures" \
            "Reissue with SAN extension" \
            "subjectAltName = DNS:example.com" \
            "https://certificate.revocationcheck.com/"
    fi

    rm -f "$tmpcert"
}

# ═══════════════════════════════════════════════════════════════════════════
#  CERTIFICATE CHAIN
# ═══════════════════════════════════════════════════════════════════════════

check_certificate_chain() {
    print_section "Certificate Chain" "⛓️"

    local cert_pem
    cert_pem=$(get_cert_pem)
    if [[ -z "$cert_pem" ]]; then
        add_result "chain" "Chain Retrieval" "FAIL" "HIGH" "No certificates received" \
            "Server did not provide any certificates" \
            "Connection failures" \
            "Verify SSL/TLS configuration on server" \
            "ssl_certificate /path/to/fullchain.pem;" \
            ""
        return
    fi

    local chain_count
    chain_count=$(echo "$cert_pem" | grep -c "BEGIN CERTIFICATE" || echo "0")
    add_result "chain" "Chain Length" "PASS" "INFO" "${chain_count} certificate(s)" "" "" "" "" ""

    if [[ "$chain_count" -ge 2 ]]; then
        add_result "chain" "Intermediate Certs" "PASS" "INFO" "Provided" "" "" "" "" ""
    else
        add_result "chain" "Intermediate Certs" "WARN" "HIGH" "No intermediate certificates provided" \
            "Chain with only leaf certificate may not validate on all platforms" \
            "Trust warnings on some browsers/devices" \
            "Provide full certificate chain including intermediates" \
            "SSLCertificateChainFile /path/to/intermediate.pem" \
            "https://www.digitalocean.com/community/tutorials/openssl-essentials"
    fi

    local leaf_order intermediate_order
    leaf_order=$(echo "$cert_pem" | grep -n "BEGIN CERTIFICATE" | head -1 | cut -d: -f1)
    intermediate_order=$(echo "$cert_pem" | grep -n "BEGIN CERTIFICATE" | tail -1 | cut -d: -f1)
    if [[ "$leaf_order" -lt "$intermediate_order" ]]; then
        add_result "chain" "Chain Order" "PASS" "INFO" "Correct order (leaf first)" "" "" "" "" ""
    else
        add_result "chain" "Chain Order" "WARN" "MEDIUM" "Potentially incorrect order" \
            "Some servers require certificates in specific order" \
            "Chain validation failures" \
            "Ensure leaf cert is first, then intermediates" \
            "SSLCertificateFile leaf.pem\nSSLCertificateChainFile intermediate.pem" \
            ""
    fi
}

# ═══════════════════════════════════════════════════════════════════════════
#  OCSP & HTTP SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════════════

check_ocsp_headers() {
    print_section "OCSP & HTTP Headers" "🛡️"

    local ocsp_out
    ocsp_out=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -status 2>/dev/null || true)
    if echo "$ocsp_out" | grep -qi "OCSP Response Data"; then
        add_result "headers" "OCSP Stapling" "PASS" "MEDIUM" "OCSP stapling active" "" "" "" "" ""
    else
        add_result "headers" "OCSP Stapling" "WARN" "MEDIUM" "OCSP stapling not detected" \
            "OCSP stapling improves privacy and performance" \
            "OCSP lookup delays, privacy leak" \
            "Enable OCSP stapling in server configuration" \
            "ssl_stapling on;" \
            "https://nginx.org/en/docs/http/ngx_http_ssl_module.html#ssl_stapling"
    fi

    if echo "$SSL_CONNECT_OUT" | grep -qi "Strict-Transport-Security"; then
        add_result "headers" "HSTS" "PASS" "HIGH" "HSTS header present" "" "" "" "" ""
    else
        local hsts_http
        hsts_http=$(curl -sI "https://$TARGET_HOST:$TARGET_PORT" 2>/dev/null | grep -i "Strict-Transport-Security" || true)
        if [[ -n "$hsts_http" ]]; then
            add_result "headers" "HSTS" "PASS" "HIGH" "HSTS present (via HTTP)" "" "" "" "" ""
        else
            add_result "headers" "HSTS" "FAIL" "HIGH" "HSTS not configured" \
                "HSTS forces HTTPS, preventing SSL stripping" \
                "Man-in-the-middle attacks, protocol downgrade" \
                "Add Strict-Transport-Security header" \
                "add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains\" always;" \
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Strict_Transport_Security_Cheat_Sheet.html"
        fi
    fi

    if curl -sI "https://$TARGET_HOST:$TARGET_PORT" 2>/dev/null | grep -qi "Public-Key-Pins"; then
        add_result "headers" "HPKP" "WARN" "MEDIUM" "HPKP is deprecated" \
            "HPKP is deprecated and can cause site lockouts" \
            "Site inaccessible if pins misconfigured" \
            "Remove HPKP; use Certificate Transparency instead" \
            "remove Public-Key-Pins header" \
            "https://developer.mozilla.org/en-US/docs/Web/HTTP/Public_Key_Pinning"
    else
        add_result "headers" "HPKP" "PASS" "LOW" "HPKP not used (recommended)" "" "" "" "" ""
    fi

    # ALPN
    local alpn_out
    alpn_out=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -alpn h2,http/1.1 2>/dev/null || true)
    if echo "$alpn_out" | grep -qi "ALPN.*h2\|ALPN.*http/1.1"; then
        local alpn_val
        alpn_val=$(echo "$alpn_out" | grep -oP "ALPN protocol:\s*\K\S+" || true)
        add_result "headers" "ALPN" "PASS" "INFO" "Negotiated: ${alpn_val:-h2/http-1.1}" "" "" "" "" ""
    else
        add_result "headers" "ALPN" "INFO" "LOW" "ALPN not negotiated or not applicable" "" "" "" "" ""
    fi

    # NPN (legacy)
    local npn_out
    npn_out=$(echo | timeout 10 openssl s_client -connect "$TARGET_HOST:$TARGET_PORT" -nextprotoneg h2,http/1.1 2>/dev/null || true)
    if echo "$npn_out" | grep -qi "Next protocol:"; then
        add_result "headers" "NPN" "INFO" "LOW" "NPN detected (legacy)" "" "" "" "" ""
    else
        add_result "headers" "NPN" "SKIP" "LOW" "NPN not detected" "" "" "" "" ""
    fi

    # Additional HTTP security headers
    local header_values
    header_values=$(curl -sI "https://$TARGET_HOST:$TARGET_PORT" 2>/dev/null || true)

    local headers=(
        "X-Content-Type-Options|nosniff|Prevents MIME-sniffing attacks"
        "X-Frame-Options|DENY|Prevents clickjacking"
        "X-XSS-Protection|1; mode=block|Enables XSS filter"
    )
    for hcheck in "${headers[@]}"; do
        IFS='|' read -r hname hexp hrisk <<< "$hcheck"
        if echo "$header_values" | grep -qi "^${hname}:"; then
            add_result "headers" "$hname" "PASS" "MEDIUM" "Header present" "" "" "" "" ""
        else
            add_result "headers" "$hname" "WARN" "MEDIUM" "Header not detected" \
                "$hname security header is missing" \
                "$hrisk" \
                "Add $hname header in server configuration" \
                "add_header $hname \"$hexp\" always;" \
                "https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html"
        fi
    done
}

# ═══════════════════════════════════════════════════════════════════════════
#  SCORING
# ═══════════════════════════════════════════════════════════════════════════

calculate_score() {
    local deductions=$((FAIL * 10 + WARN * 5))
    SCORE=$((100 - deductions))
    [[ $SCORE -lt 0 ]] && SCORE=0
    [[ $SCORE -gt 100 ]] && SCORE=100
}

# ═══════════════════════════════════════════════════════════════════════════
#  REPORT GENERATORS
# ═══════════════════════════════════════════════════════════════════════════

generate_json() {
    local arr=""
    local first=1
    for entry in "${RESULTS[@]}"; do
        [[ $first -eq 0 ]] && arr+=","
        arr+="$entry"
        first=0
    done

    cat > "$REPORT_JSON" <<EOF
{
  "tool": "nawasec-audit-ssl-tls",
  "version": "$VERSION",
  "framework_version": "$FRAMEWORK_VERSION",
  "timestamp": "$(date -Iseconds)",
  "target": {"host": "$TARGET_HOST", "port": "$TARGET_PORT"},
  "score": $SCORE,
  "summary": {"total": $TOTAL, "pass": $PASS, "warn": $WARN, "fail": $FAIL, "info": $INFO, "skip": $SKIP},
  "results": [$arr]
}
EOF
}

generate_html() {
    local sc_color="#10b981"
    [[ $SCORE -lt 70 ]] && sc_color="#ef4444"
    [[ $SCORE -lt 85 ]] && sc_color="#f59e0b"

    cat > "$REPORT_HTML" <<'HTMLHEAD'
<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>NawaSec Audit — SSL/TLS Security</title>
<style>
:root{--bg:#0f172a;--card:#1e293b;--border:#334155;--text:#f1f5f9;--muted:#94a3b8;--pass:#10b981;--warn:#f59e0b;--fail:#ef4444;--info:#3b82f6}
*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,sans-serif;background:var(--bg);color:var(--text);padding:2rem;max-width:1200px;margin:0 auto;line-height:1.6}
h1{font-size:1.5rem;font-weight:800}.sub{color:var(--muted);font-size:.85rem;margin-bottom:2rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(130px,1fr));gap:.8rem;margin-bottom:2rem}
.c{background:var(--card);border:1px solid var(--border);border-radius:12px;padding:1.2rem;text-align:center}
.c-val{font-size:1.8rem;font-weight:800}.c-lbl{font-size:.7rem;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:.2rem}
.section{font-size:1rem;font-weight:700;margin:2.5rem 0 .8rem;padding:.6rem 0;border-bottom:1px solid var(--border)}
table{width:100%;border-collapse:collapse;font-size:.82rem;margin-bottom:1.5rem}
th{text-align:left;padding:.5rem .7rem;background:var(--card);color:var(--muted);font-size:.7rem;text-transform:uppercase}
td{padding:.5rem .7rem;border-bottom:1px solid var(--border);vertical-align:top}
.badge{display:inline-block;padding:.12rem .45rem;border-radius:100px;font-size:.68rem;font-weight:600}
.b-pass{background:rgba(16,185,129,.12);color:var(--pass)}.b-warn{background:rgba(245,158,11,.12);color:var(--warn)}.b-fail{background:rgba(239,68,68,.12);color:var(--fail)}.b-info{background:rgba(59,130,246,.12);color:var(--info)}
.detail{color:var(--muted);font-size:.72rem;margin-top:.2rem}.detail b{color:var(--text)}
footer{text-align:center;padding:2rem 0;color:#334155;font-size:.72rem;border-top:1px solid var(--border);margin-top:2rem}
</style></head><body>
HTMLHEAD

    cat >> "$REPORT_HTML" <<EOF
<h1>🔒 NawaSec Audit — SSL/TLS</h1>
<p class="sub">${TARGET_HOST}:${TARGET_PORT} — $(hostname) — $(date)</p>
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
        local cat status name message explanation recommendation
        cat=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['category'])" 2>/dev/null || echo "unknown")
        [[ "$cat" != "$current_cat" ]] && [[ -n "$current_cat" ]] && echo "</tbody></table>" >> "$REPORT_HTML"
        [[ "$cat" != "$current_cat" ]] && current_cat="$cat" && echo "<div class='section'>${cat^^}</div><table><thead><tr><th>Check</th><th>Status</th><th>Severity</th><th>Message</th><th>Details</th></tr></thead><tbody>" >> "$REPORT_HTML"

        name=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['name'])" 2>/dev/null)
        status=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])" 2>/dev/null)
        message=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['message'])" 2>/dev/null)
        explanation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('explanation',''))" 2>/dev/null)
        recommendation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recommendation',''))" 2>/dev/null)

        local badge_class="b-info"
        case "$status" in
            PASS) badge_class="b-pass" ;;
            WARN) badge_class="b-warn" ;;
            FAIL) badge_class="b-fail" ;;
        esac

        local detail=""
        [[ -n "$explanation" ]] && detail+="<div class='detail'><b>Explanation:</b> $(echo "$explanation" | sed 's/</\\</g' | sed "s/'/\\'/g")</div>"
        [[ -n "$recommendation" ]] && detail+="<div class='detail'><b>Recommendation:</b> $(echo "$recommendation" | sed 's/</\\</g' | sed "s/'/\\'/g")</div>"

        echo "<tr><td><b>$name</b></td><td><span class='badge $badge_class'>$status</span></td><td>$status</td><td>$(echo "$message" | sed 's/</\\</g')</td><td>$detail</td></tr>" >> "$REPORT_HTML"
    done

    [[ -n "$current_cat" ]] && echo "</tbody></table>" >> "$REPORT_HTML"
    cat >> "$REPORT_HTML" <<'HTMLFOOTER'
<footer>NawaSec Audit v2.1.0 — Pure rule-based security audit</footer>
</body></html>
HTMLFOOTER
}

generate_txt() {
    {
        echo "════════════════════════════════════════════════════════════════"
        echo "  NawaSec Audit — SSL/TLS Security Report"
        echo "  Version: $VERSION | Framework: $FRAMEWORK_VERSION"
        echo "════════════════════════════════════════════════════════════════"
        echo "Target:    $TARGET_HOST:$TARGET_PORT"
        echo "Hostname:  $(hostname)"
        echo "Date:      $(date)"
        echo "Score:     $SCORE/100"
        echo ""
        echo "Summary:   PASS=$PASS | WARN=$WARN | FAIL=$FAIL | INFO=$INFO | SKIP=$SKIP | TOTAL=$TOTAL"
        echo "════════════════════════════════════════════════════════════════"

        local current_cat=""
        for entry in "${RESULTS[@]}"; do
            local cat name status severity message explanation recommendation
            cat=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['category'])" 2>/dev/null || echo "unknown")
            [[ "$cat" != "$current_cat" ]] && echo -e "\n▸ ${cat^^}" && current_cat="$cat"

            name=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['name'])" 2>/dev/null)
            status=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['status'])" 2>/dev/null)
            message=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin)['message'])" 2>/dev/null)
            explanation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('explanation',''))" 2>/dev/null)
            recommendation=$(echo "$entry" | python3 -c "import sys,json;print(json.load(sys.stdin).get('recommendation',''))" 2>/dev/null)

            echo "  [$status] $name ($severity): $message"
            if [[ -n "$explanation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
                echo "    Explanation: $explanation"
            fi
            if [[ -n "$recommendation" ]] && [[ "$status" =~ ^(WARN|FAIL)$ ]]; then
                echo "    Recommendation: $recommendation"
            fi
        done

        echo ""
        echo "════════════════════════════════════════════════════════════════"
        echo "  Reports:"
        echo "    HTML: $REPORT_HTML"
        echo "    JSON: $REPORT_JSON"
        echo "    TXT:  $REPORT_TXT"
        echo "════════════════════════════════════════════════════════════════"
    } > "$REPORT_TXT"
}

# ═══════════════════════════════════════════════════════════════════════════
#  MAIN
# ═══════════════════════════════════════════════════════════════════════════

main() {
    setup_colors

    echo -e "${C}${BOLD}${SCRIPT_NAME} v${VERSION}${N}"
    echo -e "${DIM}Framework v${FRAMEWORK_VERSION} | Target: ${TARGET_HOST}:${TARGET_PORT}${N}\n"

    audit_detection || true
    check_tls_versions || true
    check_cipher_suites || true
    check_certificate || true
    check_certificate_chain || true
    check_ocsp_headers || true

    calculate_score

    echo ""
    echo -e "${DIM}$(printf '═%.0s' {1..60})${N}"
    echo -e "${BOLD}  Summary${N}"
    echo -e "  Score:  ${SCORE}/100"
    echo -e "  Passed: ${G}${PASS}${N} | Warnings: ${Y}${WARN}${N} | Failed: ${R}${FAIL}${N}"
    echo -e "  Total:  ${TOTAL} | Info: ${B}${INFO}${N} | Skip: ${DIM}${SKIP}${N}"
    echo -e "${DIM}$(printf '═%.0s' {1..60})${N}"

    [[ "$OPT_HTML" -eq 1 ]] && generate_html
    [[ "$OPT_JSON" -eq 1 ]] && generate_json
    [[ "$OPT_TXT" -eq 1 ]] && generate_txt

    echo ""
    echo -e "Reports generated:"
    [[ "$OPT_HTML" -eq 1 ]] && echo -e "  ${G}HTML:${N} $REPORT_HTML"
    [[ "$OPT_JSON" -eq 1 ]] && echo -e "  ${Y}JSON:${N} $REPORT_JSON"
    [[ "$OPT_TXT" -eq 1 ]] && echo -e "  ${B}TXT:${N}  $REPORT_TXT"

    exit 0
}

main
