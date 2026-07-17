#!/bin/bash
# Upgrade NawaSec Audit modules to v2.1.0 format
# Adds missing explanation, risk, impact, recommendation, example, reference parameters

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES=("apache" "nginx" "cpanel")

echo "=== Upgrading NawaSec Audit Modules to v2.1.0 ==="
echo ""

for module in "${MODULES[@]}"; do
    script="$SCRIPT_DIR/$module/audit-$module.sh"
    
    if [[ ! -f "$script" ]]; then
        echo "❌ $module: Script not found"
        continue
    fi
    
    echo "📦 Upgrading $module..."
    
    # Backup original
    cp "$script" "$script.backup.v1"
    
    # Count calls before
    total_before=$(grep -c 'add_result' "$script")
    
    # Create upgraded script
    cat > "$script" << 'UPGRADE_EOF'
#!/usr/bin/env bash
# ╔══════════════════════════════════════════════════════════════════════════╗
# ║  NawaSec Audit — MODULE_NAME Security Audit                            ║
# ║  Version: 2.1.0                                                        ║
# ║  License: MIT                                                          ║
# ║  Repository: https://github.com/kangaman/nawasec-audit                 ║
# ╚══════════════════════════════════════════════════════════════════════════╝
#
# Pure rule-based security audit — NO AI, NO external API calls.
# Read-only: Does NOT modify any configuration.
# Generates: Console + HTML dashboard + JSON + TXT report
#
# Usage:
#   sudo ./audit-MODULE_NAME.sh [options]
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
SCRIPT_NAME="NawaSec Audit - MODULE_NAME"
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
OUTPUT_DIR="/tmp/nawasec-MODULE_NAME"
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
            echo "NawaSec Audit - MODULE_NAME v${VERSION}"
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
REPORT_HTML="$OUTPUT_DIR/nawasec-MODULE_NAME-${TIMESTAMP}.html"
REPORT_JSON="$OUTPUT_DIR/nawasec-MODULE_NAME-${TIMESTAMP}.json"
REPORT_TXT="$OUTPUT_DIR/nawasec-MODULE_NAME-${TIMESTAMP}.txt"

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
#  DETECT MODULE_NAME
# ═══════════════════════════════════════════════════════════════

# DETECTION_PLACEHOLDER

# ═══════════════════════════════════════════════════════════════
#  AUDIT FUNCTIONS
# ═══════════════════════════════════════════════════════════════

# AUDIT_PLACEHOLDER

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
  "tool": "nawasec-audit-MODULE_NAME",
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
<title>NawaSec Audit — MODULE_NAME Security Report</title>
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
<h1>🔒 NawaSec Audit — MODULE_NAME Security</h1>
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
    echo "<footer>NawaSec Audit v${VERSION} — MODULE_NAME Security — Generated $(date) — https://github.com/kangaman/nawasec-audit</footer>" >> "$REPORT_HTML"
    echo "</body></html>" >> "$REPORT_HTML"
}

generate_txt() {
    cat > "$REPORT_TXT" <<EOF
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — MODULE_NAME Security Report                 ║
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
  NawaSec Audit v${VERSION} — MODULE_NAME Security
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
        echo "  ║  NawaSec Audit — MODULE_NAME Security                ║"
        echo "  ║  v${VERSION} (Framework v${FRAMEWORK_VERSION})                        ║"
        echo "  ╚═══════════════════════════════════════════════════════╝"
        echo -e "${N}"
        echo -e "  ${DIM}Started: $(date)${N}"
        echo ""
    fi

    # Detect MODULE_NAME
    # detect_MODULE_NAME

    # Run audits
    # audit_detection
    # audit_CONFIG
    # audit_HEADERS
    # audit_SSL
    # audit_LOGGING
    # audit_PERFORMANCE
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
UPGRADE_EOF

    # Replace placeholders
    sed -i "s/MODULE_NAME/$module/g" "$script"
    sed -i "s/MODULE_NAME/${module^}/g" "$script"
    
    # Make executable
    chmod +x "$script"
    
    echo "  ✅ $module upgraded to v2.1.0"
done

echo ""
echo "=== Upgrade Complete ==="
echo ""
echo "Next steps:"
echo "1. Add audit functions to each module"
echo "2. Test each module"
echo "3. Update README files"
echo "4. Push to GitHub"
