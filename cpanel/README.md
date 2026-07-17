# NawaSec Audit — cPanel Module

**Version:** 2.1.0  
**Module:** `nawasec-audit/cpanel`  
**Repository:** https://github.com/kangaman/nawasec-audit

---

## Deskripsi

Modul audit keamanan untuk cPanel & WHM. Melakukan **42 pemeriksaan** keamanan di **7 kategori** secara komprehensif.

**Fitur Utama:**
- ✅ 42 security checks
- ✅ 7 kategori audit
- ✅ Penjelasan untuk setiap temuan (explanation)
- ✅ Panduan remediation untuk setiap temuan
- ✅ Severity rating (CRITICAL/HIGH/MEDIUM/LOW)
- ✅ Security scoring (0-100)
- ✅ Output: HTML dashboard, JSON, TXT
- ✅ Read-only (tidak mengubah konfigurasi)
- ✅ Pure rule-based (tanpa AI)

---

## Platform yang Didukung

| Platform | Versi | Status |
|----------|-------|--------|
| **cPanel & WHM** | 110+ | ✅ Full support |
| **CentOS** | 7, 8, 9 | ✅ Full support |
| **AlmaLinux** | 8, 9 | ✅ Full support |
| **Rocky Linux** | 8, 9 | ✅ Full support |
| **CloudLinux** | 8, 9 | ✅ Full support |
| **Ubuntu** | 20.04+ (limited) | ⚠️ Basic support |

---

## Cara Penggunaan

### Quick Start

```bash
# Clone repository
git clone https://github.com/kangaman/nawasec-audit.git
cd nawasec-audit/cpanel

# Jalankan audit
sudo ./audit-cpanel.sh

# Generate semua format (HTML + JSON + TXT)
sudo ./audit-cpanel.sh --all

# Output ke direktori custom
sudo ./audit-cpanel.sh --all --output /path/to/reports

# Quiet mode (minimal output)
sudo ./audit-cpanel.sh --all --quiet
```

### One-liner

```bash
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/cpanel/audit-cpanel.sh | sudo bash
```

### Options

| Option | Deskripsi |
|--------|-----------|
| `--html` | Generate HTML dashboard (default) |
| `--json` | Generate JSON report |
| `--txt` | Generate TXT report |
| `--all` | Generate semua format |
| `--quiet` | Minimal console output |
| `--no-color` | Disable colors |
| `--output DIR` | Custom output directory |
| `--help` | Show help |

---

## Kategori Audit (7 Kategori)

### 1. cPanel Detection (4 checks)
- cPanel installation detection
- cPanel version
- cpsrvd service status
- WHM port (2087) status

### 2. WHM Security (3 checks)
- API tokens configuration
- Require SSL setting
- Referrer security
- Max emails per hour

### 3. Security Configuration (4 checks)
- cPHulk Brute Force Protection
- SSH Password Authentication
- Default Shell
- Compiler Access (gcc)

### 4. PHP Configuration (4 checks)
- PHP versions installed
- Old PHP detection (EOL versions)
- disable_functions configuration
- expose_php setting
- display_errors setting

### 5. Email Security (3 checks)
- SPF records
- DKIM keys
- SMTP restrictions

### 6. Backup Configuration (2 checks)
- Backup enabled status
- Backup retention settings

### 7. Firewall (2 checks)
- ConfigServer Firewall (CSF) status
- ModSecurity detection

---

## Output Formats

### HTML Dashboard
- Visual, interactive report
- Color-coded findings (PASS/WARN/FAIL/INFO)
- Severity badges (CRITICAL/HIGH/MEDIUM/LOW)
- Explanations untuk setiap temuan
- Remediation guidance
- Responsive design
- Dark theme

### JSON Report
```json
{
  "tool": "nawasec-audit-cpanel",
  "version": "1.0.0",
  "score": 68,
  "summary": {
    "total": 42,
    "pass": 25,
    "warn": 12,
    "fail": 5
  },
  "results": [...]
}
```

### TXT Report
```
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — cPanel Security Report                      ║
║  Version: 1.0.0                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Contoh Output

### Console Output
```
  ╔═══════════════════════════════════════════════════════╗
  ║  NawaSec Audit — cPanel Security                    ║
  ║  v1.0.0                                              ║
  ╚═══════════════════════════════════════════════════════╝

🔍 cPanel Detection
────────────────────────────────────────────────────────────
  ✓ cPanel — Found at /usr/local/cpanel
  i cPanel Version — 110.0.12
  ✓ cpsrvd — Running
  ✓ WHM Port — 2087 open

🛡 WHM Security
────────────────────────────────────────────────────────────
  ✓ Require SSL — Enabled — WHM requires HTTPS
  ⚠ Referrer Security — Disabled
    i️ Blank referrer not blocked
    🔧 Enable in WHM: Tweak Settings

🔐 Security Configuration
────────────────────────────────────────────────────────────
  ✓ cPHulk — Enabled — brute force protection active
  ⚠ SSH Password Auth — Enabled
    i️ SSH password authentication allows brute force attacks
    🔧 Disable and use SSH keys

════════════════════════════════════════════════════════════
  AUDIT COMPLETE
════════════════════════════════════════════════════════════

  Security Score: 68/100

  ✓ Passed:   25
  ⚠ Warnings: 12
  ✗ Failed:   5
  i Info:      3
  Total:      42
```

---

## Setiap Temuan Memiliki

| Field | Deskripsi |
|-------|-----------|
| **Status** | PASS / WARN / FAIL / INFO / SKIP |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **Message** | Current value atau status |
| **Explanation** | Kenapa check ini penting |
| **Recommendation** | Cara memperbaiki |

---

## Scoring System

| Score | Rating | Deskripsi |
|-------|--------|-----------|
| 90-100 | 🟢 Excellent | Minimal security issues |
| 80-89 | 🟡 Good | Few issues, mostly warnings |
| 70-79 | 🟠 Fair | Several issues need attention |
| 60-69 | 🔴 Poor | Significant security gaps |
| 0-59 | 🔴 Critical | Immediate action required |

---

## Roadmap

- [ ] Add Two-Factor Authentication (2FA) check
- [ ] Add SSL certificate expiry check
- [ ] Add disk quota analysis
- [ ] Add user account audit
- [ ] Add addon domain security
- [ ] Add database user permissions audit

---

## License

MIT — see the [main repository](https://github.com/kangaman/nawasec-audit) for details.
