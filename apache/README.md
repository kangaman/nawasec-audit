# NawaSec Audit — Apache Module

**Version:** 1.0.0  
**Module:** `nawasec-audit/apache`  
**Repository:** https://github.com/kangaman/nawasec-audit

---

## Deskripsi

Modul audit keamanan untuk Apache HTTP Server. Melakukan **68 pemeriksaan** keamanan di **7 kategori** secara komprehensif.

**Fitur Utama:**
- ✅ 68 security checks
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
| **Apache HTTPD** | 2.4+ | ✅ Full support |
| **Ubuntu/Debian** | apache2 package | ✅ Full support |
| **RHEL/CentOS** | httpd package | ✅ Full support |
| **cPanel/WHM** | EasyApache 4 | ✅ Full support |
| **Docker** | httpd image | ✅ Full support |

---

## Cara Penggunaan

### Quick Start

```bash
# Clone repository
git clone https://github.com/kangaman/nawasec-audit.git
cd nawasec-audit/apache

# Jalankan audit
sudo ./audit-apache.sh

# Generate semua format (HTML + JSON + TXT)
sudo ./audit-apache.sh --all

# Output ke direktori custom
sudo ./audit-apache.sh --all --output /path/to/reports

# Quiet mode (minimal output)
sudo ./audit-apache.sh --all --quiet
```

### One-liner

```bash
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/apache/audit-apache.sh | sudo bash
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

### 1. Apache Detection (4 checks)
- Apache binary detection
- Config file detection
- Version information
- Service status

### 2. Security Headers (8 checks)
- **ServerTokens** — Version information exposure
- **ServerSignature** — Error page signature
- **X-Frame-Options** — Clickjacking protection
- **X-Content-Type-Options** — MIME sniffing protection
- **X-XSS-Protection** — XSS filter (legacy)
- **Content-Security-Policy** — Code injection protection
- **Strict-Transport-Security** — HSTS for HTTPS
- **Referrer-Policy** — Referrer information control
- **Permissions-Policy** — Browser feature restrictions

### 3. Directory Security (5 checks)
- DocumentRoot permissions
- Directory listing (autoindex)
- AllowOverride settings
- FollowSymLinks configuration
- Sensitive file protection

### 4. Modules Security (6 checks)
- Dangerous modules detection (status, info, autoindex, userdir, proxy)
- Required modules (rewrite, ssl, headers)
- Module security implications

### 5. SSL/TLS Configuration (4 checks)
- SSLProtocol — Protocol versions (SSLv2/3, TLSv1.0/1.1/1.2/1.3)
- SSLCipherSuite — Cipher strength
- SSLHonorCipherOrder — Server cipher preference
- Certificate configuration

### 6. Access Control (3 checks)
- Require directives
- .htaccess files
- Authentication configuration

### 7. Logging (3 checks)
- Error log configuration
- Access log configuration
- Log level settings

### 8. Performance & Caching (3 checks)
- KeepAlive configuration
- MaxKeepAliveRequests
- Timeout settings

---

## Output Formats

### HTML Dashboard
- Visual, interactive report
- Color-coded findings (PASS/WARN/FAIL/INFO)
- Severity badges (CRITICAL/HIGH/MEDIUM/LOW)
- Explanations untuk setiap temuan
- Remediation guidance dengan contoh konfigurasi
- Responsive design
- Dark theme

### JSON Report
```json
{
  "tool": "nawasec-audit-apache",
  "version": "1.0.0",
  "score": 75,
  "summary": {
    "total": 68,
    "pass": 45,
    "warn": 15,
    "fail": 8
  },
  "results": [...]
}
```

### TXT Report
```
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — Apache Security Report                      ║
║  Version: 1.0.0                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Contoh Output

### Console Output
```
  ╔═══════════════════════════════════════════════════════╗
  ║  NawaSec Audit — Apache Security                     ║
  ║  v1.0.0                                              ║
  ╚═══════════════════════════════════════════════════════╝

🔍 Apache Detection
────────────────────────────────────────────────────────────
  ✓ Apache Binary — Found: /usr/sbin/httpd
  ✓ Config File — /etc/httpd/conf/httpd.conf
  i Version — 2.4.57
  ✓ Service Status — Running

🛡 Security Headers
────────────────────────────────────────────────────────────
  ✗ ServerTokens — Not set — defaults to Full
    i️ ServerTokens defaults to 'Full' which exposes Apache version, OS, and modules
    🔧 Add 'ServerTokens Prod' to /etc/httpd/conf/httpd.conf
  ✗ X-Frame-Options — Not configured
    i️ Without X-Frame-Options, site can be embedded in iframes (Clickjacking)
    🔧 Add 'Header always set X-Frame-Options DENY'

════════════════════════════════════════════════════════════
  AUDIT COMPLETE
════════════════════════════════════════════════════════════

  Security Score: 75/100

  ✓ Passed:   45
  ⚠ Warnings: 15
  ✗ Failed:   8
  i Info:      5
  Total:      68
```

---

## Setiap Temuan Memiliki

| Field | Deskripsi |
|-------|-----------|
| **Status** | PASS / WARN / FAIL / INFO / SKIP |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **Message** | Current value atau status |
| **Explanation** | Kenapa check ini penting |
| **Risk** | Apa risikonya |
| **Impact** | Dampak jika tidak diperbaiki |
| **Recommendation** | Cara memperbaiki |
| **Example** | Contoh konfigurasi |
| **Reference** | Link dokumentasi |

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

- [ ] Add HTTP/2 security checks
- [ ] Add mod_security detection
- [ ] Add virtual host analysis
- [ ] Add reverse proxy security checks
- [ ] Add CORS configuration audit
- [ ] Add rate limiting detection

---

## License

MIT — see the [main repository](https://github.com/kangaman/nawasec-audit) for details.
