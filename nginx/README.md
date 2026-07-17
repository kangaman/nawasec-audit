# NawaSec Audit — Nginx Module

**Version:** 2.1.0  
**Module:** `nawasec-audit/nginx`  
**Repository:** https://github.com/kangaman/nawasec-audit

---

## Deskripsi

Modul audit keamanan untuk Nginx Web Server. Melakukan **49 pemeriksaan** keamanan di **6 kategori** secara komprehensif.

**Fitur Utama:**
- ✅ 49 security checks
- ✅ 6 kategori audit
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
| **Nginx OSS** | 1.18+ | ✅ Full support |
| **Nginx Plus** | R20+ | ✅ Full support |
| **Ubuntu/Debian** | nginx package | ✅ Full support |
| **RHEL/CentOS** | nginx package | ✅ Full support |
| **Docker** | nginx image | ✅ Full support |

---

## Cara Penggunaan

### Quick Start

```bash
# Clone repository
git clone https://github.com/kangaman/nawasec-audit.git
cd nawasec-audit/nginx

# Jalankan audit
sudo ./audit-nginx.sh

# Generate semua format (HTML + JSON + TXT)
sudo ./audit-nginx.sh --all

# Output ke direktori custom
sudo ./audit-nginx.sh --all --output /path/to/reports

# Quiet mode (minimal output)
sudo ./audit-nginx.sh --all --quiet
```

### One-liner

```bash
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/nginx/audit-nginx.sh | sudo bash
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

## Kategori Audit (6 Kategori)

### 1. Nginx Detection (4 checks)
- Nginx binary detection
- Config file detection
- Version information
- Service status

### 2. Security Headers (8 checks)
- **server_tokens** — Version information exposure
- **X-Frame-Options** — Clickjacking protection
- **X-Content-Type-Options** — MIME sniffing protection
- **Content-Security-Policy** — Code injection protection
- **Strict-Transport-Security** — HSTS for HTTPS
- **Referrer-Policy** — Referrer information control
- **Permissions-Policy** — Browser feature restrictions

### 3. SSL/TLS Configuration (4 checks)
- ssl_protocols — Protocol versions
- ssl_prefer_server_ciphers — Server cipher preference
- ssl_ciphers — Cipher strength
- ssl_stapling — OCSP stapling

### 4. Server Configuration (4 checks)
- autoindex — Directory listing
- client_max_body_size — Upload limit
- server_names_hash_bucket_size
- HTTP methods restriction (limit_except)

### 5. Access Control (3 checks)
- Default server (catch-all)
- Sensitive file protection (.env, .git, .bak)
- Access restrictions

### 6. Logging (3 checks)
- Error log configuration
- Access log configuration
- Log format

### 7. Performance & Caching (3 checks)
- gzip compression
- keepalive_timeout
- worker_connections

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
  "tool": "nawasec-audit-nginx",
  "version": "1.0.0",
  "score": 82,
  "summary": {
    "total": 49,
    "pass": 35,
    "warn": 10,
    "fail": 4
  },
  "results": [...]
}
```

### TXT Report
```
╔══════════════════════════════════════════════════════════════╗
║  NawaSec Audit — Nginx Security Report                       ║
║  Version: 1.0.0                                              ║
╚══════════════════════════════════════════════════════════════╝
```

---

## Contoh Output

### Console Output
```
  ╔═══════════════════════════════════════════════════════╗
  ║  NawaSec Audit — Nginx Security                      ║
  ║  v1.0.0                                              ║
  ╚═══════════════════════════════════════════════════════╝

🔍 Nginx Detection
────────────────────────────────────────────────────────────
  ✓ Nginx Binary — Found: nginx
  ✓ Config File — /etc/nginx/nginx.conf
  i Version — 1.24.0
  ✓ Service Status — Running

🛡 Security Headers
────────────────────────────────────────────────────────────
  ✗ server_tokens — Not set or On — version exposed
    i️ Exposing Nginx version helps attackers find known vulnerabilities
    🔧 Add 'server_tokens off;' to http block
  ✗ X-Frame-Options — Not configured
    i️ Without X-Frame-Options, site can be embedded in iframes (Clickjacking)
    🔧 Add 'add_header X-Frame-Options DENY;'

🔒 SSL/TLS Configuration
────────────────────────────────────────────────────────────
  ✓ ssl_protocols — Secure protocols only
  ⚠ ssl_prefer_server_ciphers — Not set or off
    i️ Server should control cipher order
    🔧 Set 'ssl_prefer_server_ciphers on;'

════════════════════════════════════════════════════════════
  AUDIT COMPLETE
════════════════════════════════════════════════════════════

  Security Score: 82/100

  ✓ Passed:   35
  ⚠ Warnings: 10
  ✗ Failed:   4
  i Info:      3
  Total:      49
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
| **Example** | Contoh konfigurasi |

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

- [ ] Add HTTP/2 and HTTP/3 security checks
- [ ] Add reverse proxy security audit
- [ ] Add load balancer configuration checks
- [ ] Add rate limiting detection
- [ ] Add CORS configuration audit
- [ ] Add WAF (ModSecurity for Nginx) detection

---

## License

MIT — see the [main repository](https://github.com/kangaman/nawasec-audit) for details.
