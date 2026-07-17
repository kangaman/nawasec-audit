# NawaSec Audit

[![Version](https://img.shields.io/badge/Framework-2.0.0-green.svg)]()
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Modules](https://img.shields.io/badge/Modules-4-purple.svg)]()
[![Checks](https://img.shields.io/badge/Checks-317-orange.svg)]()

**NawaSec Audit** is a modular, rule-based server security audit framework. It provides structured security checks across operating systems, web servers, and hosting panels without relying on AI or external services.

**All checks are read-only and deterministic.**

---

## Modules

| Module | Version | Checks | Description |
|--------|---------|--------|-------------|
| [**Linux**](linux/) | 2.1.0 | 158 | Core OS security: users, SSH, firewall, kernel, services, permissions, containers, cloud, logging |
| [**Apache**](apache/) | 2.1.0 | 68 | Apache HTTP Server: headers, modules, SSL/TLS, directories, access control, logging |
| [**Nginx**](nginx/) | 2.1.0 | 49 | Nginx Web Server: headers, SSL/TLS, server config, access control, logging, performance |
| [**cPanel**](cpanel/) | 2.1.0 | 42 | cPanel & WHM: security config, PHP, email, backup, firewall |

**Total: 317 security checks across 4 modules**

---

## Supported Platforms

| Module | Supported Platforms |
|--------|---------------------|
| **Linux** | Ubuntu, Debian, Kali, CentOS, RHEL, Rocky, Alma, Fedora, Amazon Linux, Oracle Linux |
| **Apache** | Apache HTTPD 2.4+, Ubuntu/Debian (apache2), RHEL/CentOS (httpd), cPanel EasyApache 4 |
| **Nginx** | Nginx 1.18+, Nginx Plus R20+, Ubuntu/Debian, RHEL/CentOS, Docker |
| **cPanel** | cPanel & WHM 110+, CentOS, AlmaLinux, Rocky Linux, CloudLinux |

---

## Quick Start

### Clone & Run

```bash
# Clone repository
git clone https://github.com/kangaman/nawasec-audit.git
cd nawasec-audit

# Make scripts executable
chmod +x linux/audit-linux.sh apache/audit-apache.sh nginx/audit-nginx.sh cpanel/audit-cpanel.sh

# Run audit
sudo ./linux/audit-linux.sh --all
sudo ./apache/audit-apache.sh --all
sudo ./nginx/audit-nginx.sh --all
sudo ./cpanel/audit-cpanel.sh --all
```

### One-liner

```bash
# Linux
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/linux/audit-linux.sh | sudo bash

# Apache
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/apache/audit-apache.sh | sudo bash

# Nginx
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/nginx/audit-nginx.sh | sudo bash

# cPanel
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/cpanel/audit-cpanel.sh | sudo bash
```

### Options (All Modules)

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

## Audit Philosophy

- **Read-only** — Tidak mengubah konfigurasi, tidak restart service, tidak modifikasi file
- **No AI** — Pure rule-based checks dengan hardcoded security baselines
- **Deterministic** — Hasil konsisten dan reproducible
- **Offline-capable** — Tidak memerlukan koneksi internet

---

## Output Formats

Setiap modul menghasilkan 3 format output:

| Format | Deskripsi |
|--------|-----------|
| **HTML** | Visual dashboard dengan dark theme, color-coded findings, severity badges, explanations, remediation |
| **JSON** | Machine-readable untuk CI/CD integration, automation, custom dashboards |
| **TXT** | Plain text untuk terminal viewing, log archival, email reports |

---

## Scoring System

| Score | Rating | Deskripsi |
|-------|--------|-----------|
| 90-100 | 🟢 Excellent | Minimal security issues |
| 80-89 | 🟡 Good | Few issues, mostly warnings |
| 70-79 | 🟠 Fair | Several issues need attention |
| 60-69 | 🔴 Poor | Significant security gaps |
| 0-59 | 🔴 Critical | Immediate action required |

**Formula:**
```
Score = (Pass × 100 + Info × 50) / Total Checks
```

---

## Setiap Temuan Memiliki

| Field | Deskripsi |
|-------|-----------|
| **Status** | PASS / WARN / FAIL / INFO / SKIP |
| **Severity** | CRITICAL / HIGH / MEDIUM / LOW |
| **Message** | Current value atau status |
| **Explanation** | Kenapa check ini penting |
| **Remediation** | Cara memperbaiki |

---

## Project Structure

```
nawasec-audit/
├── README.md                 # This file
├── LICENSE                   # MIT License
├── CHANGELOG.md              # Version history
│
├── linux/
│   ├── README.md             # Linux module documentation
│   └── audit-linux.sh        # Linux audit script (158 checks)
│
├── apache/
│   ├── README.md             # Apache module documentation
│   └── audit-apache.sh       # Apache audit script (68 checks)
│
├── nginx/
│   ├── README.md             # Nginx module documentation
│   └── audit-nginx.sh        # Nginx audit script (49 checks)
│
└── cpanel/
    ├── README.md             # cPanel module documentation
    └── audit-cpanel.sh       # cPanel audit script (42 checks)
```

---

## Roadmap

### Phase 1 — Done ✅
- [x] Linux audit module (158 checks, 15 categories)
- [x] Apache audit module (68 checks, 7 categories)
- [x] Nginx audit module (49 checks, 6 categories)
- [x] cPanel audit module (42 checks, 7 categories)
- [x] HTML/JSON/TXT output
- [x] Scoring system
- [x] Explanations & remediation

### Phase 2 — Planned 🔜
- [ ] Database module (MySQL, PostgreSQL, MariaDB)
- [ ] PHP-FPM security audit
- [ ] DNS configuration audit
- [ ] SSL/TLS certificate audit
- [ ] Docker security audit
- [ ] CIS Benchmark mapping
- [ ] Compliance presets (PCI DSS, UU PDP)

### Phase 3 — Future 🔮
- [ ] NawaSec for Windows Server
- [ ] NawaSec for macOS
- [ ] Web dashboard
- [ ] API integration

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

## Credits

Built and maintained by **Saeful Bahri** ([@kangaman](https://github.com/kangaman))

---

## Repository

[https://github.com/kangaman/nawasec-audit](https://github.com/kangaman/nawasec-audit)

**Framework Version: 2.0.0**
