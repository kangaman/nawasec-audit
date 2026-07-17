# NawaSec Audit — Linux Module

**Version:** 2.0.0  
**Module:** `nawasec-audit/linux`  
**Repository:** https://github.com/kangaman/nawasec-audit  
**Based on:** [NawaHard](https://github.com/kangaman/NawaHard)

---

## Deskripsi

Modul audit keamanan untuk Linux VPS dan server. Melakukan **158 pemeriksaan** keamanan di **15 kategori** secara komprehensif.

**Fitur Utama:**
- ✅ 158 security checks
- ✅ 15 kategori audit
- ✅ Penjelasan untuk setiap temuan (explanation)
- ✅ Panduan remediation untuk setiap temuan
- ✅ Security scoring (0-100)
- ✅ Output: HTML dashboard, JSON, TXT
- ✅ Multi-distro support
- ✅ Read-only (tidak mengubah konfigurasi)
- ✅ Pure rule-based (tanpa AI)

---

## Platform yang Didukung

| OS | Versi | Status |
|----|-------|--------|
| **Ubuntu** | 18.04, 20.04, 22.04, 24.04 | ✅ Full support |
| **Debian** | 10 (Buster), 11 (Bullseye), 12 (Bookworm) | ✅ Full support |
| **Kali Linux** | 2023+ | ✅ Full support |
| **Linux Mint** | 20+ | ✅ Full support |
| **Pop!_OS** | 20.04+ | ✅ Full support |
| **CentOS** | 7, 8, 9 | ✅ Full support |
| **RHEL** | 7, 8, 9 | ✅ Full support |
| **Rocky Linux** | 8, 9 | ✅ Full support |
| **AlmaLinux** | 8, 9 | ✅ Full support |
| **Fedora** | 35+ | ✅ Full support |
| **Amazon Linux** | 2, 2023 | ✅ Full support |
| **Oracle Linux** | 7, 8, 9 | ✅ Full support |
| **Arch Linux** | Rolling | ⚠️ Basic support |

---

## Cara Penggunaan

### Quick Start

```bash
# Clone repository
git clone https://github.com/kangaman/nawasec-audit.git
cd nawasec-audit/linux

# Jalankan audit
sudo ./audit-linux.sh

# Generate semua format (HTML + JSON + TXT)
sudo ./audit-linux.sh --all

# Output ke direktori custom
sudo ./audit-linux.sh --all --output /path/to/reports

# Quiet mode (minimal output)
sudo ./audit-linux.sh --all --quiet
```

### One-liner

```bash
curl -sL https://raw.githubusercontent.com/kangaman/nawasec-audit/master/linux/audit-linux.sh | sudo bash
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

## Kategori Audit (15 Kategori)

### 1. System Foundation (12 checks)
- OS version & EOL status
- Kernel version
- Boot loader password
- Package integrity
- ASLR configuration
- Core dump settings
- Time sync
- System info (hostname, CPU, memory, disk)

### 2. SSH Configuration (14 checks)
- Root login status
- Password authentication
- SSH port
- Empty passwords
- X11 forwarding
- Max auth tries
- Login grace time
- Client alive interval
- Access restrictions
- Host key permissions
- Max sessions
- Login banner

### 3. Firewall & Network (12 checks)
- Firewall detection (UFW/Firewalld/nftables)
- IP forwarding
- ICMP redirects
- Source routing
- SYN cookies
- Reverse path filtering
- Broadcast ICMP
- IPv6 redirects

### 4. Intrusion Prevention (3 checks)
- Fail2ban status
- CrowdSec status
- IPS general check

### 5. Authentication & Access (8 checks)
- Failed logins (24h)
- Sudo logging
- Password policy
- Account lockout
- UID 0 accounts
- Empty passwords
- SUID files

### 6. Kernel Hardening (20 checks)
- Reverse path filter
- ICMP redirects
- Source routing
- Log martians
- SYN cookies
- ASLR
- Kernel pointer restriction
- dmesg restriction
- ptrace scope
- Protected hardlinks/symlinks
- SUID core dump
- Magic SysRq

### 7. Service Management (6 checks)
- Running service count
- Dangerous services
- Docker status
- Container count

### 8. Open Ports (16 checks)
- Total listening ports
- Dangerous ports (21, 23, 25, 110, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900, 6379, 27017)

### 9. Resource Usage (5 checks)
- Disk usage
- Memory usage
- CPU usage
- Swap configuration
- Inode usage

### 10. System Updates (4 checks)
- Reboot requirement
- Pending updates
- Auto updates
- Security updates

### 11. File Permissions (4 checks)
- World-writable files in /etc
- /etc/shadow permissions
- /etc/passwd permissions
- SUID in /tmp

### 12. Container Security (5 checks)
- Docker socket permissions
- Root containers
- Privileged mode
- Content trust

### 13. Cloud Metadata (3 checks)
- Cloud provider detection
- IMDSv2 status
- Metadata access

### 14. Logging & Auditing (5 checks)
- Syslog daemon
- Audit daemon (auditd)
- Journal persistence
- Log rotation

### 15. Miscellaneous (5 checks)
- USB storage module
- File integrity monitoring
- Login banner

---

## Output Formats

### HTML Dashboard
- Visual, interactive report
- Color-coded findings (PASS/WARN/FAIL/INFO)
- Explanations untuk setiap temuan
- Remediation guidance
- Responsive design
- Dark theme

### JSON Report
- Machine-readable
- CI/CD integration
- Automation scripts
- Custom dashboards

### TXT Report
- Plain text
- Terminal viewing
- Log archival
- Email reports

---

## Contoh Output

### Console Output
```
🛡 NawaSec Audit - Linux v2.0.0

🖥 System Foundation
────────────────────────────────────────────────────────────
  i OS Version — Ubuntu 24.04.4 LTS
  ✓ OS Support — Ubuntu 24.04 — supported
  i Kernel — 6.8.0-124-generic
  ⚠ Boot Loader — No GRUB password
    i️ Tanpa GRUB password, akses fisik bisa bypass
    → Set GRUB password: grub2-setpassword

🔑 SSH Configuration
────────────────────────────────────────────────────────────
  ✗ Root Login — Enabled (yes)
    i️ Akses root langsung memudahkan attacker
    → Set 'PermitRootLogin no' in /etc/ssh/sshd_config

════════════════════════════════════════════════════════════
  AUDIT COMPLETE
════════════════════════════════════════════════════════════

  Security Score: 43/100

  ✓ Passed:   34
  ⚠ Warnings: 25
  ✗ Failed:   19
  i Info:      10
  Total:      89
```

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

## Roadmap

- [ ] CIS Benchmark reference mappings
- [ ] Container-aware audits (Docker, Podman)
- [ ] Compliance presets (PCI-DSS, UU PDP)
- [ ] Differential mode untuk change tracking
- [ ] SBOM-style package inventory
- [ ] Email notification support

---

## License

MIT — see the [main repository](https://github.com/kangaman/nawasec-audit) for details.

---

## Credits

Based on [NawaHard](https://github.com/kangaman/NawaHard) — the original Linux VPS security audit tool.
