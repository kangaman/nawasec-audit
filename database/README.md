# NawaSec Audit — Database Module

**Version:** 2.1.0  
**Module:** `nawasec-audit/database`  
**Repository:** https://github.com/kangaman/nawasec-audit

---

## Deskripsi

Modul audit keamanan untuk Database Server (MySQL, MariaDB, PostgreSQL). Memeriksa konfigurasi keamanan, autentikasi, jaringan, logging, TLS/SSL, dan pengaturan berbahaya.

## Cakupan Audit

### MySQL/MariaDB (~35 checks)
- **Network**: bind-address, port, skip-networking
- **Authentication**: skip-grant-tables, old_passwords, authentication plugin
- **Privileges**: secure-file-priv, local-infile
- **Logging**: error log, general log, slow query log
- **TLS/SSL**: SSL configuration, require-secure-transport
- **Dangerous Settings**: symbolic-links, suspicious UDFs
- **Connection Limits**: max_connections, max_connect_errors, wait_timeout

### PostgreSQL (~25 checks)
- **Network**: listen_addresses, port
- **Authentication**: password_encryption, pg_hba.conf, trust authentication
- **Logging**: log_connections, log_disconnections, log_statement
- **TLS/SSL**: SSL enabled, minimum TLS version
- **Dangerous Settings**: data checksums

## Penggunaan

```bash
sudo ./audit-database.sh [options]
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

### Contoh

```bash
# Audit dengan semua format output
sudo ./audit-database.sh --all

# Audit dengan output ke direktori tertentu
sudo ./audit-database.sh --html --output /var/reports

# Audit quiet mode (hanya file output)
sudo ./audit-database.sh --all --quiet
```

## Output

### Console Output
```
✓ Bind Address — 127.0.0.1 — Localhost only
⚠ SSL/TLS — Not configured or disabled
  ℹ️  Without TLS, data transmitted in plaintext
  ⚠️  Risk: Credentials and data can be intercepted
  🔧 Enable SSL: require-secure-transport = ON
     Example: require-secure-transport = ON
```

### JSON Output
```json
{
  "tool": "nawasec-audit-database",
  "version": "2.1.0",
  "database_type": "postgresql",
  "database_version": "16.14",
  "score": 65,
  "summary": {
    "total": 13,
    "pass": 7,
    "warn": 3,
    "fail": 0,
    "info": 3
  },
  "results": [...]
}
```

## Persyaratan

- Root access (sudo)
- MySQL 5.7+/8.0+, MariaDB 10.3+, atau PostgreSQL 12+
- Bash 4.0+

## Scoring

| Status | Poin |
|--------|------|
| PASS | 100 |
| INFO | 50 |
| WARN | 0 |
| FAIL | 0 |

**Formula:** `Score = (PASS × 100 + INFO × 50) / TOTAL`

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.1.0 | 2026-07-17 | Initial release with full MySQL/MariaDB/PostgreSQL audit |

## License

MIT — https://github.com/kangaman/nawasec-audit

---

Made with ❤️ by Saeful Bahri
