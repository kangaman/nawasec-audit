# NawaSec Audit — DNS Module

**Version:** 2.1.0  
**Module:** `nawasec-audit/dns`  
**Repository:** https://github.com/kangaman/nawasec-audit

---

## Deskripsi

Modul audit keamanan untuk DNS Server. Memeriksa konfigurasi BIND/named, resolv.conf, dan pengaturan keamanan DNS.

## Cakupan Audit

### BIND/named (~30 checks)
- **Recursion**: recursion, allow-recursion
- **Zone Transfer**: allow-transfer, TSIG
- **Listen**: listen-on, listen-on-v6
- **Logging**: query logging
- **Permissions**: named.conf, zone files
- **DNSSEC**: dnssec-validation
- **Rate Limiting**: response rate limiting
- **Forwarders**: forward configuration

### resolv.conf (~8 checks)
- **Nameservers**: count, redundancy
- **Public DNS**: Google, Cloudflare, Quad9
- **Search Domain**: domain/search configuration

## Penggunaan

```bash
sudo ./audit-dns.sh [options]
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
sudo ./audit-dns.sh --all

# Audit dengan output ke direktori tertentu
sudo ./audit-dns.sh --html --output /var/reports

# Audit quiet mode
sudo ./audit-dns.sh --all --quiet
```

## Output

### Console Output
```
✓ Recursion — Disabled — Authoritative only
⚠ Allow-Recursion — Not restricted
  ℹ️  Any client can use this server for recursive queries
  ⚠️  Risk: DNS amplification attacks
  🔧 Add: allow-recursion { trusted-nets; };
     Example: allow-recursion { 127.0.0.1; 10.0.0.0/8; };
```

### JSON Output
```json
{
  "tool": "nawasec-audit-dns",
  "version": "2.1.0",
  "dns_type": "bind",
  "score": 62,
  "summary": {
    "total": 4,
    "pass": 2,
    "warn": 1,
    "fail": 0,
    "info": 1
  },
  "results": [...]
}
```

## Persyaratan

- Root access (sudo)
- BIND 9 atau systemd-resolved (opsional)
- Bash 4.0+

## Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.1.0 | 2026-07-17 | Initial release with BIND/resolv.conf audit |

## License

MIT — https://github.com/kangaman/nawasec-audit

---

Made with ❤️ by Saeful Bahri
