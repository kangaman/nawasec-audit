# NawaSec Audit — SSL/TLS Module

**Version:** 2.1.0  
**Module:** `nawasec-audit/ssl-tls`  
**Repository:** https://github.com/kangaman/nawasec-audit  
**Based on:** [NawaHard](https://github.com/kangaman/NawaHard)

---

## Deskripsi

Modul audit keamanan SSL/TLS untuk server lokal maupun remote. Melakukan **45 pemeriksaan** keamanan SSL/TLS secara komprehensif.

**Fitur Utama:**
- ✅ TLS version checks (1.0, 1.1, 1.2, 1.3)
- ✅ Cipher suite analysis
- ✅ Certificate validation (expiry, chain, SANs, wildcard)
- ✅ OCSP stapling verification
- ✅ HSTS header check
- ✅ HPKP deprecated usage detection
- ✅ ALPN/NPN protocol negotiation
- ✅ Key size validation
- ✅ Signature algorithm check
- ✅ Security headers audit
- ✅ Remote host scanning via `--host`
- ✅ Output: HTML dashboard, JSON, TXT
- ✅ Security scoring (0-100)

---

## Platform yang Didukung

| OS | Dukungan |
|----|----------|
| Ubuntu / Debian | ✅ Full |
| CentOS / RHEL / Rocky / AlmaLinux | ✅ Full |
| Fedora / Amazon Linux | ✅ Full |
| Arch Linux | ✅ Basic |

---

## Prasyarat

- `openssl` (recommendasi: 1.1.1+)
- `curl`
- `bash` 4.0+
- Akses jaringan ke target (`--host` mode)

---

## Cara Penggunaan

```bash
# Clone repository
git clone https://github.com/kangaman/nawasec-audit.git
cd nawasec-audit/ssl-tls

# Audit local server (localhost:443)
sudo ./audit-ssl.sh

# Audit remote host
sudo ./audit-ssl.sh --host example.com:443

# Audit specific port
sudo ./audit-ssl.sh --host 10.0.0.1:8443

# Generate all formats
sudo ./audit-ssl.sh --all

# Quiet mode
sudo ./audit-ssl.sh --host example.com:443 --quiet
```

---

## Pilihan

| Opsi | Deskripsi |
|------|-----------|
| `--host HOST:PORT` | Host remote untuk scan |
| `--html` | Buat laporan HTML (default) |
| `--json` | Buat laporan JSON |
| `--txt` | Buat laporan TXT |
| `--all` | Buat semua format |
| `--quiet` | Output minimal |
| `--no-color` | Nonaktifkan warna |
| `--output DIR` | Direktori output kustom |
| `--help` | Bantuan |

---

## Kategori Pemeriksaan

| # | Kategori | Pemeriksaan |
|---|----------|-------------|
| 1 | Deteksi | OpenSSL, curl, target, tipe sertifikat |
| 2 | TLS Versions | TLS 1.0, 1.1, 1.2, 1.3 support |
| 3 | Cipher Suites | Weak cipher, anonymous, forward secrecy, AEAD |
| 4 | Sertifikat | Validity, expiry, chain, signature, key size |
| 5 | SANs | Subject Alt Names, wildcard, hostname match |
| 6 | Chain | Chain length, intermediate certs, order |
| 7 | Headers | OCSP, HSTS, HPKP, ALPN, HTTP security headers |

---

## Output

### Console
Menampilkan semua pemeriksaan dengan detail untuk WARN/FAIL:
- Explanation
- Risk
- Recommendation
- Example

### HTML
Dashboard interaktif dengan score, ringkasan, dan detail setiap pemeriksaan.

### JSON
Semua field hasil audit untuk integrasi sistem.

### TXT
Ringkasan teks untuk dokumentasi.

---

## Scoring

- FAIL: -10 points
- WARN: -5 points
- Minimum score: 0

---

## Keamanan

- **Pure bash** — tanpa AI, tanpa eksternal API
- **Read-only** — tidak memodifikasi konfigurasi apapun
- **Argumen aman** — tidak menyimpan kredensial

---

## Kontribusi

Buka issue atau pull request di: https://github.com/kangaman/nawasec-audit

---

## License

MIT
