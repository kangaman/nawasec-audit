# NawaSec Apache Audit Module

**Version:** 1.0.0  
**Module:** `nawasec-audit/apache`  
**Repository:** https://github.com/kangaman/nawasec-audit

## Description

The Apache Audit Module inspects Apache HTTP Server (`httpd`) deployments for configuration weaknesses, dangerous module usage, TLS misconfigurations, and common web server attack surfaces. It evaluates both global configuration and virtual host definitions to produce a focused set of actionable findings for hardening production web infrastructure.

## Supported Platforms

- Apache 2.4.x on Linux and Unix-like systems
- Amazon Linux 2, RHEL, Ubuntu, Debian, and CentOS with Apache from OS packages
- Apache installed from source, with configs under `/etc/httpd` or `/etc/apache2`

## Usage

### Command Examples

```bash
# Scan local Apache instance
nawasec-audit apache --target /etc/apache2

# Scan remote Apache via provided config archive
nawasec-audit apache --target /tmp/apache-config-backup.tar.gz
nawasec-audit apache --target /path/to/conf-directory

# Export reports
nawasec-audit apache --target /etc/httpd --output apache-report.html --format html
nawasec-audit apache --target /etc/apache2 --output apache-report.json --format json

# Limit to specific categories
nawasec-audit apache --target /etc/apache2 --category tls --category headers

# Scan a single vhost config
nawasec-audit apache --target /etc/apache2/sites-available/000-default.conf --category modules
```

## Audit Categories

| Category | Description |
|----------|-------------|
| `modules` | Loaded modules, dangerous modules enabled, and unnecessary module exposure. |
| `tls` | TLS protocol versions, cipher suites, certificate validity, HSTS, and OCSP stapling. |
| `headers` | Security headers: `X-Frame-Options`, `Content-Security-Policy`, `Referrer-Policy`, `X-XSS-Protection`, `Server` header disclosure. |
| `configuration` | Server tokens, directory listing, trace enabled, FollowSymLinks, `.htaccess` override behavior. |
| `logging` | Access and error log configuration, log rotation, and request ID exposure. |
| `vhosts` | Missing vhost defaults, host header ambiguity, and SNI coverage. |
| `authentication` | Basic auth usage, `.htpasswd` protections, and authorization rule strength. |
| `performance` | KeepAlive, timeout hardening, and request size limits relevant to DoS resilience. |

## Output Formats

- **HTML** — Interactive report with per-vhost findings and evidence block.
- **JSON** — Structured output with category, severity, file, and directive references.
- **TXT** — Plain summary with remediation snippets for each finding.

## Scoring System

NawaSec weights Apache findings by internet exposure and exploitability:

- Findings that expose response headers or TLS behavior to external clients increase risk faster than local-only configuration issues.
- Scores reflect the hardening gap relative to recommended Apache production baselines.
- A score of **80% or higher** is considered internet-facing hardened.
- Scores below 60% typically indicate configs that should not be exposed without remediation.

## Example Output

```
[INFO] Apache config loaded: /etc/apache2/sites-available/000-default.conf
[SCAN] Categories: modules, tls, headers, configuration, logging, vhosts

[CRITICAL] tls — SSLProtocol allows TLSv1 and TLSv1.1 (severity: Critical)
[WARN] headers — X-Frame-Options not set for vhost example.com (severity: Medium)
[PASS] headers — Strict-Transport-Security enabled with max-age=31536000
[INFO] configuration — ServerTokens set to 'Prod'

=== Apache Audit Summary ===
Overall Score: 64.7 / 100 (Grade: C)
Critical: 1
High: 2
Medium: 4
Low: 3
Info: 11
Output: html:/root/reports/apache-audit-20250115.html
```

## Roadmap

- [ ] Add checks for Apache 2.2 legacy config patterns
- [ ] Add mod_evasive / mod_reqtimeout DoS hardening validation
- [ ] Add checks for reverse proxy security and upstream trust bounds
- [ ] Add .htaccess override auditing for shared hosting patterns

## License

MIT — see the main repository for details.
