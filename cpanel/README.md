# NawaSec cPanel Audit Module

**Version:** 1.0.0  
**Module:** `nawasec-audit/cpanel`  
**Repository:** https://github.com/kangaman/nawasec-audit

## Description

The cPanel Audit Module inspects cPanel/WHM hosting environments for misconfigurations that increase breach risk, hosting abuse, or privilege escalation across shared-hosting estates. It covers WHM access controls, Apache configs managed by cPanel, user isolation, PHP handler exposure, email config, and backup routines.

## Supported Platforms

- cPanel / WHM 100+ on AlmaLinux, Rocky Linux, Ubuntu, and CloudLinux
- Standalone servers and hypervisor-managed shared-hosting nodes
- Environments with EasyApache 4 and native cPanel-provided services

## Usage

### Command Examples

```bash
# Run audit against a live WHM host
nawasec-audit cpanel --whm-host whm.example.com --whm-user root

# Run audit against a local config export directory
nawasec-audit cpanel --target /root/cpanel-backup/configs

# Limit to categories
nawasec-audit cpanel --whm-host whm.example.com --category accounts --category mail
nawasec-audit cpanel --target /root/cpanel-backup/configs --category php --category ssh

# Output reports
nawasec-audit cpanel --whm-host whm.example.com --output cpanel-report.html --format html
nawasec-audit cpanel --target /root/cpanel-backup/configs --output cpanel-report.json --format json

# Quiet mode
nawasec-audit cpanel --whm-host whm.example.com --quiet
```

## Audit Categories

| Category | Description |
|----------|-------------|
| `accounts` | Root/reseller privilege boundaries, password policies, suspended accounts, and access hosts. |
| `apache` | Apache configs inherited from cPanel/EasyApache, mod_security status, and listener exposure. |
| `php` | PHP handlers per account, `open_basedir` enforcement, `disable_functions`, and version exposure across shared hosting. |
| `mail` | Exim config, SMTP restrictions, SPF/DKIM/DMARC coverage, spamassassin tuning, and authenticated relay risks. |
| `ssh` | SSH daemon config on hosting nodes, root login controls, and user-level SSH access from WHM. |
| `backups` | Backup destinations, local backup exposure, and account-transport protections. |
| `security` | cPHulk config, two-factor authentication, brute-force protection, and process ownership expectations. |
| `permissions` | Home directory permissions, umask enforcement, and CGI/suexec boundaries. |

## Output Formats

- **HTML** — Panel-aware report with priority findings grouped by WHM area.
- **JSON** — Structured output suitable for integration with hosting management dashboards.
- **TXT** — Concise summary for ticket triage and internal hosting review.

## Scoring System

NawaSec applies an estate-risk weighting model for cPanel:

- Findings impacting tenant isolation or root privilege leakage are weighted more heavily.
- Mail relay and phishing-related risks increase score impact because of abuse liability.
- A score of **75% or higher** indicates a reasonably hardened shared-hosting node.
- Below 55%, the estate is considered high risk for account compromise and abuse.

## Example Output

```
[INFO] cPanel target: whm.example.com
[SCAN] Categories: accounts, apache, php, mail, ssh, backups, security, permissions

[CRITICAL] accounts — root access host not restricted to management IPs (severity: Critical)
[WARN] php — open_basedir not enforced for 4 cPanel accounts (severity: High)
[PASS] mail — SPF/DKIM/DMARC is enabled by default for new accounts
[INFO] security — cPHulk brute-force protection is active

=== cPanel Audit Summary ===
Overall Score: 68.2 / 100 (Grade: C+)
Critical: 1
High: 2
Medium: 6
Low: 14
Info: 33
Output: html:/root/reports/cpanel-audit-20250115.html
```

## Roadmap

- [ ] Add WHM API v1 integration for programmatic, real-time checks
- [ ] Add CloudLinux-specific cagefs and lve hardening checks
- [ ] Add per-cPanel-account isolation checks for multiple tenants
- [ ] Add checks for EasyApache profile rebuild safety and version drift
- [ ] Add support for WHMCS billing integration for recurring audits

## License

MIT — see the main repository for details.
