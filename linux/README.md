# NawaSec Linux Audit Module

**Version:** 1.0.0  
**Module:** `nawasec-audit/linux`  
**Repository:** https://github.com/kangaman/nawasec-audit

## Description

The Linux Audit Module performs comprehensive security audits of Linux-based VPS and server environments. It inspects system configuration, user accounts, network services, file permissions, kernel parameters, and package state to identify misconfigurations, unauthorized access paths, and common hardening gaps. This module is designed for sysadmins, security engineers, and auditors who need a reproducible, scriptable assessment of Linux server security posture.

## Supported Platforms

- Ubuntu / Debian (18.04 LTS and above)
- RHEL / CentOS / Rocky / Alma (7 and above)
- Amazon Linux 2 / 2023
- SUSE Linux Enterprise Server 12+
- Arch Linux
- Any system supporting `bash`, `systemctl`, `awk`, and standard `/proc` and `/sys` interfaces

## Usage

Run the module directly from the repository or import it as part of the core NawaSec runner.

### Command Examples

```bash
# Run a full Linux audit and print to stdout
nawasec-audit linux --full

# Save output to a specific format
nawasec-audit linux --full --output report.html --format html
nawasec-audit linux --full --output report.json --format json
nawasec-audit linux --full --output report.txt --format txt

# Audit specific categories only
nawasec-audit linux --category kernel
nawasec-audit linux --category users
nawasec-audit linux --category firewall

# Combine categories
nawasec-audit linux --category kernel --category users --output report.html --format html

# Run quietly with only the final score
nawasec-audit linux --full --quiet
```

## Audit Categories

| Category | Description |
|----------|-------------|
| `kernel` | Kernel version, sysctl hardening, module exposure, and runtime protection flags (e.g., ASLR, ptr_restrict). |
| `users` | User accounts, password aging, empty passwords, UID 0 accounts, sudo policy, and login defaults. |
| `ssh` | SSH daemon config, root login, PermitRootLogin, key-only auth, and cipher/MAC policy. |
| `firewall` | Active firewall rules, open ports, exposure of sensitive services, and default-drop posture. |
| `packages` | Installed package versions, out-of-date packages, and automatic update status. |
| `filesystem` | World-writable files, SUID/SGID binaries, `.ssh` permissions, and sensitive directory ACLs. |
| `logging` | Auditd, journald config, log rotation, remote logging, and tamper resistance. |
| `services` | Unnecessary services exposed, listeners, and internet-facing daemons. |
| `network` | IP forwarding, rp_filter settings, promiscuous interfaces, and routing state. |

## Output Formats

- **HTML** — Full color-coded report with severity badges and expandable evidence sections.
- **JSON** — Machine-readable result for CI/CD integration, dashboards, and further analysis.
- **TXT** — Plaintext summary suitable for tickets, emails, and quick terminal review.

## Scoring System

NawaSec uses a weighted scoring model:

- Each finding is assigned a severity: `Critical`, `High`, `Medium`, `Low`, or `Info`.
- Findings are scored and aggregated per category.
- The final score is expressed as a percentage of the maximum attainable hardening score for the platform.
- A score of **70% or higher** is considered a hardened baseline for production.
- Scores below 50% indicate significant risk that should be prioritized.

## Example Output

```
[INFO] NawaSec Linux Audit started — 2025-01-15 10:42:03 UTC
[SCAN] Categories: kernel, users, ssh, firewall, packages, filesystem, logging, services, network

[WARN] kernel — kernel.randomize_va_space is disabled (severity: Medium)
[PASS] kernel — Kernel version is up to date
[CRITICAL] users — UID 0 account found: backup (severity: Critical)
[PASS] users — No empty passwords detected

=== Linux Audit Summary ===
Overall Score: 82.4 / 100 (Grade: B+)
Critical: 0
High: 1
Medium: 3
Low: 12
Info: 28
Output: html:/root/reports/linux-audit-20250115.html
```

## Roadmap

- [ ] Add CIS Benchmark reference mappings per check
- [ ] Add CIS-CAT Pro integration fallback checks
- [ ] Add container-aware audits (Docker, Podman)
- [ ] Export SBOM-style inventory of installed packages
- [ ] Add compliance presets: PCI-DSS, HIPAA, SOC 2
- [ ] Add differential mode for change tracking

## License

MIT — see the main repository for details.

## Credits

This module is based on [NawaHard](https://github.com/kangaman/NawaHard) — the original Linux VPS security audit tool.
