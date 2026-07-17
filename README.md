# NawaSec Audit

# NawaSec Audit

**NawaSec Audit** is a modular, rule-based server security audit framework for Linux environments. It provides structured checks across operating systems, web servers, and hosting panels without relying on AI or external services. All checks are read-only and deterministic.

## Modules

NawaSec Audit separates concerns into focused modules so you can audit only what you need.

- **Linux** — Core operating system security checks including users, permissions, SSH, services, firewalls, logging, and kernel hardening.
- **Apache** — Web server configuration checks for headers, modules, TLS settings, access control, and hardening.
- **Nginx** — Web server configuration checks for headers, modules, TLS settings, access control, and hardening.
- **cPanel** — Hosting control panel checks covering WHM access, Apache/Nginx integration, PHP settings, and user account hygiene.

## Supported Platforms

| Component   | Supported Platforms                                    |
|-------------|--------------------------------------------------------|
| Linux       | Ubuntu, Debian, RHEL/CentOS, AlmaLinux, Rocky Linux    |
| Apache      | Apache HTTPD 2.4+                                      |
| Nginx       | Nginx 1.18+                                            |
| cPanel      | cPanel / WHM, CentOS, AlmaLinux, Rocky Linux           |

## Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/kangaman/nawasec-audit.git
   cd nawasec-audit
   ```

2. Make scripts executable:
   ```bash
   chmod +x *.sh
   ```

3. Run a module audit:
   ```bash
   # Linux audit
   ./modules/linux-audit.sh

   # Apache audit
   ./modules/apache-audit.sh

   # Nginx audit
   ./modules/nginx-audit.sh

   # cPanel audit
   ./modules/cpanel-audit.sh
   ```

## Audit Philosophy

NawaSec Audit is designed around these principles:

- **Read-only:** All checks are non-invasive. No files are modified, no services restarted, and no configurations changed during audit execution.
- **No AI:** The framework uses pure rule-based checks and hardcoded security baselines.
- **Deterministic output:** Results are consistent and reproducible across environments.
- **Offline-capable:** Audits do not require external connectivity unless explicitly enabled.

## Scoring System

Each finding is evaluated and scored to help prioritize remediation:

| Score | Severity     | Description                                        |
|-------|--------------|----------------------------------------------------|
| 0-4   | Low          | Minor deviation from best practice                 |
| 5-7   | Medium       | Notable risk; should be addressed in short term    |
| 8-9   | High         | Significant risk; requires attention               |
| 10    | Critical     | Immediate risk; should be treated as an emergency  |

Framework version: **2.0.0**

## Roadmap

### Phase 1 — Done
- Modular audit framework with Linux, Apache, Nginx, and cPanel modules.
- Read-only, rule-based checks with deterministic scoring.
- Standard workspace: `/usr/local/nawasec` with modular output segregation.

### Phase 2 — Planned
- Extended web server modules: OpenLiteSpeed, LiteSpeed Enterprise.
- Database module: MySQL, PostgreSQL, and MariaDB.
- Container module: Docker and Podman security baselines.
- Compliance mapping: CIS Benchmarks, PCI DSS, and HIPAA references.
- Report export: HTML and JSON report generation.
- Diff mode: Compare current audit results against previous baselines.

## Credits

Built and maintained by **Saeful Bahri** ([@kangaman](https://github.com/kangaman))

## Repository

[https://github.com/kangaman/nawasec-audit](https://github.com/kangaman/nawasec-audit)

Version: **2.0.0**
