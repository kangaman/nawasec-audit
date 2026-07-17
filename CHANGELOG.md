# Changelog

## [2.0.0] - 2026-07-17

### Added
- Restructured as **NawaSec Audit Framework** with modular architecture.
- New dedicated modules:
  - `linux-audit`
  - `apache-audit`
  - `nginx-audit`
  - `cpanel-audit`
- Standard project skeleton under `/usr/local/nawasec`.
- Consistent read-only, deterministic, rule-based audit behavior across all modules.
- Framework version centralized for future release automation.

### Changed
- Project renamed from **NawaHard** to **NawaSec Audit**.
- Removed Linux-audit-only limitation in favor of multi-module expansion.

---

## [1.0.0] - 2026-07-17

### Added
- Initial release of NawaHard.
- Linux-only server security audit checks.
- Read-only baseline checks for users, permissions, SSH, services, and logging.
