# NawaSec Audit — Docker Security Audit

Professional, rule-based Docker security audit module for the NawaSec Audit Framework.

- **Version:** 2.1.0
- **Framework:** 2.0.0
- **License:** MIT
- **Repository:** https://github.com/kangaman/nawasec-audit

## What it does

Audits Docker host and runtime configuration from a read-only, rule-based perspective. It evaluates daemon hardening, container privileges, image hygiene, network exposure, and control-plane security. No AI, no external calls, no system modifications.

## Checks included (~50 checks)

- Docker detection and binary/runtime reachability
- Daemon config file presence and JSON validity
- Rootless mode and user namespace remapping
- Seccomp and AppArmor profiles
- TLS for Docker daemon API / plain TCP exposure
- live-restore configuration
- Docker socket file permissions and ownership
- Container privilege audit: `--privileged`, capabilities drop/add
- Read-only root filesystem
- No-new-privileges and security options
- Userns mode: host vs isolated
- PID namespace: host vs private
- Cgroup namespace isolation
- Resource limits: CPU/memory/memory swap
- Inter-container communication (`icc`)
- Default bridge vs user-defined networks
- Network mode: host/bridge/none
- Published port exposure
- Sensitive host volume mounts
- Image inventory: age, dangling images
- Container default user / root execution
- Logging driver configuration

## Outputs

- **HTML Dashboard:** Dark-themed security report with score and sectioned findings
- **JSON:** Machine-readable results for ticketing/CI
- **TXT:** Plain-text report for quick review

## Usage

Run as root:

```bash
sudo ./audit-docker.sh --all
```

Flags:

- `--html` Generate HTML dashboard
- `--json` Generate JSON report
- `--txt` Generate TXT report
- `--all` Generate all formats
- `--quiet` Minimal console output
- `--no-color` Disable colored output
- `--output DIR` Custom output directory
- `--help` Show help

Exit status on failures can be used for CI gating (`0` clean, `2` any failures).

## Integration

This module follows the NawaSec add_result 11-parameter contract, so results can be consumed uniformly across all NawaSec modules.
