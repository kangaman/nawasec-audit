# NawaSec Nginx Audit Module

**Version:** 1.0.0  
**Module:** `nawasec-audit/nginx`  
**Repository:** https://github.com/kangaman/nawasec-audit

## Description

The Nginx Audit Module evaluates Nginx HTTP server configurations for security misconfigurations, TLS weaknesses, header hygiene, and reverse-proxy risks. It supports standard installs as well as configurations embedded in container and CI/CD delivery pipelines.

## Supported Platforms

- Nginx 1.18+ on Linux containers and VPS
- Ubuntu, Debian, RHEL, CentOS, and Alpine-based Nginx packages
- Nginx installed from source or managed via `nginx -t` config chains

## Usage

### Command Examples

```bash
# Scan main Nginx config and included files
nawasec-audit nginx --config /etc/nginx/nginx.conf

# Scan a standalone config file for a specific target
nawasec-audit nginx --config /etc/nginx/conf.d/default.conf

# Output reports
nawasec-audit nginx --config /etc/nginx/nginx.conf --output nginx-report.json --format json
nawasec-audit nginx --config /etc/nginx/nginx.conf --output nginx-report.html --format html
nawasec-audit nginx --config /etc/nginx/nginx.conf --category tls --category headers

# Include custom snippets directory
nawasec-audit nginx --config /etc/nginx/nginx.conf --include-dir /etc/nginx/snippets
```

## Audit Categories

| Category | Description |
|----------|-------------|
| `tls` | TLS version exposure, weak ciphers, certificate metadata, OCSP, and HSTS configuration. |
| `headers` | `Content-Security-Policy`, `X-Frame-Options`, `Referrer-Policy`, `server_tokens`, `X-XSS-Protection`, and `add_header` inheritance. |
| `configuration` | `client_max_body_size`, buffer size, `underscores_in_headers`, `server_name_in_redirect`, and directory behavior. |
| `modules` | Usage of `ngx_http_ssl_module`, `ngx_http_proxy_module`, `ngx_http_headers_module`, and third-party modules. |
| `proxy` | `proxy_set_header`, `proxy_pass` trust boundaries, WebSocket proxying, and upstream health checks. |
| `logging` | Access and error logging, log format, buffering behavior, and sensitive field exposure. |
| `rate-limiting` | `limit_req`, `limit_conn`, burst behavior, and DoS resilience posture. |
| `listeners` | IPv4 vs IPv6 listeners, exposed ports, and default server block behavior. |

## Output Formats

- **HTML** — Per-location and per-server block findings with config snippet linking.
- **JSON** — Machine-readable findings tied to exact directive names and file references.
- **TXT** — Plain summary with concise remediation commands per finding.

## Scoring System

NawaSec treats Nginx as a high-exposure edge component:

- TLS and header hygiene contribute the largest share of score because they directly affect external clients.
- Reverse proxy rules are weighted heavily because misconfigurations can turn Nginx into a trust-boundary leak.
- A score of **80% or above** indicates production-edge readiness.
- Scores in the 55–75% range typically indicate internal or staging configurations that need hardening before being promoted to production.

## Example Output

```
[INFO] Nginx config loaded: /etc/nginx/nginx.conf
[SCAN] Categories: tls, headers, configuration, modules, proxy, logging, rate-limiting, listeners

[CRITICAL] tls — ssl_protocols includes TLSv1 and TLSv1.1 (severity: Critical)
[WARN] headers — add_header Content-Security-Policy missing for /api location (severity: Medium)
[PASS] headers — server_tokens off; detected
[INFO] proxy — upstream block 'backend' has no health_check directive

=== Nginx Audit Summary ===
Overall Score: 76.3 / 100 (Grade: B)
Critical: 1
High: 1
Medium: 5
Low: 9
Info: 19
Output: html:/root/reports/nginx-audit-20250115.html
```

## Roadmap

- [ ] Add checks for Nginx Plus-specific features and advanced ACL controls
- [ ] Add OpenResty / Lua script behavior review guidance
- [ ] Add container-native patterns for Kubernetes Ingress controller configs
- [ ] Add checks for `mitm` / `proxy_set_header Host` leak paths
- [ ] Add DNS rebinding and http2 header compression checks

## License

MIT — see the main repository for details.
