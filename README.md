<div align="center">

# Nginx Proxy Guard

### Make Your Nginx Smarter & Safer

**English** | [한국어](./README_KO.md)

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="./NPG_banner_dark.png">
  <img src="./NPG_banner.png" alt="Nginx Proxy Guard" width="520">
</picture>

[![Version](https://img.shields.io/github/v/release/svrforum/NginxProxyGuard?style=for-the-badge&color=brightgreen&label=Version)](https://github.com/svrforum/NginxProxyGuard/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/svrforum/NginxProxyGuard?style=for-the-badge&logo=github&color=gold)](https://github.com/svrforum/NginxProxyGuard/stargazers)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/u/svrforum)

[![Nginx](https://img.shields.io/badge/Nginx-1.30.4-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org/)
[![ModSecurity](https://img.shields.io/badge/ModSecurity-v3.0.15-red?style=for-the-badge)](https://modsecurity.org/)
[![OWASP CRS](https://img.shields.io/badge/OWASP_CRS-v4.26.0-orange?style=for-the-badge)](https://coreruleset.org/)
[![HTTP/3](https://img.shields.io/badge/HTTP/3-QUIC-blue?style=for-the-badge)]()

<p align="center">
  <strong>A secure and fast solution to manage proxy hosts, SSL certificates,<br/>and security rules through an intuitive web UI</strong>
</p>

<p align="center">
  <a href="https://nginxproxyguard.com">🌐 Website</a> •
  <a href="https://nginxproxyguard.com/en/docs">📖 Docs</a> •
  <a href="#-key-features">✨ Features</a> •
  <a href="#-quick-start">🚀 Quick Start</a> •
  <a href="#-tech-stack">🛠 Tech Stack</a> •
  <a href="#-api-documentation">📚 API</a>
</p>

<p align="center">
  <em>Love this project? Your sponsorship keeps it going ↓</em><br/>
  <a href="https://github.com/sponsors/svrforum" target="_blank"><img src="https://img.shields.io/badge/Sponsor-GitHub%20Sponsors-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Sponsor Nginx Proxy Guard on GitHub Sponsors"></a>
  <a href="https://buymeacoffee.com/svrforum" target="_blank"><img src="https://img.shields.io/badge/%E2%98%95%20Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Buy Me a Coffee"></a>
</p>

---

</div>

## ✨ Key Features

**Robust Security, Easy Management** - Reduced Nginx complexity, maximized security

### 🔒 SSL Automation
Let's Encrypt integration with automatic renewal. Supports wildcard certificates via DNS-01 challenge. Multiple DNS providers supported: **Cloudflare**, **AWS Route 53**, **DuckDNS**, **Dynu**, **IONOS**.

### 🤖 Bot Protection
Block 80+ malicious bots and 50+ AI crawlers automatically. Search engine allowlist ensures legitimate traffic. CAPTCHA challenge mode for suspicious requests.

### 📊 Intuitive Dashboard
Real-time traffic monitoring, security block logs, certificate status, and server health at a glance.

### 🌍 GeoIP Access Control
Block or allow traffic by country with interactive world map visualization. MaxMind GeoIP2 integration with auto-update.

### 📝 Log Viewer & Analytics
Analyze Nginx access/error logs with powerful filtering and exclusion patterns. **TimescaleDB** time-series optimization with automatic compression.

### 🛡️ Web Application Firewall
ModSecurity v3 with OWASP Core Rule Set v4.26. Paranoia Level 1-4, a global WAF default with per-host override, rule exclusions that are global or per host and can be scoped host-wide, to a URI path, or to a single argument, plus exploit blocking rules.

### ⚡ Rate Limiting
Protect against DDoS and brute-force attacks with configurable rate limits per IP, URI, or IP+URI combination.

### 🔀 Load Balancing & Upstream
Multiple backend servers with round-robin, least-connections, IP-hash or random distribution, per-server weights and backup servers (`down`, `max_fails`, `fail_timeout` per server via the API). Failed backends are taken out of rotation passively by nginx (`max_fails`/`fail_timeout`); active HTTP health probes are not implemented yet.

### 🔌 TCP/UDP Stream Proxying
Manage Nginx `stream` reverse proxies from the same UI. Supports TCP and UDP listeners, optional SNI preread routing (TCP only), PROXY protocol in/out, stream timeouts, config testing, and backup/restore. Banned IPs are auto-applied to stream listeners.

**Stream security scope** — `stream` operates at L4 (TCP/UDP), so HTTP-layer protections do **not** apply: ModSecurity (WAF), exploit blocking, bot filter, URI blocking, rate limit, and access lists are HTTP-only. IP-based controls (banned IPs) work at L4 and are auto-injected. fail2ban and GeoIP for stream listeners are tracked as follow-ups.

> Stream traffic is logged to `/var/log/nginx/stream_access.log` (and `stream_error.log`) inside the nginx container. LogCollector ingestion of stream traffic into the NPG dashboard is tracked as a follow-up; for now use `docker logs npg-proxy` or read the file directly.

> `worker_connections` is shared between HTTP and stream listeners. Large numbers of long-lived stream sessions can pressure HTTP capacity — increase `worker_connections` (Settings → Global → "Apply recommended" raises it to 8192) if you run heavy stream workloads.

> `CustomStreamConfig` (Advanced tab) accepts raw nginx `stream` directives and can bind arbitrary ports on any interface. Treat it as an admin-only capability.

### 🔐 Security Headers
HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, and Content-Security-Policy.

### 📋 Access Lists
IP-based access control lists for whitelisting or blacklisting. Support for CIDR notation.
Allow rules also accept a domain name (such as a DDNS name): only the addresses it currently resolves to are allowed.
URI block exceptions, priority allow, rate limit exceptions and the global trusted IPs take domain names too; a domain there never gets past bans or the WAF.

### 💾 Backup & Restore
Full configuration backup including certificates, settings, and database. Scheduled auto-backup support.

### 🔑 API Token Management
Create API tokens with granular permissions, IP restrictions, and expiration. Perfect for CI/CD integration.

### 🔄 Redirect Hosts
HTTP to HTTPS redirects, domain redirects, and custom redirect rules.

### 📜 Audit Logs
Track all configuration changes with user attribution and timestamps.

### 🔐 Two-Factor Authentication
Optional 2FA for admin accounts using TOTP (Google Authenticator, Authy, etc.).

### 🌐 HTTP/3 & QUIC
Modern protocol support for faster, more reliable connections over UDP.

### 🔐 Security Hardening (v2.2.0)
Strong password policy (10+ chars, complexity requirements). IP/CIDR input validation. Regex ReDoS prevention. Automatic Nginx config rollback on failure.

### 📡 Filter Subscriptions (v2.7.0)
Subscribe to external IP/CIDR blocklists that automatically sync and integrate with Nginx. Preset blocklists included, auto-refresh scheduling, entry deduplication across subscriptions and banned IPs. Up to 25K entries per list, 100K total.

### 🔮 Post-Quantum TLS (v2.6.0)
ML-KEM (X25519MLKEM768) hybrid key exchange support for future-proof TLS connections. Configurable via global SSL settings with OpenSSL 3.5 compatibility.

### ⚙️ Proxy Buffering Control (v2.3.2)
Global proxy request/response buffering settings for fine-tuned performance. Useful for WebSocket, streaming, and large file upload scenarios.

### 🔍 Config Error Diagnostics (v2.4.0)
Actionable error guides for proxy host configuration failures. Clickable error badges with detailed troubleshooting. Auto-disable broken configs on Nginx startup.

### 🌐 Dynamic DNS (v2.21.0, integrated v2.23.0)
Built-in DDNS keeps your domains pointed at your home server as your public IP changes (Cloudflare / DuckDNS / Dynu). Enable per proxy host with one toggle — the host's domains become managed DDNS records that auto-sync on domain changes and are cleaned up when the host is deleted. Bulk-enable existing hosts, and configure the refresh interval from the DDNS settings.

### 🔐 ForwardAuth (v2.27.0)
Put **Authelia**, **Authentik**, or a custom `auth_request` provider in front of a proxy host, with per-host bypass paths. (A host uses either ForwardAuth or the geo/bot challenge, not both.)

### 👥 Multi-User & Roles (v2.34.0)
Built-in **Administrator / Operator / Viewer** roles plus custom roles with per-area read/write permissions. Each person gets their own account and 2FA; API tokens can never exceed their owner's role.

### 🪪 SSO / OIDC Login (v2.35.0)
Sign in through any OpenID Connect provider (Keycloak preset included). Password login always stays available, and just-in-time account creation is fail-closed behind an allowlist.

### ☁️ Cloudflare Tunnel (v2.32.0, managed mode v2.48.0)
`cloudflared` ships inside the nginx image — paste a tunnel token and your hosts are reachable without port forwarding, still behind the full WAF/GeoIP/ban stack. Managed mode lets NPG maintain the tunnel's catch-all rule for you.

### 🔔 Notifications (v2.36.0)
Discord, Telegram and generic webhook channels. Each of the ten alerts can be off, immediate, or held for a daily summary that also reports CPU/memory/disk.

### 🌐 Global Security Defaults (v2.31.0)
Set GeoIP restriction, bot filter, security headers, cloud-provider blocking, rate limit and WAF mode/paranoia once, globally; every host inherits the default or overrides it.

### 🛰️ Trusted Proxies (v2.51.0)
Running behind Cloudflare or another proxy? Settings → Trusted Proxies (Cloudflare preset or custom CIDRs) tells nginx which hops to trust for the real client IP, so bans, access lists, GeoIP and fail2ban act on the visitor instead of the proxy.

### 🚧 Global Fail2ban Jail (v2.53.0)
Counts requests that matched **no** proxy host (direct-IP scanners, unknown hostnames answered with 444) — traffic a per-host jail can never see. Ships disabled in Log-Only mode and requires Trusted Proxies to be configured.

Also since June: saved log filter presets (v2.33.0), a per-IP activity view for banned addresses (v2.38.0), an in-app update check (v2.29.0), and WAF rule exclusions scoped to a path or argument (v2.37.0, fully working since v2.54.0).

---

## 🛠 Tech Stack

**Solid Tech Stack** - Designed with modern technologies, a microservices architecture

| Technology | Purpose |
|------------|---------|
| **Nginx 1.30.4** | High-performance HTTP and stream reverse proxy core with HTTP/3 & QUIC support |
| **TimescaleDB (PostgreSQL 17)** | Time-series-optimized database with automatic log compression |
| **Valkey 9** | Redis-compatible high-speed caching and session management (optional) |
| **Go 1.26 (Echo v4)** | Backend API with efficient resource management and concurrency |
| **React 19 & TypeScript 6** | Type-safe, component-based modern UI (Vite 8 + Tailwind 4) |
| **ModSecurity v3.0.15** | Web Application Firewall with OWASP Core Rule Set v4.26.0 |
| **MaxMind GeoIP2** | Geographic IP database for country-level access control |

---

## 🚀 Quick Start

**Get Started in 1 Minute** - Run Nginx Proxy Guard using Docker Compose

### Prerequisites

- Docker 24.0+ and Docker Compose v2
- A linux/amd64 or linux/arm64 host (Raspberry Pi 4/5 and other ARM64 servers are supported)
- (Optional) [MaxMind License Key](https://www.maxmind.com/en/geolite2/signup) for GeoIP

### Installation

```bash
# 1. Create directory
mkdir -p ~/nginx-proxy-guard && cd ~/nginx-proxy-guard

# 2. Download files
wget https://raw.githubusercontent.com/svrforum/nginxproxyguard/main/docker-compose.yml
wget -O .env https://raw.githubusercontent.com/svrforum/nginxproxyguard/main/env.example

# 3. Auto-generate secure secrets
sed -i "s/DB_PASSWORD=.*/DB_PASSWORD=$(openssl rand -base64 24)/" .env
sed -i "s/JWT_SECRET=.*/JWT_SECRET=$(openssl rand -hex 32)/" .env

# 4. Start services
docker compose up -d
```

### Access

| Service | URL |
|---------|-----|
| Admin Panel | https://localhost:81 |
| HTTP Proxy | http://localhost:80 |
| HTTPS Proxy | https://localhost:443 |

**Default Login**: `admin` / `admin` (Change immediately after first login!)

> **Security notes**
> - Since **v2.24.6** the server blocks every protected API until the default credentials are changed (initial-setup gate), so a freshly-installed instance cannot be hijacked via `admin`/`admin`.
> - **Do not expose the Admin Panel (port 81) to the internet.** Keep it on your LAN/VPN, or front it with its own proxy host protected by access lists and 2FA.
> - Found a vulnerability? Please report it privately — see [SECURITY.md](./SECURITY.md).

> **Password Policy (v2.2.0+)**: New passwords must be at least 10 characters with uppercase, lowercase, digit, and special character. Common passwords are blocked.

### Update

```bash
docker compose pull
docker compose up -d
```

### Reset Admin Password

Lost your admin password (or 2FA device)? If you have shell access to the host, recover from the CLI without touching the database directly:

```bash
# Auto-target the sole admin and print a freshly generated random password
docker compose exec api ./server reset-password

# Pick a specific user
docker compose exec api ./server reset-password --username alice

# Set a known password instead of the auto-generated one (≥ 8 chars, ≤ 72 bytes)
docker compose exec api ./server reset-password --username alice --password 'S3cure-Pwd!'

# Also wipe the user's TOTP secret and disable 2FA
docker compose exec api ./server reset-password --clear-2fa
```

Each successful reset:
- writes a fresh bcrypt `password_hash`
- clears the user's failed `login_attempts` (lifts any stale per-IP lockout)
- invalidates every active `auth_session` for that user — they (and any holder of a stolen token) must sign in again
- records a `Password reset via CLI` entry in `system_logs` (`source=audit`)

Sign in with the printed password and change it immediately from **Account Settings** in the UI.

### Upgrading

All versions are fully backward compatible. No manual migration needed — database schema upgrades are applied automatically on startup. Just pull the latest image and recreate the containers.

> **Compose-level options** (port overrides, API/login rate limits, `TRUSTED_PROXY_CIDR`, container log caps, capability drops) only reach installs whose `docker-compose.yml` is refreshed — pulling images alone keeps your old compose file. Compare yours with the current [docker-compose.yml](./docker-compose.yml) after upgrading. See the [latest releases](https://github.com/svrforum/NginxProxyGuard/releases) and [Key Features](#-key-features) for what changed.

---

## 📚 API Documentation

Nginx Proxy Guard provides a comprehensive REST API for automation and integration.

### Authentication

All API endpoints require authentication via:
- **Session token**: `Authorization: Bearer <token>` (the `token` field returned by `POST /api/v1/auth/login`, or by `POST /api/v1/auth/verify-2fa` when 2FA is enabled)
- **API Token**: `Authorization: Bearer ng_<api_token>` (for automation)

### Key Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/auth/login` | Authenticate and get a session token |
| `GET /api/v1/proxy-hosts` | List all proxy hosts |
| `POST /api/v1/proxy-hosts` | Create new proxy host |
| `GET /api/v1/certificates` | List SSL certificates |
| `POST /api/v1/certificates` | Request new certificate |
| `GET /api/v1/waf/rules` | List WAF rules |
| `POST /api/v1/backups` | Create backup |
| `GET /api/v1/filter-subscriptions` | List filter subscriptions |
| `GET /api/v1/dashboard` | Get dashboard stats |

### Swagger UI

The API documentation (Swagger UI) is served at:
```
https://localhost:81/api/docs
```
The raw OpenAPI 3.0 spec is at `https://localhost:81/api/docs/swagger.yaml`.

---

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password | (required) |
| `JWT_SECRET` | Application secret — set it to a random value (`openssl rand -hex 32`) | placeholder in `docker-compose.yml` (change it) |
| `TZ` | Timezone | `UTC` |
| `DB_USER` | PostgreSQL user | `postgres` |
| `DB_NAME` | Database name | `nginx_proxy_guard` |
| `DOCKER_API_VERSION` | Docker API version (for Synology) | auto-detect |
| `UI_PORT` | Admin panel host port | `81` |
| `NGINX_HTTP_PORT` / `NGINX_HTTPS_PORT` | nginx listen ports (host network mode; change when 80/443 are already taken, e.g. Synology DSM) | `80` / `443` |
| `API_HOST_PORT` | Loopback host port nginx uses to reach the API (must not collide with another service) | `9080` |
| `API_RATE_LIMIT_PER_MINUTE` | Per-IP API request budget per minute; `0` = off; needs Valkey | `600` |
| `AUTH_RATE_LIMIT_PER_MINUTE` | Separate per-IP budget for the login endpoints; `0` = off; needs Valkey | `100` |
| `TRUSTED_PROXY_CIDR` | Comma-separated CIDRs the API trusts as `X-Forwarded-For` hops; unset = trust loopback/link-local/private ranges | (unset) |

---

## 📖 More Information

- **Website**: [nginxproxyguard.com](https://nginxproxyguard.com)
- **Documentation**: [nginxproxyguard.com/docs](https://nginxproxyguard.com/en/docs)

---

## ☕ Sponsor

If you find Nginx Proxy Guard useful, consider supporting the project! [GitHub Sponsors](https://github.com/sponsors/svrforum) is the best way to help — it goes directly to development with zero platform fees.

<a href="https://github.com/sponsors/svrforum" target="_blank"><img src="https://img.shields.io/badge/%E2%9D%A4%20Sponsor%20on%20GitHub-EA4AAA?style=for-the-badge&logo=githubsponsors&logoColor=white" alt="Sponsor on GitHub Sponsors" height="50"></a>
<a href="https://buymeacoffee.com/svrforum" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- [Website](https://nginxproxyguard.com) - Documentation and guides
- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - Bug reports and feature requests
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - Questions and community
- [GitHub Sponsors](https://github.com/sponsors/svrforum) - Support the project (zero fees)
- [Buy Me a Coffee](https://buymeacoffee.com/svrforum) - Support the project

---

<div align="center">
  <sub>© 2025-2026 Nginx Proxy Guard. Powerful, secure, and fast Nginx proxy manager & WAF.</sub>
</div>
