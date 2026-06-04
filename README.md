<div align="center">

# Nginx Proxy Guard

### Make Your Nginx Smarter & Safer

**English** | [한국어](./README_KO.md)

<img src="./NPG_banner.png" alt="Nginx Proxy Guard" width="800">

[![Version](https://img.shields.io/badge/Version-2.23.1-brightgreen?style=for-the-badge)](https://github.com/svrforum/NginxProxyGuard/releases)
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)
[![GitHub stars](https://img.shields.io/github/stars/svrforum/NginxProxyGuard?style=for-the-badge&logo=github&color=gold)](https://github.com/svrforum/NginxProxyGuard/stargazers)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=for-the-badge&logo=docker&logoColor=white)](https://hub.docker.com/u/svrforum)

[![Nginx](https://img.shields.io/badge/Nginx-1.30.1-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org/)
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
  <em>Love this project? A coffee keeps it going ↓</em><br/>
  <a href="https://buymeacoffee.com/svrforum" target="_blank"><img src="https://img.shields.io/badge/%E2%98%95%20Sponsor%20this%20project-Buy%20Me%20a%20Coffee-FFDD00?style=for-the-badge&logo=buymeacoffee&logoColor=black" alt="Sponsor Nginx Proxy Guard"></a>
</p>

---

</div>

## ✨ Key Features

**Robust Security, Easy Management** - Reduced Nginx complexity, maximized security

### 🔒 SSL Automation
Let's Encrypt integration with automatic renewal. Supports wildcard certificates via DNS-01 challenge. Multiple DNS providers supported: **Cloudflare**, **DuckDNS**, **Dynu**.

### 🤖 Bot Protection
Block 80+ malicious bots and 50+ AI crawlers automatically. Search engine allowlist ensures legitimate traffic. CAPTCHA challenge mode for suspicious requests.

### 📊 Intuitive Dashboard
Real-time traffic monitoring, security block logs, certificate status, and server health at a glance.

### 🌍 GeoIP Access Control
Block or allow traffic by country with interactive world map visualization. MaxMind GeoIP2 integration with auto-update.

### 📝 Log Viewer & Analytics
Analyze Nginx access/error logs with powerful filtering and exclusion patterns. **TimescaleDB** time-series optimization with automatic compression.

### 🛡️ Web Application Firewall
ModSecurity v3 with OWASP Core Rule Set v4.26. Paranoia Level 1-4, per-host rule exceptions, exploit blocking rules.

### ⚡ Rate Limiting
Protect against DDoS and brute-force attacks with configurable rate limits per IP, URI, or IP+URI combination.

### 🔀 Load Balancing & Upstream
Multiple backend servers with round-robin, least connections, IP hash, or weighted distribution. Health checks included.

### 🔌 TCP/UDP Stream Proxying
Manage Nginx `stream` reverse proxies from the same UI. Supports TCP and UDP listeners, optional SNI preread routing (TCP only), PROXY protocol in/out, stream timeouts, config testing, and backup/restore. Banned IPs are auto-applied to stream listeners.

**Stream security scope** — `stream` operates at L4 (TCP/UDP), so HTTP-layer protections do **not** apply: ModSecurity (WAF), exploit blocking, bot filter, URI blocking, rate limit, and access lists are HTTP-only. IP-based controls (banned IPs) work at L4 and are auto-injected. fail2ban and GeoIP for stream listeners are tracked as follow-ups.

> Stream traffic is logged to `/var/log/nginx/stream_access.log` (and `stream_error.log`) inside the nginx container. LogCollector ingestion of stream traffic into the NPG dashboard is tracked as a follow-up; for now use `docker logs npg-proxy` or read the file directly.

> `worker_connections` is shared between HTTP and stream listeners. Large numbers of long-lived stream sessions can pressure HTTP capacity — increase `worker_connections` (Settings → Global → "Apply recommended preset" raises it to 8192) if you run heavy stream workloads.

> `CustomStreamConfig` (Advanced tab) accepts raw nginx `stream` directives and can bind arbitrary ports on any interface. Treat it as an admin-only capability.

### 🔐 Security Headers
HSTS, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, and Content-Security-Policy.

### 📋 Access Lists
IP-based access control lists for whitelisting or blacklisting. Support for CIDR notation.

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
Built-in DDNS keeps your domains pointed at your home server as your public IP changes (Cloudflare / DuckDNS). Enable per proxy host with one toggle — the host's domains become managed DDNS records that auto-sync on domain changes and are cleaned up when the host is deleted. Bulk-enable existing hosts, and configure the refresh interval from the DDNS settings.

---

## 🛠 Tech Stack

**Solid Tech Stack** - Designed with modern technologies, a microservices architecture

| Technology | Purpose |
|------------|---------|
| **Nginx 1.30.1** | High-performance HTTP and stream reverse proxy core with HTTP/3 & QUIC support |
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

> **Recently added**: built-in Dynamic DNS (Cloudflare/DuckDNS) integrated per proxy host. See the [latest releases](https://github.com/svrforum/NginxProxyGuard/releases) and [Key Features](#-key-features).

---

## 📚 API Documentation

Nginx Proxy Guard provides a comprehensive REST API for automation and integration.

### Authentication

All API endpoints require authentication via:
- **JWT Token**: `Authorization: Bearer <jwt_token>` (from login)
- **API Token**: `Authorization: Bearer ng_<api_token>` (for automation)

### Key Endpoints

| Endpoint | Description |
|----------|-------------|
| `POST /api/v1/auth/login` | Authenticate and get JWT token |
| `GET /api/v1/proxy-hosts` | List all proxy hosts |
| `POST /api/v1/proxy-hosts` | Create new proxy host |
| `GET /api/v1/certificates` | List SSL certificates |
| `POST /api/v1/certificates` | Request new certificate |
| `GET /api/v1/waf/rules` | List WAF rules |
| `POST /api/v1/backups` | Create backup |
| `GET /api/v1/filter-subscriptions` | List filter subscriptions |
| `GET /api/v1/dashboard` | Get dashboard stats |

### Swagger UI

Access the interactive API documentation at:
```
https://localhost:81/api/v1/swagger
```

---

## ⚙️ Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_PASSWORD` | PostgreSQL password | (required) |
| `JWT_SECRET` | Secret for JWT tokens | (required) |
| `TZ` | Timezone | `UTC` |
| `DB_USER` | PostgreSQL user | `postgres` |
| `DB_NAME` | Database name | `nginx_proxy_guard` |
| `DOCKER_API_VERSION` | Docker API version (for Synology) | auto-detect |

---

## 📖 More Information

- **Website**: [nginxproxyguard.com](https://nginxproxyguard.com)
- **Documentation**: [nginxproxyguard.com/docs](https://nginxproxyguard.com/en/docs)

---

## ☕ Sponsor

If you find Nginx Proxy Guard useful, consider supporting the project!

<a href="https://buymeacoffee.com/svrforum" target="_blank"><img src="https://cdn.buymeacoffee.com/buttons/v2/default-yellow.png" alt="Buy Me A Coffee" height="50"></a>

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - Bug reports and feature requests
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - Questions and community
- [Buy Me a Coffee](https://buymeacoffee.com/svrforum) - Support the project

---

<div align="center">
  <sub>© 2025-2026 Nginx Proxy Guard. Powerful, secure, and fast Nginx proxy manager & WAF.</sub>
</div>
