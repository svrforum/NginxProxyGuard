<div align="center">

# Nginx Proxy Guard

### Make Your Nginx Smarter & Safer

**English** | [한국어](./README_KO.md)

<img src="./NPG_banner.png" alt="Nginx Proxy Guard" width="800">

[![Version](https://img.shields.io/badge/Version-2.2.0-brightgreen?style=for-the-badge)]()
[![Nginx](https://img.shields.io/badge/Nginx-1.28.0-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org/)
[![ModSecurity](https://img.shields.io/badge/ModSecurity-v3.0.14-red?style=for-the-badge)](https://modsecurity.org/)
[![OWASP CRS](https://img.shields.io/badge/OWASP_CRS-v4.21.0-orange?style=for-the-badge)](https://coreruleset.org/)
[![HTTP/3](https://img.shields.io/badge/HTTP/3-QUIC-blue?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

<p align="center">
  <strong>A secure and fast solution to manage proxy hosts, SSL certificates,<br/>and security rules through an intuitive web UI</strong>
</p>

<p align="center">
  <a href="https://nginxproxyguard.com">Website</a> •
  <a href="#-key-features">Features</a> •
  <a href="#-quick-start">Quick Start</a> •
  <a href="#-tech-stack">Tech Stack</a> •
  <a href="#-api-documentation">API</a>
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
ModSecurity v3 with OWASP Core Rule Set v4.21. Paranoia Level 1-4, per-host rule exceptions, exploit blocking rules.

### ⚡ Rate Limiting
Protect against DDoS and brute-force attacks with configurable rate limits per IP, URI, or IP+URI combination.

### 🔀 Load Balancing & Upstream
Multiple backend servers with round-robin, least connections, IP hash, or weighted distribution. Health checks included.

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

---

## 🛠 Tech Stack

**Solid Tech Stack** - Designed with modern technologies, a microservices architecture

| Technology | Purpose |
|------------|---------|
| **Nginx 1.28** | High-performance reverse proxy core with HTTP/3 & QUIC support |
| **TimescaleDB** | PostgreSQL with time-series optimization for log compression |
| **Valkey 8** | Redis-compatible high-speed caching and session management |
| **Go 1.24** | Backend API with efficient resource management and concurrency |
| **React 18 & TypeScript** | Type-safe, component-based modern UI |
| **ModSecurity 3** | Web Application Firewall with OWASP Core Rule Set v4.21 |
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

### Upgrading to v2.2.0

v2.2.0 is fully backward compatible. No migration needed.

> **Password policy change**: New passwords now require 10+ characters with complexity requirements. Existing users can still log in — the policy only applies when changing passwords.

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

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - Bug reports and feature requests
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - Questions and community

---

<div align="center">
  <sub>© 2025-2026 Nginx Proxy Guard. Powerful, secure, and fast Nginx proxy manager & WAF.</sub>
</div>
