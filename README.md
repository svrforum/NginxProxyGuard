<div align="center">

# Nginx Proxy Guard

### Make Your Nginx Smarter & Safer

**English** | [한국어](./README_KO.md)

<img src="https://nginxproxyguard.com/images/homepage/hero/bannerImages/0.png" alt="Nginx Proxy Guard Dashboard" width="800">

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
  <a href="#-tech-stack">Tech Stack</a>
</p>

---

</div>

## ✨ Key Features

**Robust Security, Easy Management** - Reduced Nginx complexity, maximized security

### SSL Automation
Let's Encrypt integration with automatic renewal. Supports wildcard certificates via DNS-01 challenge (Cloudflare).

### Bot Protection
Block 80+ malicious bots and 50+ AI crawlers automatically. Search engine allowlist ensures legitimate traffic.

### Intuitive Dashboard
Real-time traffic monitoring, block logs, and server status at a glance.

### GeoIP Access Control
Block or allow traffic by country with interactive map visualization. MaxMind GeoIP2 integration.

### Log Viewer & Analytics
Analyze Nginx access/error logs with powerful filtering and exclusion patterns.

### Web Application Firewall
ModSecurity v3 with OWASP Core Rule Set v4.21. Paranoia Level 1-4, per-host rule exceptions.

---

## 🛠 Tech Stack

**Solid Tech Stack** - Designed with modern technologies, a microservices architecture

| Technology | Purpose |
|------------|---------|
| **Nginx** | High-performance reverse proxy core with HTTP/3 & QUIC support |
| **PostgreSQL** | Secure storage for configurations and logs with optimized queries |
| **Valkey (Redis)** | High-speed caching, session management, real-time data processing |
| **Go (Golang)** | Backend API with efficient resource management and concurrency |
| **React & TypeScript** | Type-safe, component-based modern UI |
| **ModSecurity** | Web Application Firewall with OWASP Core Rule Set |

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
wget -O .env https://raw.githubusercontent.com/svrforum/nginxproxyguard/main/.env.example

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

### Update

```bash
docker compose pull
docker compose up -d
```

---

## 📖 More Information

- **Website**: [nginxproxyguard.com](https://nginxproxyguard.com)
- **Documentation**: [nginxproxyguard.com/docs](https://nginxproxyguard.com/docs)

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - Bug reports and feature requests
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - Questions and community

---

<div align="center">
  <sub>© 2025 Nginx Proxy Guard. Powerful, secure, and fast Nginx proxy manager & WAF.</sub>
</div>
