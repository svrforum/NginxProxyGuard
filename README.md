<div align="center">

# Nginx Proxy Guard

### Next-Generation Nginx Reverse Proxy Manager with Enterprise Security

**English** | [한국어](./README_KO.md)

[![Nginx](https://img.shields.io/badge/Nginx-1.28.0-009639?style=for-the-badge&logo=nginx&logoColor=white)](https://nginx.org/)
[![ModSecurity](https://img.shields.io/badge/ModSecurity-v3.0.14-red?style=for-the-badge)](https://modsecurity.org/)
[![OWASP CRS](https://img.shields.io/badge/OWASP_CRS-v4.21.0-orange?style=for-the-badge)](https://coreruleset.org/)
[![HTTP/3](https://img.shields.io/badge/HTTP/3-QUIC-blue?style=for-the-badge)]()
[![License](https://img.shields.io/badge/License-MIT-yellow?style=for-the-badge)](LICENSE)

<p align="center">
  <strong>Modern reverse proxy management system with<br/>powerful WAF, Bot Protection, GeoIP Blocking, and Rate Limiting</strong>
</p>

---

</div>

## ✨ Key Features

| Category | Features |
|----------|----------|
| **WAF** | ModSecurity v3 + OWASP CRS v4.21, Paranoia Level 1-4, Per-host exceptions |
| **Bot Protection** | 200+ bot signatures, Search engine allowlist, AI bot detection |
| **GeoIP** | Country blocking/challenge, MaxMind integration, Traffic visualization |
| **Rate Limiting** | Per-host/global limits, Burst handling, Auto-ban |
| **Challenge** | reCAPTCHA v2/v3, hCaptcha, Cloudflare Turnstile |
| **SSL/TLS** | Let's Encrypt auto-renewal, HTTP/3 QUIC support |
| **Monitoring** | Real-time dashboard, Log viewer with GeoIP, Traffic analytics |

---

## 🚀 Quick Start

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

# 4. Auto-detect timezone
TZ=$(cat /etc/timezone 2>/dev/null || readlink /etc/localtime | sed 's|/usr/share/zoneinfo/||' 2>/dev/null || echo "UTC")
sed -i "s|TZ=.*|TZ=$TZ|" .env

# 5. Start services
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

## 📚 Documentation

- [Configuration Guide](./docs/configuration.md) - Environment variables, SSL setup, GeoIP
- [API Reference](./docs/api.md) - REST API documentation
- [Architecture](./docs/architecture.md) - System design and tech stack
- [Troubleshooting](./docs/troubleshooting.md) - Common issues and solutions
- [Development](./docs/development.md) - Contributing and local setup

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 💬 Support

- [GitHub Issues](https://github.com/svrforum/nginxproxyguard/issues) - Bug reports and feature requests
- [Discussions](https://github.com/svrforum/nginxproxyguard/discussions) - Questions and community
