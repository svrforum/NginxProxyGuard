# Migration Guide: Bridge Mode → Host Mode (v2)

## Overview

Starting from v2, Nginx Proxy Guard runs nginx exclusively in **host network mode**.
This provides real client IP addresses directly without relying on Docker proxy protocol,
simplifying the architecture and improving security logging accuracy.

## What Changed

| Before (v1) | After (v2) |
|---|---|
| `docker-compose.yml` (bridge mode) + `docker-compose.host.yml` (host mode) | Single `docker-compose.yml` (host mode only) |
| nginx uses Docker bridge network with port mapping | nginx uses `network_mode: host` |
| `resolver 127.0.0.11` (Docker DNS) | Configurable `DNS_RESOLVER` (default: `127.0.0.53 8.8.8.8`) |
| API URL default `http://api:8080` | API URL default `http://127.0.0.1:9080` |
| `NGINX_STATUS_URL` default `http://nginx:8080/nginx_status` | Default `http://host.docker.internal:80/nginx_status` |

## Migration Steps

### 1. Stop Current Services

```bash
docker compose down
```

### 2. Back Up Your Data

```bash
# Back up volumes
docker run --rm -v npg_postgres_data:/data -v $(pwd)/backup:/backup alpine tar czf /backup/postgres_data.tar.gz -C /data .
docker run --rm -v npg_nginx_data:/data -v $(pwd)/backup:/backup alpine tar czf /backup/nginx_data.tar.gz -C /data .
docker run --rm -v npg_api_data:/data -v $(pwd)/backup:/backup alpine tar czf /backup/api_data.tar.gz -C /data .
```

### 3. Update `.env` File

Add the following variables if not already present:

```env
# API host port (nginx reaches API via this port on localhost)
API_HOST_PORT=9080

# Optional: custom DNS resolver (default: 127.0.0.53 8.8.8.8)
# DNS_RESOLVER=127.0.0.53 8.8.8.8
```

If you were using custom ports (e.g., Synology DSM), keep your `NGINX_HTTP_PORT` and `NGINX_HTTPS_PORT` settings.

### 4. If You Were Using `docker-compose.host.yml`

You were already in host mode. Simply switch to the main `docker-compose.yml`:

```bash
# Old way
docker compose -f docker-compose.host.yml up -d

# New way
docker compose up -d
```

Your `API_HOST_PORT` and `API_HOST` settings in `.env` will continue to work.

### 5. If You Were Using Default `docker-compose.yml` (Bridge Mode)

The main compose file now uses host mode. Ensure port 80/443 are available on the host,
or set `NGINX_HTTP_PORT` / `NGINX_HTTPS_PORT` in `.env`.

```bash
docker compose up -d
```

### 6. Verify

```bash
# Check all services are running
docker compose ps

# API health check
docker compose exec api wget -qO- http://localhost:8080/health

# Nginx config test
docker exec npg-proxy nginx -t

# Check real client IPs are being logged
docker exec npg-proxy tail -5 /etc/nginx/logs/access_raw.log
```

## Troubleshooting

### Port Conflict

If ports 80/443 are occupied by another service:

```env
NGINX_HTTP_PORT=8080
NGINX_HTTPS_PORT=8443
```

### DNS Resolution Issues

If upstream hosts fail to resolve, set a custom DNS resolver:

```env
DNS_RESOLVER=8.8.8.8 1.1.1.1
```

### API Unreachable from Nginx

Ensure `API_HOST_PORT` doesn't conflict with `NGINX_HTTP_PORT`:

```env
API_HOST_PORT=9080    # Must differ from NGINX_HTTP_PORT
```
