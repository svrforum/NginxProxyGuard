#!/bin/sh
# Nginx Proxy Guard Nginx Docker Entrypoint
# Handles volume initialization, GeoIP updates, raw log configuration, and nginx startup

set -e

echo "=========================================="
echo "  Nginx Proxy Guard Nginx Proxy"
echo "=========================================="

NGINX_DEFAULT="/etc/nginx.default"
NGINX_DIR="/etc/nginx"
GEOIP_DIR="/etc/nginx/geoip"
LOG_DIR="/etc/nginx/logs"
LEGACY_LOG_DIR="/var/log/nginx"
RAW_LOG_CONFIG="/etc/nginx/conf.d/.raw_log_config"
LOGROTATE_CONFIG="/etc/logrotate.d/nginx-proxy-guard"

# =============================================================================
# Volume Initialization
# When /etc/nginx is mounted as a volume, it may be empty
# Copy default configuration files from /etc/nginx.default
# =============================================================================
initialize_nginx_volume() {
    if [ ! -f "$NGINX_DIR/nginx.conf" ]; then
        echo "[Entrypoint] Initializing nginx volume from defaults..."

        # Copy all default files to the volume
        cp -a "$NGINX_DEFAULT/." "$NGINX_DIR/"

        # Create required subdirectories that might be missing
        mkdir -p "$NGINX_DIR/conf.d"
        mkdir -p "$NGINX_DIR/certs"
        mkdir -p "$NGINX_DIR/geoip"
        mkdir -p "$NGINX_DIR/modsec"
        mkdir -p "$NGINX_DIR/includes"
        mkdir -p "$NGINX_DIR/acme-challenge"
        mkdir -p "$NGINX_DIR/owasp-crs"
        mkdir -p "$NGINX_DIR/logs"

        # Set permissions
        chown -R nginx:nginx "$NGINX_DIR/conf.d" "$NGINX_DIR/certs" "$NGINX_DIR/geoip" "$NGINX_DIR/modsec" "$NGINX_DIR/logs" 2>/dev/null || true

        echo "[Entrypoint] Nginx volume initialized successfully"
    else
        echo "[Entrypoint] Nginx configuration found in volume"
    fi
}

# Function to ensure GeoIP config files exist in geoip volume
ensure_geoip_configs() {
    # Create geoip-enabled.conf if it doesn't exist (volume may be empty)
    if [ ! -f "$GEOIP_DIR/geoip-enabled.conf" ]; then
        echo "[Entrypoint] Creating geoip-enabled.conf..."
        cat > "$GEOIP_DIR/geoip-enabled.conf" << 'GEOIPCONF'
# ==========================================================================
# GeoIP2 Configuration for Nginx Proxy Guard
# Provides country and ASN information for access control and logging
# ==========================================================================

# GeoIP2 Country Database
geoip2 /etc/nginx/geoip/GeoLite2-Country.mmdb {
    auto_reload 60m;
    $geoip2_metadata_country_build metadata build_epoch;
    $geoip2_country_code default=-- source=$remote_addr country iso_code;
    $geoip2_country_name default="Unknown" source=$remote_addr country names en;
    $geoip2_continent_code default=-- source=$remote_addr continent code;
}

# GeoIP2 ASN Database (for ISP/Organization info)
geoip2 /etc/nginx/geoip/GeoLite2-ASN.mmdb {
    auto_reload 60m;
    $geoip2_asn default=0 source=$remote_addr autonomous_system_number;
    $geoip2_org default="Unknown" source=$remote_addr autonomous_system_organization;
}
GEOIPCONF
    fi

    # Create geoip-disabled.conf if it doesn't exist
    if [ ! -f "$GEOIP_DIR/geoip-disabled.conf" ]; then
        echo "[Entrypoint] Creating geoip-disabled.conf..."
        cat > "$GEOIP_DIR/geoip-disabled.conf" << 'GEODISABLED'
# ==========================================================================
# GeoIP2 Disabled - Placeholder Variables
# ==========================================================================
# This file provides default values when GeoIP databases are not available

map $remote_addr $geoip2_country_code {
    default "--";
}

map $remote_addr $geoip2_country_name {
    default "Unknown";
}

map $remote_addr $geoip2_continent_code {
    default "--";
}

map $remote_addr $geoip2_asn {
    default "0";
}

map $remote_addr $geoip2_org {
    default "Unknown";
}
GEODISABLED
    fi
}

# Function to setup GeoIP configuration
setup_geoip_config() {
    local geoip_enabled=false

    # First ensure config files exist in volume
    ensure_geoip_configs

    # Check if valid GeoIP databases exist
    if [ -f "$GEOIP_DIR/GeoLite2-Country.mmdb" ] && [ -f "$GEOIP_DIR/GeoLite2-ASN.mmdb" ]; then
        # Additional check: file size should be reasonable (> 1MB for Country DB)
        local country_size=$(stat -c%s "$GEOIP_DIR/GeoLite2-Country.mmdb" 2>/dev/null || echo "0")
        local asn_size=$(stat -c%s "$GEOIP_DIR/GeoLite2-ASN.mmdb" 2>/dev/null || echo "0")
        # Valid GeoIP databases are at least 1MB
        if [ "$country_size" -gt 1000000 ] && [ "$asn_size" -gt 1000000 ]; then
            geoip_enabled=true
        fi
    fi

    # Create symlink to appropriate config (always recreate to handle volume mount)
    rm -f "$GEOIP_DIR/geoip-active.conf"

    if [ "$geoip_enabled" = true ]; then
        echo "[Entrypoint] GeoIP databases found - enabling GeoIP features"
        ln -sf "$GEOIP_DIR/geoip-enabled.conf" "$GEOIP_DIR/geoip-active.conf"
        rm -f "$GEOIP_DIR/.no-geoip"
    else
        echo "[Entrypoint] GeoIP databases not available - using placeholder values"
        ln -sf "$GEOIP_DIR/geoip-disabled.conf" "$GEOIP_DIR/geoip-active.conf"
        touch "$GEOIP_DIR/.no-geoip"
    fi
}

# Function to setup log file configuration
# IMPORTANT: We always keep stdout/stderr for LogCollector (docker logs)
# Raw log files are ADDITIONAL storage, not a replacement
# Raw logs are stored in /etc/nginx/logs (within the consolidated volume) for API access
setup_log_files() {
    local raw_log_enabled=false

    # Check if raw log configuration file exists
    if [ -f "$RAW_LOG_CONFIG" ]; then
        raw_log_enabled=$(grep "^ENABLED=" "$RAW_LOG_CONFIG" | cut -d'=' -f2)
    fi

    echo "[Entrypoint] Raw log enabled: $raw_log_enabled"

    # Create log directory within consolidated volume
    mkdir -p "$LOG_DIR"
    chown nginx:nginx "$LOG_DIR"

    # Always set up stdout/stderr for Docker logging (LogCollector needs this)
    # These go to the legacy location for nginx's default config
    rm -f "$LEGACY_LOG_DIR/access.log" "$LEGACY_LOG_DIR/error.log" 2>/dev/null || true
    ln -sf /dev/stdout "$LEGACY_LOG_DIR/access.log"
    ln -sf /dev/stderr "$LEGACY_LOG_DIR/error.log"
    echo "[Entrypoint] Docker log forwarding configured (stdout/stderr)"

    if [ "$raw_log_enabled" = "true" ]; then
        # Create ADDITIONAL log files for raw storage in consolidated volume
        echo "[Entrypoint] Setting up additional raw log files in $LOG_DIR..."
        touch "$LOG_DIR/access_raw.log" "$LOG_DIR/error_raw.log"
        chown nginx:nginx "$LOG_DIR/access_raw.log" "$LOG_DIR/error_raw.log"
        chmod 644 "$LOG_DIR/access_raw.log" "$LOG_DIR/error_raw.log"

        # Migrate old logs from legacy location if they exist
        if [ -f "$LEGACY_LOG_DIR/access_raw.log" ] && [ ! -L "$LEGACY_LOG_DIR/access_raw.log" ]; then
            echo "[Entrypoint] Migrating existing raw logs to consolidated volume..."
            mv "$LEGACY_LOG_DIR/access_raw.log"* "$LOG_DIR/" 2>/dev/null || true
            mv "$LEGACY_LOG_DIR/error_raw.log"* "$LOG_DIR/" 2>/dev/null || true
        fi

        # Create nginx config to enable dual logging (using consolidated volume path)
        cat > /etc/nginx/conf.d/00-raw-logging.conf << 'RAWLOG'
# Raw log file storage (in addition to stdout/stderr)
# Auto-generated by entrypoint - do not edit manually
# Logs stored in /etc/nginx/logs for API access via consolidated volume

# Additional access log to file (main format)
access_log /etc/nginx/logs/access_raw.log main;

# Note: error_log can only have one destination in nginx main context
# For error logs, we log to both via Dockerfile symlink trick is not possible
# Error logs are captured from stderr which goes to error.log -> /dev/stderr
RAWLOG
        echo "[Entrypoint] Dual logging nginx config created"

        # Setup logrotate for raw log files
        if [ -f "/etc/nginx/conf.d/.logrotate.conf" ]; then
            cp /etc/nginx/conf.d/.logrotate.conf "$LOGROTATE_CONFIG"
            # Update paths in logrotate config
            sed -i "s|/var/log/nginx|$LOG_DIR|g" "$LOGROTATE_CONFIG"
            echo "[Entrypoint] Logrotate configuration installed from volume"
        else
            # Create default logrotate config for raw logs only
            cat > "$LOGROTATE_CONFIG" << LOGROTATE
$LOG_DIR/access_raw.log $LOG_DIR/error_raw.log {
    size 100M
    rotate 5
    missingok
    notifempty
    create 0644 nginx nginx
    sharedscripts
    compress
    delaycompress
    postrotate
        [ -f /var/run/nginx.pid ] && kill -USR1 \$(cat /var/run/nginx.pid) 2>/dev/null || true
    endscript
}
LOGROTATE
            echo "[Entrypoint] Default logrotate configuration created"
        fi

        # Run logrotate once to ensure state is initialized
        logrotate -s /var/lib/logrotate.status "$LOGROTATE_CONFIG" 2>/dev/null || true
    else
        # Remove raw logging config if exists
        rm -f /etc/nginx/conf.d/00-raw-logging.conf 2>/dev/null || true
        rm -f "$LOGROTATE_CONFIG" 2>/dev/null || true
        echo "[Entrypoint] Raw logging disabled, using stdout/stderr only"
    fi
}

# Initialize nginx volume if empty (when mounted as consolidated volume)
initialize_nginx_volume

# Always update static HTML files from default (for new features like font support)
update_static_html() {
    echo "[Entrypoint] Updating static HTML files from defaults..."
    if [ -d "$NGINX_DEFAULT/html" ]; then
        cp -f "$NGINX_DEFAULT/html/"*.html "$NGINX_DIR/html/" 2>/dev/null || true
        cp -f "$NGINX_DEFAULT/html/"*.ico "$NGINX_DIR/html/" 2>/dev/null || true
        chmod 644 "$NGINX_DIR/html/"*.html 2>/dev/null || true
        echo "[Entrypoint] Static HTML files updated"
    fi
}
update_static_html

# Run GeoIP update if script exists and license key is provided
if [ -x /scripts/geoip-update.sh ]; then
    echo "[Entrypoint] Running GeoIP database update..."
    /scripts/geoip-update.sh || echo "[Entrypoint] GeoIP update failed, continuing without GeoIP"
fi

# Setup GeoIP configuration based on available databases
setup_geoip_config

# Setup log files based on raw log configuration
setup_log_files

# Create required directories
mkdir -p /var/cache/nginx/proxy
mkdir -p /tmp/modsecurity/tmp
mkdir -p /tmp/modsecurity/data
mkdir -p /tmp/modsecurity/upload
mkdir -p /var/www/acme-challenge

# Set permissions
chown -R nginx:nginx /var/cache/nginx /tmp/modsecurity /var/www/acme-challenge 2>/dev/null || true

# Update internal status server port based on NGINX_HTTP_PORT
# This is needed for host network mode where a custom port is used
update_status_port() {
    local status_port="${NGINX_HTTP_PORT:-80}"
    local nginx_conf="/etc/nginx/nginx.conf"

    # Update the status server listen port to match NGINX_HTTP_PORT
    # The status server shares the HTTP port for /health and /nginx_status
    # Handle both old (8080) and new (80) default ports
    if [ "$status_port" != "80" ]; then
        # Update from 80 or 8080 to the custom port
        # Note: nginx.conf only has one "listen 80;" in the status server block
        if grep -q "listen 80;" "$nginx_conf" 2>/dev/null; then
            echo "[Entrypoint] Updating internal status server port from 80 to $status_port..."
            sed -i "s/listen 80;/listen $status_port;/" "$nginx_conf"
        elif grep -q "listen 8080;" "$nginx_conf" 2>/dev/null; then
            echo "[Entrypoint] Updating internal status server port from 8080 to $status_port..."
            sed -i "s/listen 8080;/listen $status_port;/" "$nginx_conf"
        fi
    else
        # Revert 8080 to 80 if NGINX_HTTP_PORT is default
        if grep -q "listen 8080;" "$nginx_conf" 2>/dev/null; then
            echo "[Entrypoint] Updating internal status server port from 8080 to 80..."
            sed -i "s/listen 8080;/listen 80;/" "$nginx_conf"
        fi
    fi
}
update_status_port

# Test nginx configuration
echo "[Entrypoint] Testing nginx configuration..."
if nginx -t; then
    echo "[Entrypoint] Nginx configuration OK"
else
    echo "[Entrypoint] Nginx configuration test failed!"
    exit 1
fi

echo "[Entrypoint] Starting nginx..."
exec nginx -g "daemon off;"
