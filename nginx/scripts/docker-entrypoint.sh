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

# Main nginx.conf is owned by the API — it is regenerated from the
# global_settings table on every startup and on every Global Settings save
# (issue #121). The image ships a conservative baseline so nginx can come up
# on the very first boot (before the API has ever run); on subsequent boots
# the API-generated file already exists and must be preserved so operator
# customisations stick.
ensure_main_nginx_conf() {
    local default_conf="$NGINX_DEFAULT/nginx.conf"
    local current_conf="$NGINX_DIR/nginx.conf"
    if [ ! -f "$default_conf" ]; then
        return
    fi
    if [ ! -f "$current_conf" ]; then
        echo "[Entrypoint] Seeding nginx.conf from image default (first boot)"
        cp -f "$default_conf" "$current_conf"
        chmod 644 "$current_conf"
    fi
}
ensure_main_nginx_conf

# Always update ModSecurity configs from defaults (for security fixes and CRS global loading)
update_modsec_configs() {
    if [ -f "$NGINX_DEFAULT/modsec/modsec-base.conf" ]; then
        echo "[Entrypoint] Updating ModSecurity base config from defaults..."
        cp -f "$NGINX_DEFAULT/modsec/modsec-base.conf" "$NGINX_DIR/modsec/modsec-base.conf" 2>/dev/null || true
        chown nginx:nginx "$NGINX_DIR/modsec/modsec-base.conf" 2>/dev/null || true
        chmod 644 "$NGINX_DIR/modsec/modsec-base.conf" 2>/dev/null || true
        echo "[Entrypoint] ModSecurity base config updated"
    fi
    if [ -f "$NGINX_DEFAULT/modsec/crs-global.conf" ]; then
        echo "[Entrypoint] Updating CRS global config from defaults..."
        cp -f "$NGINX_DEFAULT/modsec/crs-global.conf" "$NGINX_DIR/modsec/crs-global.conf" 2>/dev/null || true
        chown nginx:nginx "$NGINX_DIR/modsec/crs-global.conf" 2>/dev/null || true
        chmod 644 "$NGINX_DIR/modsec/crs-global.conf" 2>/dev/null || true
        echo "[Entrypoint] CRS global config updated"
    fi
}
update_modsec_configs

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

# Clean up stale temp files from previous runs (orphaned by crashes/interrupted transfers)
echo "[Entrypoint] Cleaning up stale temp files..."
find /etc/nginx/client_body_temp /etc/nginx/proxy_temp /etc/nginx/fastcgi_temp \
     /etc/nginx/uwsgi_temp /etc/nginx/scgi_temp \
     /tmp/modsecurity/tmp /tmp/modsecurity/upload \
     -type f -mmin +60 -delete 2>/dev/null || true

# Set permissions
chown -R nginx:nginx /var/cache/nginx /tmp/modsecurity /var/www/acme-challenge 2>/dev/null || true

# Background periodic cleanup of stale temp files (every hour)
(while true; do
    sleep 3600
    find /etc/nginx/client_body_temp /etc/nginx/proxy_temp /etc/nginx/fastcgi_temp \
         /etc/nginx/uwsgi_temp /etc/nginx/scgi_temp \
         /tmp/modsecurity/tmp /tmp/modsecurity/upload \
         -type f -mmin +60 -delete 2>/dev/null || true
done) &

# Test nginx configuration with auto-recovery
# If nginx -t fails, identify and disable the problematic config file,
# then retry. This prevents one broken host from taking down all hosts.
test_and_recover_nginx() {
    local max_retries=20
    local retry=0
    local disabled_count=0

    while [ $retry -lt $max_retries ]; do
        local test_output
        test_output=$(nginx -t 2>&1)

        if [ $? -eq 0 ]; then
            if [ $disabled_count -gt 0 ]; then
                echo "[Entrypoint] WARNING: Nginx started with $disabled_count config(s) disabled."
                echo "[Entrypoint] Disabled configs will be regenerated when the API syncs on startup."
                ls /etc/nginx/conf.d/*.disabled 2>/dev/null | while read f; do
                    echo "[Entrypoint]   - $(basename "$f")"
                done
            fi
            return 0
        fi

        # Try to identify the problematic config file
        local problem_conf=""

        # Method 1: Config file referenced directly in error
        # e.g. "in /etc/nginx/conf.d/proxy_host_foo.conf:10"
        problem_conf=$(echo "$test_output" | sed -n 's|.*in /etc/nginx/conf\.d/\([^:]*\.conf\).*|\1|p' | head -1)

        # Method 2: Extract missing resource path, find which config references it
        if [ -z "$problem_conf" ]; then
            local problem_path=""
            # Missing SSL certificate
            problem_path=$(echo "$test_output" | sed -n 's|.*cannot load certificate "\([^"]*\)".*|\1|p' | head -1)
            # Missing SSL key
            [ -z "$problem_path" ] && problem_path=$(echo "$test_output" | sed -n 's|.*cannot load certificate key "\([^"]*\)".*|\1|p' | head -1)
            # Missing file (open() failed)
            [ -z "$problem_path" ] && problem_path=$(echo "$test_output" | sed -n 's|.*open() "\([^"]*\)" failed.*|\1|p' | head -1)

            if [ -n "$problem_path" ]; then
                local found_file
                found_file=$(grep -l "$problem_path" /etc/nginx/conf.d/*.conf 2>/dev/null | head -1)
                [ -n "$found_file" ] && problem_conf=$(basename "$found_file")
            fi
        fi

        # Safety: only auto-disable host configs, not system configs
        case "$problem_conf" in
            proxy_host_*|redirect_host_*)
                echo "[Entrypoint] Disabling broken config: $problem_conf"
                mv "/etc/nginx/conf.d/$problem_conf" "/etc/nginx/conf.d/$problem_conf.disabled"
                disabled_count=$((disabled_count + 1))
                retry=$((retry + 1))
                ;;
            *)
                echo "[Entrypoint] Nginx config test failed (non-host config issue):"
                echo "$test_output"
                return 1
                ;;
        esac
    done

    echo "[Entrypoint] Too many broken configs ($max_retries), aborting."
    return 1
}

echo "[Entrypoint] Testing nginx configuration..."
if test_and_recover_nginx; then
    echo "[Entrypoint] Nginx configuration OK"
else
    echo "[Entrypoint] Nginx configuration test failed!"
    exit 1
fi

echo "[Entrypoint] Starting nginx..."
exec nginx -g "daemon off;"
