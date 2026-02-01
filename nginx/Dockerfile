# nginx-proxy-guard proxy with HTTP/3, ModSecurity v3, and OWASP CRS
# Built from source for full control and latest features
#
# Versions (2025):
# - nginx: 1.28.0 (stable with HTTP/3 QUIC support)
# - ModSecurity: 3.0.14
# - ModSecurity-nginx: 1.0.4
# - OWASP CRS: 4.20.0
#
# References:
# - https://nginx.org/en/docs/quic.html
# - https://github.com/owasp-modsecurity/ModSecurity
# - https://github.com/owasp-modsecurity/ModSecurity-nginx
# - https://github.com/coreruleset/coreruleset

ARG NGINX_VERSION=1.28.0
ARG MODSECURITY_VERSION=3.0.14
ARG MODSECURITY_NGINX_VERSION=1.0.4
ARG OWASP_CRS_VERSION=4.21.0

# =============================================================================
# Stage 1: Build Stage
# =============================================================================
FROM alpine:3.23 AS builder

ARG NGINX_VERSION
ARG MODSECURITY_VERSION
ARG MODSECURITY_NGINX_VERSION

# Install build dependencies
RUN apk add --no-cache \
    # Build tools
    autoconf \
    automake \
    build-base \
    cmake \
    git \
    libtool \
    linux-headers \
    pkgconfig \
    # SSL/TLS
    openssl-dev \
    # Core libraries
    curl-dev \
    geoip-dev \
    libfuzzy2-dev \
    libmaxminddb-dev \
    libxml2-dev \
    lmdb-dev \
    pcre2-dev \
    yajl-dev \
    zlib-dev \
    # Additional
    lua5.3-dev \
    brotli-dev \
    zstd-dev

WORKDIR /build

# =============================================================================
# Build ModSecurity v3 (libmodsecurity)
# =============================================================================
# Note: CXXFLAGS include cstdint for GCC 15+ compatibility (Alpine 3.23+)
RUN echo "Building ModSecurity ${MODSECURITY_VERSION}..." \
    && git clone --depth 1 --branch v${MODSECURITY_VERSION} \
        https://github.com/owasp-modsecurity/ModSecurity.git \
    && cd ModSecurity \
    && git submodule init \
    && git submodule update \
    && ./build.sh \
    && CXXFLAGS="-include cstdint" ./configure \
        --with-yajl \
        --with-ssdeep \
        --with-lmdb \
        --with-geoip \
        --with-pcre2 \
        --enable-silent-rules \
    && make CXXFLAGS="-include cstdint" -j$(nproc) \
    && make install \
    && strip /usr/local/modsecurity/lib/libmodsecurity.so*

# =============================================================================
# Download and build nginx with ModSecurity module
# =============================================================================
RUN echo "Downloading nginx ${NGINX_VERSION}..." \
    && wget -q https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar -xzf nginx-${NGINX_VERSION}.tar.gz

RUN echo "Downloading ModSecurity-nginx connector ${MODSECURITY_NGINX_VERSION}..." \
    && git clone --depth 1 --branch v${MODSECURITY_NGINX_VERSION} \
        https://github.com/owasp-modsecurity/ModSecurity-nginx.git

# Download additional modules
RUN echo "Downloading additional modules..." \
    # Brotli compression
    && git clone --depth 1 https://github.com/google/ngx_brotli.git \
    && cd ngx_brotli && git submodule update --init && cd .. \
    # Headers More module
    && git clone --depth 1 https://github.com/openresty/headers-more-nginx-module.git \
    # GeoIP2 module
    && git clone --depth 1 https://github.com/leev/ngx_http_geoip2_module.git

# Build nginx with all modules
RUN cd nginx-${NGINX_VERSION} \
    && ./configure \
        --prefix=/etc/nginx \
        --sbin-path=/usr/sbin/nginx \
        --modules-path=/usr/lib/nginx/modules \
        --conf-path=/etc/nginx/nginx.conf \
        --error-log-path=/var/log/nginx/error.log \
        --http-log-path=/var/log/nginx/access.log \
        --pid-path=/var/run/nginx.pid \
        --lock-path=/var/run/nginx.lock \
        # HTTP/3 QUIC support
        --with-http_v3_module \
        # Standard modules
        --with-http_ssl_module \
        --with-http_v2_module \
        --with-http_realip_module \
        --with-http_addition_module \
        --with-http_sub_module \
        --with-http_dav_module \
        --with-http_flv_module \
        --with-http_mp4_module \
        --with-http_gunzip_module \
        --with-http_gzip_static_module \
        --with-http_random_index_module \
        --with-http_secure_link_module \
        --with-http_stub_status_module \
        --with-http_auth_request_module \
        --with-http_slice_module \
        # Stream modules (for TCP/UDP proxying)
        --with-stream \
        --with-stream_ssl_module \
        --with-stream_ssl_preread_module \
        --with-stream_realip_module \
        # Performance
        --with-threads \
        --with-file-aio \
        --with-compat \
        --with-pcre-jit \
        # Dynamic modules
        --add-dynamic-module=/build/ModSecurity-nginx \
        --add-dynamic-module=/build/ngx_brotli \
        --add-dynamic-module=/build/headers-more-nginx-module \
        --add-dynamic-module=/build/ngx_http_geoip2_module \
        # Build options
        --with-cc-opt='-O2 -fstack-protector-strong -Wformat -Werror=format-security -fPIC -D_FORTIFY_SOURCE=2' \
        --with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie' \
    && make -j$(nproc) \
    && make install \
    && strip /usr/sbin/nginx \
    && strip /usr/lib/nginx/modules/*.so

# =============================================================================
# Download OWASP CRS
# =============================================================================
ARG OWASP_CRS_VERSION
RUN echo "Downloading OWASP CRS ${OWASP_CRS_VERSION}..." \
    && wget -q https://github.com/coreruleset/coreruleset/archive/refs/tags/v${OWASP_CRS_VERSION}.tar.gz \
    && tar -xzf v${OWASP_CRS_VERSION}.tar.gz \
    && mv coreruleset-${OWASP_CRS_VERSION} /etc/nginx/owasp-crs \
    && cp /etc/nginx/owasp-crs/crs-setup.conf.example /etc/nginx/owasp-crs/crs-setup.conf

# =============================================================================
# Stage 2: Runtime Stage
# =============================================================================
FROM alpine:3.23

ARG TARGETARCH

LABEL maintainer="nginx-proxy-guard"
LABEL description="nginx with HTTP/3, ModSecurity v3, and OWASP CRS"
LABEL nginx.version="${NGINX_VERSION}"
LABEL modsecurity.version="${MODSECURITY_VERSION}"
LABEL owasp-crs.version="${OWASP_CRS_VERSION}"

# Install runtime dependencies
RUN apk add --no-cache \
    # SSL/TLS
    openssl \
    # Runtime libraries
    curl \
    geoip \
    libfuzzy2 \
    libmaxminddb \
    libstdc++ \
    libxml2 \
    lmdb \
    lua5.3-libs \
    pcre2 \
    yajl \
    zlib \
    # Compression
    brotli-libs \
    zstd-libs \
    # Utilities
    tzdata \
    ca-certificates \
    # Log rotation
    logrotate

# Install geoipupdate from edge/testing repository
RUN apk add --no-cache --repository=https://dl-cdn.alpinelinux.org/alpine/edge/testing geoipupdate || \
    (echo "geoipupdate not available, installing manually..." && \
     wget -q https://github.com/maxmind/geoipupdate/releases/download/v7.0.1/geoipupdate_7.0.1_linux_${TARGETARCH}.tar.gz && \
     tar -xzf geoipupdate_7.0.1_linux_${TARGETARCH}.tar.gz && \
     mv geoipupdate_7.0.1_linux_${TARGETARCH}/geoipupdate /usr/local/bin/ && \
     chmod +x /usr/local/bin/geoipupdate && \
     rm -rf geoipupdate_7.0.1_linux_${TARGETARCH}*)

# Create nginx user and directories
RUN addgroup -g 101 -S nginx \
    && adduser -S -D -H -u 101 -h /var/cache/nginx -s /sbin/nologin -G nginx -g nginx nginx \
    && mkdir -p \
        /etc/nginx/conf.d \
        /etc/nginx/certs \
        /etc/nginx/includes \
        /etc/nginx/modsec \
        /etc/nginx/owasp-crs \
        /etc/nginx/geoip \
        /etc/nginx/acme-challenge \
        /etc/nginx.default \
        /var/log/nginx \
        /var/log/modsec \
        /var/cache/nginx \
        /tmp/modsecurity/tmp \
        /tmp/modsecurity/data \
        /tmp/modsecurity/upload \
        /scripts \
        /etc/logrotate.d \
    && chown -R nginx:nginx /var/log/nginx /var/cache/nginx /tmp/modsecurity
    # Note: Log symlinks are now configured by entrypoint based on settings
    # Default is stdout/stderr for Docker logging

# Copy nginx from builder
COPY --from=builder /usr/sbin/nginx /usr/sbin/nginx
COPY --from=builder /usr/lib/nginx/modules /usr/lib/nginx/modules
COPY --from=builder /etc/nginx/mime.types /etc/nginx/mime.types
COPY --from=builder /etc/nginx/fastcgi_params /etc/nginx/fastcgi_params
COPY --from=builder /etc/nginx/scgi_params /etc/nginx/scgi_params
COPY --from=builder /etc/nginx/uwsgi_params /etc/nginx/uwsgi_params

# Copy ModSecurity library
COPY --from=builder /usr/local/modsecurity/lib/libmodsecurity.so* /usr/local/lib/
RUN ldconfig /usr/local/lib || true

# Copy ModSecurity unicode mapping file
COPY --from=builder /build/ModSecurity/unicode.mapping /etc/nginx/modsec/unicode.mapping

# Copy OWASP CRS
COPY --from=builder /etc/nginx/owasp-crs /etc/nginx/owasp-crs

# Copy nginx configuration
COPY nginx.conf /etc/nginx/nginx.conf
COPY conf.d/default.conf /etc/nginx/conf.d/default.conf
COPY conf.d/logging.conf /etc/nginx/conf.d/logging.conf

# Copy GeoIP config files to geoip directory (not conf.d to avoid auto-include)
COPY conf.d/geoip.conf /etc/nginx/geoip/geoip-enabled.conf
COPY conf.d/geoip-disabled.conf /etc/nginx/geoip/geoip-disabled.conf

# Default to disabled GeoIP (entrypoint will switch if databases available)
RUN ln -sf /etc/nginx/geoip/geoip-disabled.conf /etc/nginx/geoip/geoip-active.conf

# Copy include files
COPY includes/ /etc/nginx/includes/

# Copy ModSecurity configuration
COPY modsec/ /etc/nginx/modsec/

# Copy custom error pages and welcome page
COPY html/ /etc/nginx/html/
RUN mkdir -p /usr/share/nginx && ln -sf /etc/nginx/html /usr/share/nginx/html

# Copy scripts
COPY scripts/ /scripts/
RUN chmod +x /scripts/*.sh

# Set permissions
RUN chown -R nginx:nginx /etc/nginx/conf.d /etc/nginx/certs /etc/nginx/modsec /etc/nginx/html /etc/nginx/geoip \
    && chmod -R 644 /etc/nginx/html/*.html

# Backup default nginx configuration for volume initialization
# When a volume is mounted at /etc/nginx, entrypoint will copy these defaults if nginx.conf is missing
RUN cp -a /etc/nginx/. /etc/nginx.default/

# Expose ports (80 HTTP, 443 HTTPS/HTTP3)
EXPOSE 80 443/tcp 443/udp

# Health check
HEALTHCHECK --interval=30s --timeout=10s --retries=3 \
    CMD curl -f http://localhost/health || exit 1

# Start nginx via entrypoint (handles GeoIP updates)
STOPSIGNAL SIGQUIT
ENTRYPOINT ["/scripts/docker-entrypoint.sh"]
