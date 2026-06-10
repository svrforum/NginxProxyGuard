# Build stage
FROM node:24-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json .npmrc ./

# Install dependencies
RUN npm install

# Copy source (only needed files)
COPY index.html vite.config.ts tsconfig*.json ./
COPY public/ ./public/
COPY src/ ./src/

# Build
RUN npm run build

# Runtime stage
FROM nginx:alpine

# Install openssl for certificate generation. libcap is needed to grant the
# nginx binary CAP_NET_BIND_SERVICE so the non-root user below can still bind
# the privileged port 443.
RUN apk add --no-cache openssl libcap

# Copy built files
COPY --from=builder /app/dist /usr/share/nginx/html

# Fix permissions for static files
RUN chmod -R 644 /usr/share/nginx/html/*.svg /usr/share/nginx/html/*.ico 2>/dev/null || true \
    && chmod 755 /usr/share/nginx/html /usr/share/nginx/html/assets

# Copy nginx config
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy entrypoint script
COPY docker-entrypoint.sh /docker-entrypoint.sh
RUN chmod +x /docker-entrypoint.sh

# Create SSL directory
RUN mkdir -p /etc/nginx/ssl

# --- Non-root hardening (H8 / MEDIUM-8) -------------------------------------
# Run the UI nginx as the unprivileged "nginx" user (uid 101, present in the
# stock nginx:alpine image) instead of root. This is safe here because, unlike
# the proxy container, the UI has no docker.sock access and no host network.
#
# Three things must be writable / permitted for nginx to start non-root:
#   1. listen 443 (privileged port) — grant CAP_NET_BIND_SERVICE on the binary
#      so we don't need root just to bind the port. The compose layer also
#      cap_drops ALL and re-adds NET_BIND_SERVICE for defense in depth.
#   2. pid file + runtime/temp dirs — make them owned by nginx.
#   3. /etc/nginx/ssl — the entrypoint generates a self-signed cert here on
#      first boot, so it must be writable by nginx. (Note: this dir lives in
#      the image layer, not a volume — the ui_data volume is mounted at
#      /app/ssl and is intentionally left untouched by this change.)
RUN setcap 'cap_net_bind_service=+ep' /usr/sbin/nginx \
    && chown -R nginx:nginx /etc/nginx/ssl /var/cache/nginx \
    && touch /var/run/nginx.pid \
    && chown nginx:nginx /var/run/nginx.pid

USER nginx

EXPOSE 443

ENTRYPOINT ["/docker-entrypoint.sh"]
