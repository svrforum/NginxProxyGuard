# Build stage
FROM node:24-alpine AS builder

WORKDIR /app

# Copy package files
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy source (only needed files)
COPY index.html vite.config.ts tsconfig*.json tailwind.config.js postcss.config.js ./
COPY public/ ./public/
COPY src/ ./src/

# Build
RUN npm run build

# Runtime stage
FROM nginx:alpine

# Install openssl for certificate generation
RUN apk add --no-cache openssl

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

EXPOSE 443

ENTRYPOINT ["/docker-entrypoint.sh"]
