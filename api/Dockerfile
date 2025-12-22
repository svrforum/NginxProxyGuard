# Build stage
FROM golang:1.24-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files first for caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

# Build
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd/server

# Runtime stage
FROM alpine:3.23

WORKDIR /app

# Install CA certificates for HTTPS, Docker CLI for nginx management, and geoipupdate for MaxMind
RUN apk --no-cache add ca-certificates tzdata docker-cli \
    && wget -q https://github.com/maxmind/geoipupdate/releases/download/v7.0.1/geoipupdate_7.0.1_linux_amd64.tar.gz \
    && tar -xzf geoipupdate_7.0.1_linux_amd64.tar.gz \
    && mv geoipupdate_7.0.1_linux_amd64/geoipupdate /usr/local/bin/ \
    && rm -rf geoipupdate_7.0.1_linux_amd64* \
    && chmod +x /usr/local/bin/geoipupdate

# Copy binary from builder
COPY --from=builder /app/server .

# Copy assets (favicon, etc.)
COPY assets/ ./assets/

# Copy entrypoint script for Docker API version auto-detection
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# Expose port
EXPOSE 8080

# Run with entrypoint for Docker API version compatibility
ENTRYPOINT ["./entrypoint.sh"]
