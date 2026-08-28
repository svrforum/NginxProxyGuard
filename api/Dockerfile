# Build stage
# Pinned to a stable patch release, and kept current, because the toolchain is
# what compiles the stdlib into the binary users run:
#   1.26.4/1.26.5 — GO-2026-5856 crypto/tls, GO-2026-5039 net/textproto,
#                   GO-2026-5037 crypto/x509, all confirmed reachable here by
#                   govulncheck (#211)
#   1.26.6        — crypto/tls, encoding/asn1, encoding/xml, html/template, net,
#                   net/http, net/url, and CVE-2026-56865 (sumdb tile forgery →
#                   GOSUMDB bypass and module-cache poisoning)
# Release candidates are refused on purpose: their tags are frozen rather than
# patched, so an RC that outranks the stable line silently drops these fixes.
# .github/dependabot.yml carries the matching ignore rule. (#245)
FROM golang:1.27.0-alpine AS builder

WORKDIR /app

# Install dependencies
RUN apk add --no-cache gcc musl-dev

# Copy go mod files first for caching — `go mod download` runs on its own
# layer so subsequent source-only changes don't re-pull the whole module
# graph (~80 deps, ~500 MB).
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

# Build. Intentionally NOT running `go mod tidy` here — tidy mutates go.sum
# from the source tree, which busts the mod-download cache layer on every
# code change. If go.mod/go.sum drift from the source, the build fails loud
# (which is what we want in CI) instead of silently rewriting committed deps.
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server ./cmd/server

# Runtime stage
FROM alpine:3.24

ARG TARGETARCH

WORKDIR /app

# Install CA certificates for HTTPS, Docker CLI for nginx management, and geoipupdate for MaxMind
RUN apk --no-cache add ca-certificates tzdata docker-cli \
    && wget -q https://github.com/maxmind/geoipupdate/releases/download/v7.0.1/geoipupdate_7.0.1_linux_${TARGETARCH}.tar.gz \
    && tar -xzf geoipupdate_7.0.1_linux_${TARGETARCH}.tar.gz \
    && mv geoipupdate_7.0.1_linux_${TARGETARCH}/geoipupdate /usr/local/bin/ \
    && rm -rf geoipupdate_7.0.1_linux_${TARGETARCH}* \
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

# --- Non-root hardening note (H8 / MEDIUM-8) --------------------------------
# This container is intentionally NOT switched to a non-root USER.
#
# The API needs read/write access to the mounted docker.sock to manage the
# nginx container (exec `nginx -t` / `nginx -s reload`, inspect status). The
# socket is owned by root and the host "docker" group, and that group's GID is
# host-specific (e.g. 999 on Debian, 100 on some NAS, etc.). Baking a fixed
# non-root user + matching group GID into the image would break docker.sock
# access on any host whose docker GID differs — the exact failure mode we must
# avoid (container starts but every nginx reload silently fails).
#
# Defense-in-depth is instead applied at the compose layer via
# `security_opt: no-new-privileges:true` (prevents privilege escalation even
# while running as root).
#
# RECOMMENDED FOLLOW-UP (out of scope for this bounded fix):
#   Put tecnativa/docker-socket-proxy in front of /var/run/docker.sock so the
#   API can only LIST / INSPECT / EXEC the nginx container and can NEVER create
#   or start new containers. With the proxy terminating the socket, the API can
#   then safely drop root (it talks HTTP to the proxy, no group GID needed).
#   See compose files for the matching sketch.

# Run with entrypoint for Docker API version compatibility
ENTRYPOINT ["./entrypoint.sh"]
