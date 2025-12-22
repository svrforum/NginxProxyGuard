#!/bin/sh
set -e

# Auto-detect Docker API version for compatibility with various Docker hosts
# This is especially important for Synology DSM which uses older Docker versions

if [ -z "$DOCKER_API_VERSION" ]; then
    # Try to detect the host Docker API version
    if [ -S /var/run/docker.sock ]; then
        # Query Docker daemon for its API version
        DETECTED_VERSION=$(docker version --format '{{.Server.APIVersion}}' 2>/dev/null || echo "")

        if [ -n "$DETECTED_VERSION" ]; then
            export DOCKER_API_VERSION="$DETECTED_VERSION"
            echo "[entrypoint] Auto-detected Docker API version: $DOCKER_API_VERSION"
        else
            # Fallback to a safe, widely-compatible version
            export DOCKER_API_VERSION="1.41"
            echo "[entrypoint] Could not detect Docker API version, using fallback: $DOCKER_API_VERSION"
        fi
    else
        echo "[entrypoint] Docker socket not available, skipping API version detection"
    fi
else
    echo "[entrypoint] Using configured Docker API version: $DOCKER_API_VERSION"
fi

# Execute the main application
exec ./server
