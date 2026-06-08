#!/usr/bin/env bash
set -euo pipefail

# Configuration
REPO="brawler2011/tuncli"
BINARY_NAME="tuncli"
INSTALL_DIR="/usr/local/bin"

# Check OS
OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
if [ "$OS" != "linux" ]; then
    echo "Error: Only Linux is supported." >&2
    exit 1
fi

# Detect Architecture
ARCH="$(uname -m)"
case "$ARCH" in
    x86_64)
        ARCH_SUFFIX="amd64"
        ;;
    aarch64|arm64)
        ARCH_SUFFIX="arm64"
        ;;
    *)
        echo "Error: Unsupported architecture: $ARCH" >&2
        exit 1
esac

# Fetch latest release version from GitHub API
LATEST_TAG=$(curl -s "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name":' | sed -E 's/.*"([^"]+)".*/\1/')

if [ -z "$LATEST_TAG" ]; then
    echo "Error: Could not retrieve the latest release tag. Please ensure the repository is public and has releases." >&2
    exit 1
fi

# Download URL
TARBALL="tuncli-linux-${ARCH_SUFFIX}.tar.gz"
DOWNLOAD_URL="https://github.com/$REPO/releases/download/$LATEST_TAG/$TARBALL"

# Create a temporary directory
TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

curl -sSL -o "$TMP_DIR/$TARBALL" "$DOWNLOAD_URL"

tar -xzf "$TMP_DIR/$TARBALL" -C "$TMP_DIR"

# Request sudo if not root and install directory requires it
if [ "$EUID" -ne 0 ] && [ ! -w "$INSTALL_DIR" ]; then
    sudo install -Dm755 "$TMP_DIR/tuncli-linux-$ARCH_SUFFIX" "$INSTALL_DIR/$BINARY_NAME"
else
    install -Dm755 "$TMP_DIR/tuncli-linux-$ARCH_SUFFIX" "$INSTALL_DIR/$BINARY_NAME"
fi
