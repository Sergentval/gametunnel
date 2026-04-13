#!/bin/sh
set -e

# GameTunnel installer
# Usage: curl -fsSL https://raw.githubusercontent.com/Sergentval/gametunnel/main/install.sh | sh

REPO="Sergentval/gametunnel"
INSTALL_DIR="/usr/local/bin"
BINARY="gametunnel"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64|amd64) ARCH="amd64" ;;
    aarch64|arm64) ARCH="arm64" ;;
    *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
esac

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
if [ "$OS" != "linux" ]; then
    echo "GameTunnel only supports Linux. Detected: $OS"
    exit 1
fi

# Get latest version
echo "Fetching latest release..."
VERSION=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
if [ -z "$VERSION" ]; then
    echo "Could not determine latest version. Install manually from:"
    echo "  https://github.com/$REPO/releases"
    exit 1
fi

# Download
FILENAME="${BINARY}_${VERSION#v}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/$REPO/releases/download/$VERSION/$FILENAME"

echo "Downloading $BINARY $VERSION for $OS/$ARCH..."
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

curl -fsSL "$URL" -o "$TMP/$FILENAME"
tar -xzf "$TMP/$FILENAME" -C "$TMP"

# Install
if [ -w "$INSTALL_DIR" ]; then
    cp "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
else
    echo "Installing to $INSTALL_DIR (requires sudo)..."
    sudo cp "$TMP/$BINARY" "$INSTALL_DIR/$BINARY"
fi

chmod +x "$INSTALL_DIR/$BINARY"

echo ""
echo "GameTunnel $VERSION installed to $INSTALL_DIR/$BINARY"
echo ""
echo "Quick start:"
echo "  gametunnel server init        # On VPS"
echo "  gametunnel server token create home-1"
echo "  gametunnel agent join <token>  # On home server"
