#!/usr/bin/env bash
set -euo pipefail

GOBIN="${GOBIN:-$(go env GOPATH)/bin}"
mkdir -p "$GOBIN"

if command -v argus >/dev/null 2>&1; then
    exit 0
fi

VERSION="0.5.0"
OS_RAW="$(uname -s)"
case "$OS_RAW" in
    Darwin*) OS="darwin" ;;
    Linux*)  OS="linux" ;;
    *)       echo "Unsupported OS: $OS_RAW" >&2; exit 1 ;;
esac

ARCH_RAW="$(uname -m)"
case "$ARCH_RAW" in
    x86_64|amd64) ARCH="amd64" ;;
    arm64|aarch64) ARCH="arm64" ;;
    *) echo "Unsupported ARCH: $ARCH_RAW" >&2; exit 1 ;;
esac

TARBALL="argus_${VERSION}_${OS}_${ARCH}.tar.gz"
URL="https://github.com/bonjoski/argus/releases/download/v${VERSION}/${TARBALL}"

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

echo "Downloading Argus v${VERSION} (${OS}/${ARCH})..."
curl -fsSL "$URL" -o "$TMP_DIR/$TARBALL"
tar -xzf "$TMP_DIR/$TARBALL" -C "$TMP_DIR"
cp "$TMP_DIR/argus" "$GOBIN/argus"
chmod +x "$GOBIN/argus"
echo "Argus installed to $GOBIN/argus"
