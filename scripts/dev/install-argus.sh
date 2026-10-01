#!/usr/bin/env bash
set -euo pipefail

GOBIN="${GOBIN:-$(go env GOPATH)/bin}"
mkdir -p "$GOBIN"

if command -v argus >/dev/null 2>&1; then
    exit 0
fi

TMP_DIR=$(mktemp -d)
trap 'rm -rf "$TMP_DIR"' EXIT

git clone --depth 1 https://github.com/bonjoski/argus.git "$TMP_DIR" >/dev/null 2>&1
(cd "$TMP_DIR" && go build -o "$GOBIN/argus" ./cmd/argus)
chmod +x "$GOBIN/argus"
