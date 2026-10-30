#!/usr/bin/env bash
# ==============================================================================
# SENTRIX - Core Build Script (POSIX)
# Compiles sentrixd orchestrator daemon and sentrix-waf reverse proxy
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
CORE_DIR="${ROOT_DIR}/core"
BIN_DIR="${ROOT_DIR}/bin"

mkdir -p "${BIN_DIR}"

echo "=== Building SENTRIX Core Binaries ==="

if ! command -v go >/dev/null 2>&1; then
    echo "ERROR: 'go' toolchain is not found in PATH."
    echo "Please install Go 1.24+ or build via Docker: docker build -f deploy/docker/Dockerfile.core ."
    exit 1
fi

cd "${CORE_DIR}"

echo "Compiling sentrixd daemon..."
go build -ldflags="-w -s" -o "${BIN_DIR}/sentrixd" ./cmd/sentrixd
echo " [OK] Built ${BIN_DIR}/sentrixd"

echo "Compiling sentrix-waf proxy..."
go build -ldflags="-w -s" -o "${BIN_DIR}/sentrix-waf" ./cmd/sentrix-waf
echo " [OK] Built ${BIN_DIR}/sentrix-waf"

echo ""
echo "Running Core unit tests..."
go test -v ./tests/...

echo "=== SENTRIX Core build complete ==="
