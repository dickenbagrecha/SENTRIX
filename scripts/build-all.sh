#!/usr/bin/env bash
# ==============================================================================
# SENTRIX - Unified Build Orchestrator (POSIX)
# Builds Core and Docker images for all five engines
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "=== SENTRIX Unified Multi-Engine Build Orchestrator ==="

# 1. Build Core locally if Go is available
if command -v go >/dev/null 2>&1; then
    bash "${SCRIPT_DIR}/build-core.sh"
else
    echo "NOTICE: Native Go not found, Core will be built inside Docker."
fi

# 2. Check Docker daemon availability
if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running or unreachable."
    echo "Please start Docker to build containerized engine images."
    exit 1
fi

cd "${ROOT_DIR}"

echo "Building Docker images for SENTRIX stack..."
docker compose -f deploy/docker-compose.yml build --parallel

echo "=== Build orchestration complete ==="
