#!/usr/bin/env bash
# ==============================================================================
# SENTRIX - Development Cluster Runner (POSIX)
# Launches lightweight dev profile (Core, Coraza WAF, CrowdSec, Promptfoo)
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${ROOT_DIR}"

echo "=== Launching SENTRIX Development Cluster ==="
echo "Services included: sentrix-core, sentrix-waf-coraza, sentrix-crowdsec, sentrix-promptfoo"

if ! docker info >/dev/null 2>&1; then
    echo "ERROR: Docker daemon is not running."
    exit 1
fi

docker compose -f deploy/docker-compose.yml -f deploy/docker-compose.dev.yml up -d

echo ""
echo "=== SENTRIX Development Cluster Started ==="
echo " • Ingress WAF Proxy: http://localhost:8080"
echo " • SENTRIX Core API:  http://localhost:9000/api/v1/health"
echo " • CrowdSec LAPI:     http://localhost:8085/v1/health"
echo " • Promptfoo Web UI:  http://localhost:15500"
echo ""
echo "View logs using: docker compose -f deploy/docker-compose.yml logs -f"
