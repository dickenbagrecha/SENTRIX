#!/usr/bin/env bash
# ==============================================================================
# SENTRIX - ModSecurity Submodule Initialization Script (POSIX)
# Inspects and initializes required submodules in engines/ModSecurity-3-master
# ==============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
MODSEC_DIR="${ROOT_DIR}/engines/ModSecurity-3-master"

echo "=== Inspecting ModSecurity 3 Submodules ==="

if [ ! -d "${MODSEC_DIR}" ]; then
    echo "ERROR: ModSecurity directory not found at: ${MODSEC_DIR}"
    exit 1
fi

cd "${MODSEC_DIR}"

# Check submodule directory status
check_submodule() {
    local sub_path="$1"
    local full_path="${MODSEC_DIR}/${sub_path}"
    if [ -d "${full_path}" ] && [ "$(ls -A "${full_path}")" ]; then
        echo " [OK] Submodule directory '${sub_path}' is populated."
        return 0
    else
        echo " [WARN] Submodule directory '${sub_path}' is EMPTY."
        return 1
    fi
}

echo "Current status of known submodules:"
libinj_ok=0
mbedtls_ok=0

check_submodule "others/libinjection" || libinj_ok=1
check_submodule "others/mbedtls" || mbedtls_ok=1
check_submodule "bindings/python" || true
check_submodule "test/test-cases/secrules-language-tests" || true

if [ $libinj_ok -eq 0 ] && [ $mbedtls_ok -eq 0 ]; then
    echo "All mandatory submodules are already populated."
    exit 0
fi

echo ""
echo "Attempting to initialize git submodules..."
if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    git submodule update --init --recursive
    echo "Submodules initialized successfully."
else
    echo "NOTICE: Workspace is not a standalone git repository with active submodule pointers."
    echo "Cloning required dependencies directly into submodule stubs..."
    
    if [ ! "$(ls -A "${MODSEC_DIR}/others/libinjection")" ]; then
        echo "Cloning libinjection v4.0.0..."
        git clone --depth 1 -b v4.0.0 https://github.com/libinjection/libinjection.git "${MODSEC_DIR}/others/libinjection"
    fi

    if [ ! "$(ls -A "${MODSEC_DIR}/others/mbedtls")" ]; then
        echo "Cloning mbedtls (TF-PSA-Crypto subset)..."
        git clone --depth 1 -b v4.1.0 https://github.com/Mbed-TLS/mbedtls.git "${MODSEC_DIR}/others/mbedtls"
    fi
    echo "Required submodules successfully staged for ModSecurity."
fi
