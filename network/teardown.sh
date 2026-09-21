#!/usr/bin/env bash
# Tears down the local Fabric test network brought up by bootstrap.sh.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SAMPLES_DIR="${SCRIPT_DIR}/vendor/fabric-samples"

if [ ! -d "${SAMPLES_DIR}/test-network" ]; then
    echo "No vendored fabric-samples checkout found at ${SAMPLES_DIR}; nothing to tear down."
    exit 0
fi

cd "${SAMPLES_DIR}/test-network"
./network.sh down
