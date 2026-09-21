#!/usr/bin/env bash
# Bootstraps a local Hyperledger Fabric test network for the Fase 1 spike:
# vendors a pinned fabric-samples checkout, installs pinned Fabric/CA
# binaries+images, brings up the 2-org test network, creates a channel, and
# deploys both chaincodes (transaction, asset).
#
# Per PRD §11 "Aturan pengambilan kode": pin to a specific commit, not an
# uncontrolled `main`. fabric-samples stopped tagging releases after v2.4.9
# (confirmed against the actual repo, not guessed) even though Fabric itself
# moved to the 3.x line, so `main` is pinned by commit SHA instead of a tag.
#
# Versions pinned as of 2026-09-17 (see docs/adr/0001-fase1-spike-scope.md):
#   fabric-samples commit : 8fa2cccb204529690a91a7358a4a1a48db9268be (main)
#   Fabric binaries/images: 2.5.16 (LTS line; install-fabric.sh's own default)
#   Fabric CA             : 1.5.17 (install-fabric.sh's own default)
set -euo pipefail

FABRIC_SAMPLES_COMMIT="8fa2cccb204529690a91a7358a4a1a48db9268be"
FABRIC_VERSION="2.5.16"
FABRIC_CA_VERSION="1.5.17"
CHANNEL_NAME="ledgerchannel"
TX_CHAINCODE_NAME="transaction"
ASSET_CHAINCODE_NAME="asset"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENDOR_DIR="${SCRIPT_DIR}/vendor"
SAMPLES_DIR="${VENDOR_DIR}/fabric-samples"

# Everything below assumes cwd == SCRIPT_DIR (matters for the install-fabric.sh
# download, which curl -O writes to the current directory).
cd "${SCRIPT_DIR}"

# NOTE: an earlier version of this script pointed DOCKER_HOST at Docker
# Desktop's WSL-integration proxy socket to dodge a *different* problem (a
# WSL distro's own native dockerd getting killed periodically by
# VPN/security-agent policy enforcement on some machines). That is NOT used
# here: Docker Desktop's engine runs in a separate VM with its own
# filesystem namespace, and this script's bind mounts (crypto material
# exchanged between the CLI tools and containers) are host paths as *this
# shell* sees them — across that VM boundary they silently resolve to an
# empty/wrong location, so CA containers never actually persist their certs
# where the CLI tools look for them. Bind-mount-heavy scripts like this one
# need the docker CLI and the containers on the *same* filesystem view, so
# this intentionally uses whatever dockerd is native to this shell.

echo "== 1/5: fetching pinned fabric-samples (commit ${FABRIC_SAMPLES_COMMIT}) =="
mkdir -p "${VENDOR_DIR}"
if [ ! -d "${SAMPLES_DIR}" ]; then
    # -c core.autocrlf=false: if this ever runs somewhere with Windows git's
    # global core.autocrlf=true (e.g. Git Bash), autocrlf would rewrite every
    # checked-out file to CRLF, which breaks native execution of network.sh
    # and friends (shebang lines like "#!/usr/bin/env bash\r" fail to
    # resolve) if this checkout is later used from a real Linux shell (WSL).
    # This bit us during development — see the repo's build notes.
    git clone -c core.autocrlf=false https://github.com/hyperledger/fabric-samples "${SAMPLES_DIR}"
fi
git -C "${SAMPLES_DIR}" fetch origin "${FABRIC_SAMPLES_COMMIT}" --depth=1 2>/dev/null || git -C "${SAMPLES_DIR}" fetch origin
git -C "${SAMPLES_DIR}" checkout "${FABRIC_SAMPLES_COMMIT}"

echo "== 2/5: installing pinned Fabric ${FABRIC_VERSION} / CA ${FABRIC_CA_VERSION} binaries + docker images =="
# install-fabric.sh names the binary peer.exe on Windows, peer elsewhere; it
# also needs to have placed the ../config directory network.sh expects.
if { [ ! -x "${SAMPLES_DIR}/bin/peer" ] && [ ! -x "${SAMPLES_DIR}/bin/peer.exe" ]; } || [ ! -d "${SAMPLES_DIR}/config" ]; then
    curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
    chmod +x install-fabric.sh
    (cd "${SAMPLES_DIR}" && "${SCRIPT_DIR}/install-fabric.sh" --fabric-version "${FABRIC_VERSION}" --ca-version "${FABRIC_CA_VERSION}" docker binary)
    rm -f install-fabric.sh
fi

export PATH="${SAMPLES_DIR}/bin:${PATH}"
export FABRIC_CFG_PATH="${SAMPLES_DIR}/config"

echo "== 3/5: bringing up the 2-org test network and creating channel '${CHANNEL_NAME}' =="
cd "${SAMPLES_DIR}/test-network"
# MSYS_NO_PATHCONV=1 only around network.sh: it shells out to
# docker-compose, and Git Bash's automatic path conversion mangles
# container-side volume paths like "/var/hyperledger/production" into
# host paths (e.g. "C:\Program Files\Git\var"), which then fails with an
# access-denied mkdir error. Scoped to just these calls (not the whole
# script) because the same conversion is *required* for the plain `git`
# and Fabric binary invocations above/below to understand POSIX-style
# paths at all.
MSYS_NO_PATHCONV=1 ./network.sh up createChannel -c "${CHANNEL_NAME}" -ca

echo "== 4/5: deploying transaction chaincode =="
MSYS_NO_PATHCONV=1 ./network.sh deployCC \
    -c "${CHANNEL_NAME}" \
    -ccn "${TX_CHAINCODE_NAME}" \
    -ccp "${REPO_ROOT}/chaincode/transaction" \
    -ccl go

echo "== 5/5: deploying asset chaincode =="
MSYS_NO_PATHCONV=1 ./network.sh deployCC \
    -c "${CHANNEL_NAME}" \
    -ccn "${ASSET_CHAINCODE_NAME}" \
    -ccp "${REPO_ROOT}/chaincode/asset" \
    -ccl go

echo "Network up. Channel: ${CHANNEL_NAME}; chaincodes: ${TX_CHAINCODE_NAME}, ${ASSET_CHAINCODE_NAME}."
echo "Connection profiles for the API/indexer/audit-service are under ${SAMPLES_DIR}/test-network/organizations/."
