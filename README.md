# Hybrid PQC Permissioned Ledger — Fase 1 Technical Spike

Internal transaction / asset-custody ledger built on Hyperledger Fabric, with
hybrid post-quantum signatures (Ed25519 + ML-DSA-65) and a PostgreSQL
operational read model. This is the **Fase 1 technical spike** described in
[docs/Hybrid_PQC_Permissioned_Blockchain_PRD.md](docs/Hybrid_PQC_Permissioned_Blockchain_PRD.md)
— see [docs/adr/0001-fase1-spike-scope.md](docs/adr/0001-fase1-spike-scope.md)
for exactly what is and isn't in scope. **This is not production-ready**: no
real KMS/HSM, no SSO, no HA, no encryption-at-rest hardening. Do not point it
at real data.

## Status

- [x] M0 — repo scaffold
- [x] M1 — Postgres schema + migrations, Docker Compose (Postgres + MinIO)
- [x] M2 — crypto module (hybrid sign/verify, hybrid KEM, algorithm_suite) — real ML-DSA-65 round trip verified (3309-byte PQC signature + 64-byte Ed25519 signature)
- [x] M3 — Go chaincode (`transaction`, `asset`), unit-tested; Fabric test network bootstrapped and both chaincodes deployed
- [x] M4 — API service written and builds cleanly (transactions, assets, approvals, documents, outbox worker) — live end-to-end run pending
- [x] M5 — indexer written and builds cleanly (Fabric chaincode events → Postgres read model) — live end-to-end run pending
- [ ] M6 — audit-service written and builds cleanly; docker-compose wiring, smoke test, and benchmark script written — **not yet run against the live stack**

Implementation note: both post-quantum algorithms come from the **Go standard
library** — ML-KEM-768 (`crypto/mlkem`, since Go 1.24) and ML-DSA-65
(`crypto/mldsa`, since Go 1.27) — so every module here is pure Go, no cgo and no
liboqs. (An earlier revision used liboqs for ML-DSA on a mistaken reading of
the Go release notes; corrected in
[docs/adr/0001-fase1-spike-scope.md](docs/adr/0001-fase1-spike-scope.md), addendum.)

## TTD Digital (browser)

Digital signatures on PDF documents, using the mechanism of the owner's *PQC PDF Sign V1*
project (`ttd/`, provenance in [ttd/PROVENANCE.md](ttd/PROVENANCE.md)) but as a **browser
app instead of an .exe/Android app**: the Go signing core runs as WebAssembly in a Web
Worker, the ML-DSA-65 key is generated in the browser under a mandatory PIN and never
leaves it, and the server has no signing endpoint. Design and trade-offs:
[docs/adr/0002-ttd-browser.md](docs/adr/0002-ttd-browser.md),
[ttd/docs/threat-model-browser.md](ttd/docs/threat-model-browser.md).

```bash
# no Docker: lab CA + in-memory server, then open http://127.0.0.1:8099/app/
bash ttd/web/build.sh && bash ttd/tools/dev-up.sh          # shell 1
bash ttd/tools/dev-admin.sh                                # shell 2 -> user@local / user12345

# Docker (Postgres + API + CA): see ttd/deploy/local/README.md  -> http://localhost:18099/app/

# tests: real wasm under Node, and the real-Chrome end-to-end run
(cd ttd && node --test web/test/wasm.test.mjs)
(cd ttd/web/e2e && npm ci && node run.mjs)
```

Status: works end to end in a real browser against the lab CA (49 e2e checks). **Not
production**: lab (online) CA, no trusted timestamp, and anchoring signed-PDF hashes into the
Fabric ledger is not built yet (deferred by decision).

## Prerequisites

- Docker Desktop (Windows/Mac: host.docker.internal support is used to let
  api/indexer/audit-service reach the separately-managed Fabric test network)
- Go 1.27+ (crypto/chaincode/api/indexer/audit-service all build and test
  natively; Docker is only needed to run the full stack)
- Git Bash or WSL to run the `.sh` scripts (Windows: a stalled/very slow
  `curl`/`docker pull` usually means a VPN with an MTU below Docker's default
  1500 — see the `pqc-ledger-buildnet` note in `network/bootstrap.sh`'s
  history / this repo's build notes if downloads hang)
- `jq` on PATH

## Repository layout

```
docs/            PRD, ADRs
ttd/             digital signature (TTD): imported PQC PDF Sign core/server/CA + browser client (web/)
crypto/          hybrid signing/KEM library (Ed25519+ML-DSA-65, X25519+ML-KEM-768)
chaincode/       Fabric Go chaincode: transaction, asset
network/         Fabric test-network bootstrap + config
api/             REST API: transactions, assets, approvals, documents, outbox worker
indexer/         Fabric event listener -> Postgres read model
audit-service/   independent verification + checkpoints
migrations/      SQL schema
infra/           docker-compose for Postgres/MinIO/app services
scripts/         smoke-test.sh, bench.sh
```

## Quickstart

1. **Bring up the Fabric test network** (one-time, or after `network/teardown.sh`):
   ```bash
   bash network/bootstrap.sh
   ```
   This vendors a pinned `fabric-samples` checkout, installs pinned Fabric
   2.5.16 / CA 1.5.17 binaries + Docker images, brings up a 2-org test
   network, creates channel `ledgerchannel`, and deploys the `transaction`
   and `asset` chaincodes. Large downloads — expect several minutes.

2. **Bring up Postgres, MinIO, and the app services:**
   ```bash
   cd infra
   cp .env.example .env   # dev-only defaults; see the file's comment
   docker compose up -d --build
   ```
   This runs migrations automatically (the `migrate` one-shot service) and
   starts `api` (port 8080), `audit-service` (port 8081), and `indexer`.

3. **Run the end-to-end smoke test:**
   ```bash
   bash scripts/smoke-test.sh
   ```
   Exercises: create transaction → hybrid-sign an event → queue via the
   outbox → Fabric commit → indexer updates the read model → audit-service
   independently re-verifies the signatures from the ledger. Also asserts a
   duplicate `idempotency_key` is rejected.

4. **Benchmark envelope size / commit latency** (PRD §9 — local numbers only, not a production SLA):
   ```bash
   bash scripts/bench.sh 10
   ```

To tear down the Fabric network: `bash network/teardown.sh`. To tear down
Postgres/MinIO/app services: `docker compose -f infra/docker-compose.yml down`
(add `-v` to also drop the Postgres/MinIO volumes).

### Manual API walkthrough

```bash
# Create a transaction
curl -X POST localhost:8080/transactions -H 'Content-Type: application/json' -d '{
  "organization_id": "org-a", "workflow_type": "procurement",
  "schema_version": "transaction.v1", "created_by": "requester-1"
}'

# Sign and queue an event (server-side dev keystore signs as "requester-1")
curl -X POST localhost:8080/transactions/<id>/events -H 'Content-Type: application/json' -d '{
  "event_type": "SUBMITTED", "payload": {"item": "laptop", "quantity": 3},
  "new_status": "VERIFIED", "signer_identity": "requester-1"
}'

# Read the operational read model
curl localhost:8080/transactions/<id>

# Independent audit verification straight from the ledger
curl localhost:8081/verify/transactions/<id>
```

Demo identities seeded on API startup: `requester-1`, `approver-1`,
`approver-2`, `warehouse-1`, `auditor-1` (all in `org-a`). Their signing keys
are generated on first use by the dev keystore — see
[docs/adr/0001-fase1-spike-scope.md](docs/adr/0001-fase1-spike-scope.md)
decision #4 for why this is not how real deployments should manage keys.

## Troubleshooting

**`curl`/`docker pull`/`go mod download` hangs or crawls at near-zero speed
inside a container, while small requests work fine.** This usually means an
active VPN's real path MTU (check with `Get-NetIPInterface` on Windows) is
lower than Docker's default network MTU (1500), so larger TLS records get
silently dropped instead of properly fragmented. Fixes used in this repo:
- `infra/docker-compose.yml` builds api/indexer/audit-service on a
  `buildnet` network pinned to MTU 1420 — adjust the value in that file if
  your VPN's MTU is different (lower it further, e.g. 1400, if it's still
  slow).
- For ad-hoc `docker run` commands (not via compose), create the same kind
  of network yourself: `docker network create --opt com.docker.network.driver.mtu=1420 mybuildnet`
  and pass `--network mybuildnet`.
- For plain host-side `curl` calls (e.g. inside `network/bootstrap.sh`),
  add `--speed-time 30 --speed-limit 3000` so a stalled transfer aborts and
  retries instead of hanging indefinitely.

## Testing

```bash
# Everything is pure Go — no Docker needed to build or unit-test
cd crypto && go test ./...
cd chaincode/transaction && go test ./...
cd chaincode/asset && go test ./...
cd api && go build ./... && cd ../indexer && go build ./... && cd ../audit-service && go build ./...
```
