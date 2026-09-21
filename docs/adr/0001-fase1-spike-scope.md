# ADR-0001: Scope for the Fase 1 Technical Spike

**Status:** Accepted
**Context:** [Hybrid_PQC_Permissioned_Blockchain_PRD.md](../Hybrid_PQC_Permissioned_Blockchain_PRD.md) §13 defines
a 5-phase roadmap. This ADR records the scope decisions for **Fase 1 — Technical spike**,
the first phase actually being built.

## Decisions

1. **On-chain signature verification is deferred to Fase 2.**
   Chaincode enforces append-only ordering (`previous_event_hash` linkage),
   idempotency-key uniqueness, and lifecycle state transitions. It does **not**
   cryptographically verify the classical or ML-DSA-65 signatures itself.
   Verification happens in two independent places instead:
   - the API, before submitting an event to the ledger (fail-closed at the gate);
   - the audit-service, independently re-verifying signatures against the
     committed ledger data on demand (satisfies PRD FR-010 — auditors don't need
     to trust a single admin).

   Rationale: running liboqs (ML-DSA-65) inside the chaincode container is
   possible but adds real weight (custom peer/chaincode build image, longer
   endorsement latency) that isn't needed to prove the core mechanics in a
   spike. Revisit before Fase 2 (MVP internal) — PRD's "fail closed" and
   "defense in depth" principles argue for adding it once the write path is
   stable.

2. **Classical algorithm = Ed25519**, not ECDSA. The PRD allows either
   ("ECDSA atau Ed25519"); Ed25519 has simpler, safer implementation
   properties (no nonce-reuse footgun) for a from-scratch dev keystore.

3. **Object storage = MinIO** (S3-compatible, self-hosted via Docker Compose)
   stands in for "encrypted object storage." Documents are referenced from the
   ledger by hash only, never embedded — matching PRD §6's on-chain/off-chain
   split.

4. **No real SSO/KMS/HSM.** A file-based dev keystore issues Ed25519 +
   ML-DSA-65 keypairs per demo identity. Private key material never leaves the
   keystore process/file (never logged, never returned via API, never put in
   ledger payloads) — only `key_id` is referenced, consistent with PRD §7's
   "Private key hanya direferensikan melalui `key_id`". This is explicitly
   **not production-ready**; PRD §12 lists real KMS/HSM/SSO under Fase 2+.

5. **Hybrid KEM (X25519 + ML-KEM-768) is a library-level demo, not wired into
   transport.** Implemented as a combiner function (HKDF-SHA384 over both
   shared secrets) with unit tests proving correctness, but actual hybrid TLS
   termination is an infra-level concern outside this app's code and is not
   attempted here — consistent with PRD §10's note that hybrid TLS support
   must be verified per communication path, not assumed.

## Consequences

- The spike proves: hybrid signing + canonicalization, append-only event
  chain with idempotency enforcement, Fabric commit → Postgres read model via
  an idempotent indexer, and independent audit verification with a
  verification receipt.
- It does **not** prove: production key management, in-chaincode crypto,
  encrypted-at-rest object storage with real KMS-backed envelope encryption,
  SSO/MFA, or any HA/production topology. These remain Fase 2+ work per the
  PRD roadmap and must not be assumed "done" from this spike.

## Addendum (2026-09-21): ML-DSA-65 is in the Go standard library — liboqs removed

Decision #1 and the original build notes assumed ML-DSA-65 needed liboqs
(cgo). That was wrong: Go 1.27 ships `crypto/mldsa` (FIPS 204) and `crypto/x509`
support for it. The check that led to the wrong conclusion only read the Go
1.25/1.26 release notes, not 1.27's.

Changes made:

- `crypto/mldsa.go` now uses `crypto/mldsa`. The "private key" is the 32-byte
  FIPS 204 seed (`PrivateKey.Bytes()`); public keys are the 1952-byte FIPS 204
  encoding, the same encoding liboqs used, so `key_reference.public_key` rows
  stay valid. Signatures are still 3309 bytes ("pure" ML-DSA, empty context).
- `liboqs-go` removed from `crypto`, `api`, `audit-service`; `infra/Dockerfile.godev`
  and the liboqs build stage in `api/Dockerfile` and `audit-service/Dockerfile`
  deleted. Every module now builds and tests natively with no cgo and no Docker.
- Incompatible on purpose: a dev keystore file written by the old liboqs build
  holds ~4 KB expanded secret keys, not seeds, and will be rejected with a clear
  error. No live run ever persisted such a file, so nothing is lost.
- The earlier bug where signing zeroed the caller's key buffer (a liboqs-go
  aliasing quirk) cannot occur any more; `TestMLDSASigningDoesNotConsumeCallerKey`
  keeps guarding it.
