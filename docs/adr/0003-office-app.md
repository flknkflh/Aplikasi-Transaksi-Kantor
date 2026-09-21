# ADR-0003: One office app — transactions with TTD approval

**Status:** Accepted (2026-09-21)
**Context:** ADR-0002 delivered TTD (digital signatures) as a standalone browser
app, while the transaction ledger (Fase 1) was only an unauthenticated REST API
with no UI. The requirement is *one* application for office transactions in which
**approval is a digital signature on the request's PDF**, recorded on the ledger.

## Decision

1. **One origin, one login.** The TTD server stays the place people log in and is
   the only public entry point. `/office/*` is a reverse proxy to the ledger
   service: the TTD server validates the session (JWT, active account), strips any
   client-supplied `X-Office-*` headers and the bearer token, and vouches for the
   identity with a shared secret (`X-Office-Secret`). The ledger service is not
   published to the host and refuses `/office` calls without that secret. Accounts
   are TTD accounts; `user_identity.id` = TTD account id, provisioned on first use.
2. **Roles** (`requester`, `approver`, `auditor`) are assigned by a TTD admin
   (`PUT /office/roles/{account}`, UI "Peran"). Default is `requester`. Requesters
   see only their own requests; approvers/auditors/admins see all.
3. **Workflow** `pengajuan-kantor`, policy `policy-v1` (one approver):
   `DRAFT → VERIFIED (submit) → ENDORSED (approve) → COMMITTED (complete)`;
   `VERIFIED → REJECTED` (reason required); `DRAFT|VERIFIED → CANCELLED`. The same
   state machine as the chaincode, enforced by the API too (Fabric may be off).
   The approver cannot be the creator (also enforced by the chaincode).
4. **Approval = a TTD signature, verified server-side.** The browser signs the
   request's attached PDF with the normal TTD pipeline (PIN, key in the worker) and
   then sends only the `ttd_public_id`. The ledger service asks the TTD server (the
   source of truth, over an internal secret-guarded endpoint) who made that signature,
   that its strict verification was `accepted`, that the original hash equals the
   attachment's SHA-512 and that the signed hash equals the fetched signed PDF; it
   stores the signed PDF and records `APPROVED_SIGNED` with the TTD id and both
   hashes. A TTD signature can back **one** approval (unique index). The ledger
   service never signs a document.
5. **Every step is a hybrid-signed, hash-chained event** written through the existing
   path (`appendTransactionEvent` = former `RecordTransactionEvent` body:
   Ed25519 + ML-DSA-65 by the dev keystore, transactional outbox, chaincode
   `RecordEvent`; an approval additionally queues chaincode `Approve`). A rejection
   queues only the `REJECTED` event, because chaincode `Approve(reject)` would itself
   move the status and collide.
6. **Fabric is optional at runtime** (`FABRIC_ENABLED=false`). Previously the API
   exited if it could not connect to Fabric. Now events stay `pending` in
   `outbox_event` and the UI says so ("Ledger belum terhubung" / "Antre" / "Tercatat
   di blok N"). The read model's `transaction.status` is advanced by the API itself
   (the indexer would write the same value from chaincode events).
7. **Devices/keys are created lazily**: a requester never has to make a PIN; the key
   is created the first time someone signs or approves.

## Consequences / limits

- **Not yet proven on a live Fabric network.** The outbox → chaincode path is
  unchanged Fase 1 code and was not exercised end-to-end here; what is verified is
  that events are correctly signed, chained, ordered and queued.
- Event signatures still come from the server-side dev keystore (ADR-0001, decision 4);
  only the *document approval* signature is made on the user's device.
- The approver signs the PDF **they downloaded** from the request. The ledger checks
  the signature's `original_sha512` against that attachment, but that value is supplied
  by the signing client at reservation time; a malicious approver could sign a
  different document with a matching claimed hash and would be recorded as having
  signed *that* document (both hashes are in the event, so it is auditable, not hidden).
- One approver only; no approval matrix, delegation, amount thresholds or notifications.
- `/internal/office/*` shares the public port (guarded by the secret); put a reverse
  proxy in front that does not route `/internal/` in a real deployment.
- Lab CA / no trusted timestamp, as in ADR-0002.

## Verification

`api`: 5 Postgres-backed workflow tests (`TEST_DATABASE_URL`); `ttd/server`: proxy +
internal endpoint tests; `ttd/web/e2e/office.mjs`: real Chrome against the Docker
stack (requester → approver signs → complete; reject; self-approval; forged/reused
TTD ids; roles; CSP). `ttd/web/e2e/run.mjs` still covers the standalone TTD.
