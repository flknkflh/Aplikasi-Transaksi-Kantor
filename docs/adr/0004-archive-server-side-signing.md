# ADR-0004: Multi-office upload archive with server-side signing

**Status:** Accepted (2026-09-21). Supersedes the approval workflow of ADR-0003 as the
product's focus (that code and its tests remain in the repository, unpublished).

## Context

The product changed from "approve a request by signing its PDF" to **a general recorder /
archive of data transactions**: several offices (kantor) share one server and database;
each sender uploads files of any type and size; every upload must be attributable to its
sender, signed, and protected by the blockchain; the sender gets a receipt; **only the
central admin** sees what was sent. Decided with the owner: the signing key is held
**server-side** (the sender does not hold a key), access is a **website** (not an EXE), and
the server they are sending to is shown on screen.

## Decision

1. **A transaction = one upload.** The unit that is signed is a *manifest*: sender, office,
   file name/type/size, SHA-256 and SHA-512, description, server time, the sender's IP and
   user agent, server name. It is signed with the **sender's hybrid key** (Ed25519 +
   ML-DSA-65, `crypto.SignHybrid`) — a detached signature, so it works for any file type
   (PAdES only applies to PDFs) and any size (only hashes are signed).
2. **Three chained events per upload**, no chaincode change: `UPLOAD_RECEIVED` (sender key;
   status stays DRAFT) → `INTEGRITY_VERIFIED` (system key; DRAFT→VERIFIED) → `ARCHIVED`
   (system key; VERIFIED→ENDORSED, shown as "Diarsipkan"). They go through the existing
   `appendTransactionEvent` (hash chain + outbox → Fabric). `INTEGRITY_VERIFIED` is a fact
   about the *stored* bytes: the server reads the object back and re-hashes it.
3. **Receipt.** `{body: manifest + manifest_hash + the sender's signature + event hashes,
   server_signature}` signed by the system identity; downloadable as JSON, printable, and
   checkable without login at `/app/#r=<receipt_id>` (the id is 128-bit random and is the
   capability). The public view shows hashes, time, office and who signed — not the file,
   e-mail, IP or notes — plus a live verification and an in-browser "does the file I hold
   match?" check (hashed locally, never uploaded).
4. **Any size.** Resumable chunked upload (8 MiB chunks; `Upload-Offset` must equal the
   server's offset, so a retry cannot corrupt the file). The browser hashes as it sends
   (its own incremental SHA-256, because `crypto.subtle` cannot stream and is absent on
   plain-HTTP origins) and must send that hash at completion; the server rejects a mismatch.
   The server streams to a scratch file, keeps running SHA-256/512, then streams to MinIO.
   Default ceiling 20 GiB per file (`ARCHIVE_MAX_BYTES`), disk-space check, at most 5 open
   uploads per sender, abandoned sessions expire after 48 h.
5. **Who sees what.** Senders: only the receipt of their own upload (no list). Central
   admin (a TTD account with the admin/superadmin role): list with filters, detail with the
   hash-chained timeline and Fabric block numbers, on-demand verification (manifest hash,
   sender + server signatures, chain, receipt, and optionally the stored file), streaming
   download through one-time two-minute tickets, and an access log (`archive_access`).
6. **Offices.** An office is a row of `organization`; the admin creates offices and assigns
   accounts (`office_member`). An approved account without an office cannot send.
7. **"Target server".** The page is served by the server it talks to; a permanent bar shows
   the server's configured name, its host:port and whether it is HTTPS. A page that could
   target arbitrary servers would need CORS and invite phishing, so none is offered.
8. **Keys at rest.** The keystore file (all sender and system private keys) is encrypted
   with AES-256-GCM under `KEYSTORE_KEK`; a plaintext dev keystore is migrated on first open,
   and a wrong or missing secret is an error, never an empty keystore.

## Consequences — read these

- **The sender's signature is made by the server after authenticating them.** The evidence
  that "A sent this" is A's login + the server's records + the hash chain on Fabric, *not* a
  key only A holds. Whoever controls the server (or its keystore and KEK) could create a
  signature in A's name; the chain and the access log limit *silent* tampering after the
  fact, they do not prevent forgery at the source. Mitigations here: keys encrypted at rest,
  IP/UA/time signed, each item anchored on the ledger, admin access logged. A stronger model
  (the browser or a device signs the hash; the server countersigns) remains possible later
  and would not change the receipt format much.
- **The recorded IP is what the server sees.** Behind Docker Desktop's NAT it is the gateway
  address; on a Linux host, or behind a reverse proxy that sets `X-Forwarded-For`, it is the
  client's. The TTD proxy always overwrites `X-Forwarded-For` with the real peer address.
- Files are stored as opaque bytes; nothing is scanned for malware. They are only ever
  served as `attachment` with `nosniff` and a sandbox CSP.
- Fabric is still the dev test network; the chain enforces order and status transitions, not
  the hybrid signatures (ADR-0001). No retention/deletion, notifications or sender TOTP yet.
- The lab CA and trusted timestamps belonged to PDF signing and are not part of this design.

## Verification

`api`: Postgres-backed archive tests (signed + chained + verifiable; resume across a server
restart; corrupt transfer; limits; tampering with the file, manifest or a signature is
detected; the public receipt exposes nothing private; one-time download tickets;
offices/members; search) and keystore tests. `ttd/server`: proxy tests.
`web/test/sha256.test.mjs`. `ttd/web/e2e/arsip.mjs`: real Chrome against the Docker stack,
and with `E2E_FABRIC=1` against a live Fabric network (blocks confirmed directly on the peer
with `network/query-transaction.sh`).
