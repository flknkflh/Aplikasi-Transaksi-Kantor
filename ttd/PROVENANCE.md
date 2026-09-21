# Provenance

This directory is the receiver + core + CA tooling of **PQC PDF Sign V1**
(post-quantum PDF signing, ML-DSA-65 / PAdES-B), imported from the same owner's
repository `github.com/flknkflh/TTD_ELEKTRONIK` at commit
`441695d966f0cfea70dc66018060b93f04d1a199`.

Imported verbatim: `core/`, `server/`, `tools/ca-admin/`, `pki/`, `docs/`,
`deploy/`, `tests/fixtures/`, `LICENSES/`.

Deliberately **not** imported: `apps/windows` and `apps/android` (the native
clients) — replaced in this repo by a browser client (`web/`, added in later
commits) that reuses the very same `core/` compiled to WebAssembly. The
upstream README is kept as `docs/upstream-README.md`.

Local edits after import are listed in `git log -- ttd/`. The frozen interfaces
(`docs/formats.md`: PKCS#8 key, CSR, device certificate, PAdES-B signature,
verification-result JSON, `/api/v1/*`) are not changed.

Module paths keep the upstream `example.internal/pqc-pdf-sign/*` placeholder.

Third-party licences: see `LICENSES/THIRD_PARTY_NOTICES.md` (digitorus/pdfsign,
BSD-2-Clause).
