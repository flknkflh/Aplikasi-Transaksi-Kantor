# Large documents

The PDF libraries in use (`pdfcpu` for the QR stamp, `digitorus/pdfsign` for
signing/verification, `core/verification`) all parse a whole document into
memory — none of them stream. A 1 GB PDF needs several GB of RAM per operation
and minutes of CPU, three times over (stamp, sign, verify). So the server
handles big documents in **tiers by byte size**, and stores blobs on a disk
volume instead of a Postgres `bytea` value (which is hard-capped at 1 GiB and
buffered whole).

## Tiers

| size | `/stamp` (server QR) | submit: strict re-verify | stored |
|---|---|---|---|
| ≤ `PQC_MAX_STAMP_MB` (default 150) | yes | yes | yes |
| ≤ `PQC_MAX_VERIFY_MB` (default 350) | **422 / 413** — sign without a server stamp | yes | yes |
| ≤ `PQC_MAX_UPLOAD_MB` (default 25; set higher to enable) | no | **no — store-only** | yes, hash recorded |
| larger | 413 | 413 | 413 |

`MaxStampBytes` and `MaxVerifyBytes` are each clamped to `MaxUploadBytes`, so
the defaults do nothing until an operator raises `PQC_MAX_UPLOAD_MB`.

**Store-only** (`verification_status: "stored_unverified"`): the server streams
the file to storage while hashing it, records the SHA-512 and size, and keeps
**no** certificate linkage. The public verifier page shows the badge
*"TIDAK DIVERIFIKASI SERVER"* and tells the reader to upload the PDF to the
verification page to check the signature by hand. `POST /api/v1/verify` still
works on such a file (subject to the verifier's own memory limits) — the
degradation is only that the server did not do it automatically at submit time.

## Resumable upload

A large signed PDF will not survive one HTTP request on a flaky link, so push
it in chunks and then point submit (or stamp) at the assembled upload.

```
POST  /api/v1/uploads                       -> {upload_id, received:0, max_bytes}
PATCH /api/v1/uploads/{id}?offset=<N>        body = chunk; offset must equal the
                                               current size -> {received:<new size>}
                                               (offset mismatch -> 409 {received})
GET   /api/v1/uploads/{id}                   -> {received}   (for resume)

PUT   /api/v1/signatures/{pid}/document?upload_id=<id>   (no body)
POST  /api/v1/signatures/{pid}/stamp?upload_id=<id>&...  (no body)
```

Sessions are per-account, in memory (a server restart drops them — restart that
upload), stored under `PQC_UPLOAD_DIR` (default `os.TempDir()`), and expire
after 2 h. On a successful stamp/submit the session and its scratch file are
deleted. The plain-body form of both endpoints still works for small files and
old clients.

## Storage backend

- `PQC_S3_ENDPOINT` set → MinIO/S3 (streamed multipart).
- else `PQC_OBJECT_DIR` set → files under that directory (`<dir>/<key>`), one
  volume mount. **Use this for large documents.**
- else → Postgres `objects` table (`bytea`, ≤ ~1 GiB, buffered).

## What is NOT solved

A *verified* signature is still bounded by the RAM `core/verification` needs to
parse the whole PDF — roughly a few hundred MB on a modest box. Files past
`MaxVerifyBytes` are stored but not server-verified. Lifting that would need an
async worker with lots of RAM, or a streaming PDF verifier (neither exists
here).
