# deploy/production (M9 / post-V1)

Lab → VPS move (§28).

**Moved:** source/build recipe, API image, Caddy config, DB migrations, Root +
Intermediate **public** certs, public CRL, production config (no secrets in Git).

**Not moved:** any private key (Root, Intermediate, user/device), lab DB
password, lab JWT/TOTP secrets, lab TLS key, Android debug key.

Procedure: provision domain + VPS → install Docker → create fresh production
secrets → run a separate production PKI ceremony → deploy
Postgres/MinIO/Caddy/API → migrate → publish public trust material → build
clients against the production URL + Root CA → re-enroll all devices with new
keys → smoke test sign/submit/verify/revoke/backup/restore.
