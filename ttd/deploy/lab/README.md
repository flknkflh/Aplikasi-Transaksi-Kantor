# deploy/lab (M6 slice 2)

Lab receiver server via Docker Compose (§22): `caddy`, `api`, `postgres`,
`minio`. No signing worker, no user-private-key volume. Only Caddy is exposed
to the host (`:8443`); postgres and minio stay on the internal network.

```
deploy/lab/
  docker-compose.yml
  Dockerfile              multi-stage build of server/cmd/api
  Caddyfile               TLS (Caddy internal CA) + 25 MiB upload cap + headers
  .env.lab.example        copy to .env.lab (git-ignored), fill in secrets
  pki/                    drop root-ca.crt.pem + ca-chain.pem + crl.pem here
```

## Run

```sh
# 1. build the CA operator tool and generate a lab CA
( cd ../../tools/ca-admin && go build -o ../../dist/ca-admin . )
../../dist/ca-admin init --dir ./ca
cp ./ca/public/root-ca.crt.pem ./ca/public/ca-chain.pem pki/

# 2. secrets
cp .env.lab.example .env.lab && $EDITOR .env.lab

# 3. up
docker compose --env-file .env.lab -f docker-compose.yml up -d --build
docker compose --env-file .env.lab -f docker-compose.yml ps
```

Endpoints: `https://localhost:8443` (Caddy internal cert — expect a browser
warning), `/api/v1/verify`, `/api/v1/public/ca/root.crt`.

Android device on the same Wi-Fi: `https://<LAN-IP>:8443`.

## Backend selection

`server/cmd/api` picks its store from the environment:

| env | store |
|---|---|
| `PQC_DATABASE_URL` unset | in-memory (dev) |
| `PQC_DATABASE_URL` set | PostgreSQL (schema auto-applied) |
| `+ PQC_S3_ENDPOINT` set | signed PDFs to MinIO/S3; otherwise an `objects` table |

## Integration test against a real database

```sh
docker run -d --name pg -p 5433:5432 -e POSTGRES_PASSWORD=pw postgres:17-alpine
PQC_TEST_DATABASE_URL='postgres://postgres:pw@localhost:5433/postgres?sslmode=disable' \
  go -C ../../server test ./internal/api/
docker rm -f pg
```

The same `api_test.go` suite then runs against PostgreSQL instead of the
in-memory store.

## Still slice-2 TODO

MFA/TOTP, refresh-token revocation, per-route rate limiting, DB migration
files (`server/migrations/`), backup/restore drill scripts.
