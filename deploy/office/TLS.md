# HTTPS: TLS 1.3 with hybrid post-quantum key exchange

See [ADR-0009](../../docs/adr/0009-tls13-hybrid-pqc.md) for the design. This page is the
how-to: turning it on/off, replacing the cert, and checking it's actually negotiating the
post-quantum key exchange.

## What's running

`docker compose up -d` (the normal command, nothing extra to type) now serves the app on **two
listeners**, both fully functional, neither the "real" one over the other:

| | HTTP | HTTPS |
|---|---|---|
| App | `http://localhost:18099` | `https://localhost:18443` |
| Verify-only site | `http://localhost:18098` | `https://localhost:18444` |

The certificate is **self-signed**, generated once on first boot into the `ttd_tls` volume (so
it survives `docker compose down` / restarts — only `down -v` throws it away and gets a new one
next boot). Your browser will show a trust warning the first time you open the HTTPS URL —
expected for a self-signed cert; click through it (or import `ttd_tls`'s `cert.pem` as a
trusted root in your OS/browser if you'll use it repeatedly). Nothing on the HTTP side changed
or is going away — this is additive.

## Why two listeners instead of switching over

Because flipping the existing HTTP port to HTTPS-only would break every script, bookmark and
test that already points at `http://localhost:18099`, with a self-signed cert making even `curl`
fail without `-k`. Running both lets you adopt HTTPS at your own pace: point real users at the
HTTPS URL, keep internal tooling on HTTP as long as you need to, and eventually turn HTTP off
entirely (see "Going further" below) once nothing depends on it.

## Checking it's real

```sh
# HSTS only shows up on the HTTPS response — that's correct, not a bug (HSTS is a no-op over
# plain HTTP and browsers ignore it there per spec):
curl -sI http://localhost:18099/api/v1/public/server | grep -i strict-transport   # -> nothing
curl -sIk https://localhost:18443/api/v1/public/server | grep -i strict-transport # -> Strict-Transport-Security: max-age=...

# See the TLS 1.3 + hybrid post-quantum group actually negotiated:
openssl s_client -connect localhost:18443 -tls1_3 </dev/null 2>&1 | grep -i "Protocol\|Cipher"
```

For proof the *key exchange* itself is post-quantum (not just TLS 1.3), OpenSSL's own output
doesn't show the negotiated group by default. A one-off Go program does:

```go
conn, _ := tls.Dial("tcp", "localhost:18443", &tls.Config{InsecureSkipVerify: true})
fmt.Println(conn.ConnectionState().CurveID) // 4588 = X25519MLKEM768 (hybrid PQC)
```

## Turning it off

Set `TLS_HOSTS=` (empty) in `.env` and `docker compose up -d` — the HTTPS listeners simply don't
start; `-tls-addr`/`-verify-tls-addr` are left unset so `ttd/server/cmd/api/main.go` never touches
`crypto/tls` at all.

## Bringing your own certificate

If you have a real certificate (an internal CA, or a public one for a real domain), skip the
self-signed generator entirely: mount your cert/key into the container and set
`PQC_TLS_CERT_FILE`/`PQC_TLS_KEY_FILE` directly (the entrypoint only auto-generates when those
are unset). `TLS_HOSTS` is then unused.

## Going further (production)

This setup is deliberately the minimum that's real and testable in a demo/local stack, not a
production TLS posture on its own:

- **Get a certificate a real browser trusts**: an internal CA your devices trust, or Let's
  Encrypt if the server has a public hostname. A self-signed cert is fine for a LAN demo, not for
  anyone outside it.
- **Put a reverse proxy in front** (Caddy, nginx, or your cloud LB) once you have a real
  certificate and domain — it can also do the HTTP→HTTPS redirect this setup doesn't (see
  ADR-0009's "Consequences"), and handle certificate renewal for you.
- **HSTS preload**: once running on a trusted certificate and a real domain long-term, consider
  adding `preload` to the `Strict-Transport-Security` header (`ttd/server/internal/api/api.go`'s
  `hsts` function) and submitting to hstspreload.org. Not done here — it only makes sense once
  every visitor's very first connection can also be trusted, which a self-signed cert can't
  guarantee.
