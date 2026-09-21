# server/migrations

The canonical, versioned migrations live in
[`../internal/store/migrations/`](../internal/store/migrations/) as
`NNNN_name.up.sql` / `.down.sql`. They are embedded (`//go:embed`) and applied
in order on every `OpenPostgres`, guarded by a `schema_migrations` table, so a
fresh database converges and re-runs are no-ops (Rencana V1 §23 M6: "migration
dapat dijalankan dari database kosong").

Current:

```
0001_init   accounts, devices, enrollments, certificates, reservations,
            signatures, objects, audit_events   (§18.1)
0002_mfa    mfa_credentials (TOTP)              (§17 auth/mfa/*, §24)
```

The `.down.sql` files are for operators using an external migration tool; the
server itself only rolls forward. Slice-2 remainder: refresh-token store,
rate-limit persistence if ever needed (currently in-process).
