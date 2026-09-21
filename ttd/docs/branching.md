# Branching (§9.4)

```
main                     stable release branch
develop                  V1 integration
feature/core-mldsa       core sign/verify
feature/windows-client   Windows app
feature/android-client   Android app
feature/receiver-api     receiver server
feature/ca-admin         CA administration
```

Every pull request runs: unit tests, static analysis, dependency scan, secret
scan, and a build of the affected target (see `.github/workflows/ci.yml`).

Release jobs (tag on `main`) additionally: Windows build on a Windows runner,
Android release build, server multi-stage image, integration tests, SBOM,
`SHA256SUMS`, artifact signing. CA private keys, the Android release keystore,
the Authenticode key, and production secrets live in CI secret storage — never
as repository files (§27).
