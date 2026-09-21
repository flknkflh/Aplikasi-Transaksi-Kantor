# Security findings

Tracked issues from hardening work (Rencana V1 §26, §29). Each entry: what,
impact, current mitigation, TODO.

---

## SF-1 — PDF parser CPU-loop on crafted input (DoS)

**Found:** M3 fuzzing (`core/verification.FuzzVerifyPDF`), 2026-09-02.

**What:** feeding certain malformed byte sequences to `verification.VerifyPDF`
(and by extension `ListPDFSignatures`, `signing.SignPDF`) drives the
transitive dependency `github.com/digitorus/pdf` v0.2.0 into a CPU-bound loop
that does not terminate. Go's fuzzer wedges: `execs` freezes and worker
goroutines pin every core. No panic — so a `recover()` guard does not help.

**Impact:** an unauthenticated request to `POST /api/v1/verify`, or an
authenticated `PUT /api/v1/signatures/{id}/document`, could hang a request
goroutine indefinitely and burn a core. Repeated, it is a denial of service.

**Mitigations in place:**

1. `verification.MaxPDFBytes` / `signing.MaxPDFBytes` (64 MiB): oversized
   input is rejected before the parser runs.
2. `Options.Timeout` (server sets **15 s** on both call sites): the request
   returns an error instead of hanging. Caveat — the parse goroutine keeps
   running until the process is recycled, so this bounds *latency*, not CPU.
3. Server upload cap 25 MiB (Caddy + `MaxUploadBytes`).
4. Per-route rate limits (`verify` 30/min/IP, `submit` 30/min/account) cap how
   fast an attacker can leak stuck goroutines.
5. Recommended ops: run `api` under a process supervisor with a memory limit
   and periodic recycling; alert on sustained high CPU.

**TODO before production:**

- [ ] Minimise a reproducing input (supervised `go test -fuzz` session, short
      `-fuzztime`, capture from `$GOCACHE/fuzz`).
- [ ] Report upstream to digitorus/pdf with the reproducer.
- [ ] Evaluate a bounded fork of the loop (§9.1: patch allowed for a PDF bug,
      with a test + upstream diff note) **or** move untrusted-PDF parsing into
      a sandboxed subprocess with a hard wall-clock + memory limit.
- [ ] Add the reproducer to `testdata/fuzz/FuzzVerifyPDF/` as a regression
      seed once fixed.

**Fuzz-in-CI policy:** CI actively fuzzes only the stdlib-`crypto/x509`-backed
parsers (`keys`, `enrollment`, `certutil`). The PDF-backed fuzzers
(`verification`, `signing`) run their **seed corpus only** in CI (`go test
./...`); deep `-fuzz` on them is a manual, time-boxed activity until SF-1 is
fixed.
