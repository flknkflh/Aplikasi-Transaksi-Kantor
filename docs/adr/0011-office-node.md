# ADR-0011: `office-node` — one program that turns a computer into a real peer

**Status:** Accepted (2026-09-23). Follow-up to the "bisa dijadikan EXE?" question: packages
Bagian 2 of `network/MULTI-HOST-LAB.md` (manually splitting `fabric-samples/test-network` across
two machines) into a single program an office runs, per the chosen design — **B. Hybrid**: the
web app and its database stay on the one shared central server exactly as before (ADR-0004); only
the blockchain layer becomes genuinely distributed, one real Fabric peer per participating office.

## Context

"EXE" and "web app" are not in tension — an EXE that runs a local web server is still a web app,
just reached at `localhost` instead of a shared address. What *is* a real fork in the road is
**where the blockchain node runs**: centralized (as now) or one real peer per office
(what was asked for). The owner confirmed: keep the shared server/database as the one place
everyone's browser points to; only distribute the *ledger*.

The one thing that cannot be automated away, and is not a limitation to route around: **a
permissioned network cannot let itself be joined by anyone who merely has the software.** If
running the EXE were enough to become a trusted node with no other step, the entire reason this
project chose a permissioned blockchain over a public one — identity-based trust instead of
proof-of-work — would be undermined. So the design keeps exactly one deliberate, admin-initiated
step, and automates everything else.

## Decision

1. **`network/tools/office-node`** (new Go program, stdlib only, cross-compiles to a plain
   `.exe` for Windows) has three subcommands:
   - `office-node join <package.zip>` — one-time: unpacks a join package into
     `office-node-data/` next to the binary.
   - `office-node start` — launches the **real, native Fabric `peer` binary** as a child process
     with the right environment (TLS/MSP paths, ports, `CORE_PEER_FILESYSTEMPATH`) computed from
     the join package, waits for it to come up, runs `peer channel join` automatically the first
     time, then polls and prints the ledger height every 20s for as long as it runs. Ctrl+C stops
     the child peer process cleanly rather than orphaning it.
   - `office-node status` — one-off ledger-height check against an already-running node.
2. **`network/tools/office-node/pack-join.sh`** is the admin-side counterpart, run on the central
   machine after `network/bootstrap.sh`. This is the one deliberate step: it registers a **brand
   new peer identity** with the live Fabric CA (`ca_org2`, already running because bootstrap.sh
   passes `-ca`) — not a copy of an existing identity — enrolls its MSP and TLS material, and
   zips that together with the channel genesis block and the orderer's TLS CA cert into one
   `join-<peer-id>.zip`. That file — containing a real private key — is the credential; handing
   it to an office *is* the admin's approval, the same role `POST /api/v1/superadmin/admins`
   already plays for creating an admin account (ADR-0005) or an office admin approving a pending
   user (ADR-0003). No enrollment secret, no channel access, without an admin choosing to hand
   one over.
   - The package also carries a copy of the org's existing `Admin@org2.example.com` MSP, as
     `admin-msp/`. Fabric's default `Admins` policy on the channel-join system-chaincode call
     requires an identity with `OU=admin` — the new peer's own freshly-issued identity
     (`OU=peer`) is correctly rejected for that one call, only ever used for it (`office-node`
     swaps `CORE_PEER_MSPCONFIGPATH` to `admin-msp/` for the single `peer channel join`
     invocation, never for the long-running peer process or for status queries). **v1
     simplification, stated plainly:** every office's package therefore carries the same
     org-wide administrative credential, not a join-scoped one. The more correct version has the
     *central* admin perform the join remotely, using an admin identity that is never
     distributed — left as a follow-up now that the join mechanism itself is proven (see
     Verification).
3. **Where each piece runs**: `office-node` only ever starts a `peer` process — never the web
   app, never Postgres/MinIO, never chaincode-as-a-container. The shared central server (ADR-0004,
   0009) is completely unmodified by this; office-node is additive, exactly like the TLS listeners
   in ADR-0009 were additive to the plain-HTTP ones.
4. **`core.yaml`** (the peer's config template, 777 lines, normally supplied by
   `fabric-samples/test-network`'s own `compose/docker/peercfg/`) is embedded into the binary
   (`//go:embed core.yaml`) — an office needs nothing beyond `office-node.exe` + a native Fabric
   `peer` binary for their OS + the join package the admin sent them.

## Consequences — read these

- **v1 does not make the new peer an endorser.** It becomes a genuine, independently-validating
  replica of the ledger — real security value on its own (an additional copy no single party
  controls, exactly the "terdistribusi" property discussed) — but the channel's endorsement
  policy still only names the existing peers until a consortium decides to add this one, and
  chaincode execution on a brand-new peer needs either Docker on that machine or Fabric's
  "chaincode as an external service" builder configured for it — neither is wired up by v1.
  Both are natural next increments, not required for the "does this genuinely hold and validate
  its own copy" question this version answers.
- **The native `peer` binary is platform-specific and not bundled by this v1.** `office-node`
  looks for `peer`/`peer.exe` next to itself, then on `PATH`. Distributing a real, double-click,
  nothing-else-to-install EXE means bundling (or first-run-downloading) the matching Fabric
  release binary for the office's OS — a packaging step, not a design gap; noted here rather than
  silently assumed away.
- **Windows SmartScreen / firewall prompts.** An unsigned EXE that opens listening ports will
  trigger warnings; a real rollout wants a code-signing certificate and a first-run prompt
  explaining what firewall rule it needs (the same ports covered in
  `network/MULTI-HOST-LAB.md`'s Part 2).
- **The join package is a bearer credential for that peer's identity.** Losing it (or it leaking)
  is equivalent to losing an admin's password — pack-join.sh's own output says so and tells the
  operator to send it over a secure channel and not keep stray copies around.

## Verification

Compiles clean (`go build`, `go vet`, `gofmt`). **Run end-to-end against a live network** (not just
compiled) on 2026-09-23, after `network/bootstrap.sh` brought up a real `test-network` (both
`transaction` and `asset` chaincodes installed/approved/committed on Org1 and Org2):
`pack-join.sh` registered and enrolled a genuinely new identity (`peer1.org2.example.com`) with the
live `ca_org2`; `office-node join` unpacked the resulting package; `office-node start` launched the
real `peer` binary as a native (non-Docker) process, which joined `ledgerchannel` and then caught
up to **block height 9 — matching the existing peers exactly** — with gossip membership showing
both `peer0.org1.example.com` and `peer0.org2.example.com` online. This satisfies the bar set
before calling this done: a real CA-issued identity, a real process, a real channel join, verified
sync.

Four real bugs surfaced only by this live run (would not have been caught by compiling alone):

1. **Ledger snapshot path.** `core.yaml`'s `ledger.snapshots.rootDir` is a separate hardcoded path
   from `peer.fileSystemPath`, not covered by the `CORE_PEER_FILESYSTEMPATH` override already in
   place — the peer panicked trying to `mkdir /var/hyperledger`. Fixed by also setting
   `CORE_LEDGER_SNAPSHOTS_ROOTDIR`.
2. **`CORE_PEER_TLS_SERVERHOSTOVERRIDE` is global, not orderer-scoped.** Setting it to the
   orderer's hostname broke the peer CLI's own local connection to itself during `channel join`
   (it presents a cert for the peer's own hostname, not the orderer's — a spurious mismatch).
   Removed; any future genuinely orderer-facing CLI call should use the per-command
   `--ordererTLSHostnameOverride` flag instead.
3. **`channel join` needs an admin identity**, not the peer's own — see the `admin-msp/` note
   under Decision above.
4. **Hostname resolution for `orderer.example.com` / `peer0.org1.example.com` /
   `peer0.org2.example.com`.** These hostnames are baked into the channel config and TLS certs;
   inside the original Docker-Compose network they resolve via Docker's internal DNS, but a
   native, non-Dockerized `office-node` process sits outside that namespace and needs them to
   resolve some other way (a hosts-file entry pointing at wherever those services are actually
   reachable — `127.0.0.1` when testing on the same machine, a real LAN IP across machines, per
   `MULTI-HOST-LAB.md`'s existing `extra_hosts` guidance). Without it, the peer joins but its
   ledger height sticks at 1 (genesis only) — it can never actually pull new blocks or reach full
   gossip membership. **Not yet automated**: a real rollout should have `office-node` write this
   itself from the addresses already present in `join.json`, rather than requiring a manual
   `/etc/hosts`/`hosts` edit on every office machine — tracked as a follow-up.

Also confirmed working end-to-end but noted as testing-environment accommodations, not design
changes: the distributable artifact is a native Windows `.exe` (`GOOS=windows go build`); the live
test above ran a Linux build of the same unmodified source against a Linux `peer` binary inside
WSL, since that was the environment with a live Fabric network available.

### Follow-up, 2026-09-25: proven on native Windows too

`network/vendor/fabric-samples/bin/` already contains a genuine `peer.exe` — Fabric's own binary
release turns out to ship Windows binaries after all (confirmed: `peer.exe version` → real
`v2.5.16 windows/amd64` output, run directly, no WSL). So "package peer.exe for Windows offices"
turned out to mean proving the pair actually works, not sourcing a new binary. Built a fresh
`office-node.exe`, paired it with `peer.exe` in one directory, minted a third identity
(`peer3.org2.example.com`) via `pack-join.sh`, and ran `office-node.exe join` / `start` as genuine
native Windows processes (not WSL) against the same live network: identity extraction, admin-MSP
swap, and `channel join` all worked identically to the Linux run — **confirmed** end-to-end for
everything except full block sync (see below).

**A second bug, found and reverted, not just fixed:** tried solving the orderer-hostname-resolution
gap (bug #4 above) via a local `core.yaml` `deliveryclient.addressOverrides` entry instead of a
hosts-file edit — cleaner in principle, no admin/root rights needed. It does not work on this
channel: Fabric's own peer log says why — `"Config defines both orderer org specific endpoints and
global endpoints, global endpoints will be ignored"`. `configtx.yaml` defines per-org
`OrdererEndpoints` (the modern, common configtx.yaml shape), and `deliveryclient.addressOverrides`
only ever covers the legacy single global orderer address — it silently has no effect once
per-org endpoints are in play. The code for this was written, tested, observed not to work (TLS
handshake kept validating against the override's `to` address instead of `tlsHostnameOverride`),
and removed rather than left in as dead, misleading complexity.

**What shipped instead:** `office-node join` now calls `ensureOrdererHostsEntry`, which tries to
append the resolving line to the OS hosts file itself (`/etc/hosts`, or
`%SystemRoot%\System32\drivers\etc\hosts` on Windows) — best-effort, never fatal. `join.json` gained
`orderer_reachable_addr` (set by `pack-join.sh`, default `127.0.0.1:7050`, overridable via
`ORDERER_REACHABLE_ADDR=<lan-ip>:7050` env for a genuinely remote office, matching
`MULTI-HOST-LAB.md`'s existing guidance). When the write succeeds (normal case: an admin/root-elevated
first run, or Linux where the invoking user already has the rights), sync "just works" with zero
manual steps. When it can't (confirmed: this session's non-elevated Windows shell got `Access is
denied` writing `...\drivers\etc\hosts`), it prints the exact line to add and continues — the peer
still starts and joins, it just stays behind on sync until that line is added, exactly like before
this change, except now it tells the operator precisely what to do instead of silently stalling at
block height 1.

**Final verification status:** peer identity + process + channel join — proven on native Windows,
live, this session. Full block sync via the hosts-file mechanism — proven on Linux/WSL (block height
9, matching the network exactly, per the original verification above); on Windows specifically, this
session's shell lacks Administrator rights to write the system hosts file, so the *sync* leg was
verified in the expected, documented degraded mode (clean retry-with-backoff, no crash, correct
warning) rather than the fully-caught-up state — the write mechanism is OS-generic (same function,
just a different path per `runtime.GOOS`) and already proven on the Linux side, so this is recorded
as an honest, narrow gap (needs one elevated run to confirm the Windows file write itself succeeds),
not a claimed-but-unverified full pass.

### Follow-up, 2026-09-25: the admin-msp v1 simplification is now optional, and proven fixed

The "every office's package carries the same org-wide admin credential" simplification (noted under
Decision above) is now a *choice*, not a given: `pack-join.sh` takes `INCLUDE_ADMIN_MSP` (default
`true`, unchanged behavior). Set to `false`:

- `pack-join.sh` never copies `admin-msp/` into the package at all — this office receives no admin
  identity, ever.
- `office-node join`'s required-files check no longer demands `admin-msp/` (it was already handling
  its *absence* correctly before this change, just never exercised that path).
- `office-node start` detects the missing `admin-msp/` and, instead of attempting (and failing) a
  local self-join, prints that it's waiting for the central admin and goes straight to the polling
  status loop.
- **New: `network/tools/office-node/remote-join.sh <peer-id> <office-host:port>`**, run on the
  central machine once that office's peer is up and reachable. It uses *only* identities and files
  already resident on the central machine (the org's retained `Admin@org2.example.com` MSP, the
  genesis block, and the target peer's own TLS root CA — generated locally by `pack-join.sh` when it
  minted that peer's identity, never sent anywhere) to submit `peer channel join` against the
  *remote* peer's address. Nothing new is distributed to the office; the admin identity never leaves
  the central machine.

**Verified live, end-to-end, this session:** minted a fourth identity (`peer4`) with
`INCLUDE_ADMIN_MSP=false`; ran `office-node join` + `start` — confirmed it printed the "waiting for
remote join" message and did *not* attempt a local join; ran `remote-join.sh peer4 127.0.0.1:9061`
from a separate shell (standing in for the central admin's machine) — it joined successfully; the
still-running `office-node start` detected this and caught up to **block height 9, matching the
network exactly**, with no restart needed. This closes the follow-up cleanly: the stronger,
credential-never-distributed deployment mode is not just designed but proven to work, and is
available as an opt-in (`INCLUDE_ADMIN_MSP=false`) alongside the simpler default.
