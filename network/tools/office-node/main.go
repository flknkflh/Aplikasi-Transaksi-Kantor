// Command office-node is what an office runs to become a real, additional
// node on the shared blockchain (docs/adr/0011-office-node.md): a single
// program that extracts a join package (issued once by the central admin
// via pack-join.sh — the one deliberate approval step a permissioned
// network cannot skip, see the ADR) and then runs a genuine Hyperledger
// Fabric peer process, joins the channel, and keeps an independently
// validated copy of the ledger in sync for as long as it runs.
//
// It does NOT run the office's web app or database — those stay on the one
// shared central server exactly as before (docs/adr/0004,0009). This is
// "Bagian 2" of network/MULTI-HOST-LAB.md, packaged as one program instead
// of a page of manual peer-CLI commands.
//
//	office-node join <package.zip>   # one-time: unpack the identity/certs the admin gave you
//	office-node start                # run the peer, join the channel on first run, then stay up
//	office-node status                # one-off: how far behind/caught-up is this node
package main

import (
	"archive/zip"
	"bufio"
	_ "embed"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
)

//go:embed core.yaml
var embeddedCoreYAML []byte

type joinConfig struct {
	OrgLabel           string `json:"org_label"`
	MSPID              string `json:"msp_id"`
	PeerID             string `json:"peer_id"`
	ChannelName        string `json:"channel_name"`
	PeerPort           int    `json:"peer_port"`
	PeerChaincodePort  int    `json:"peer_chaincode_port"`
	PeerOperationsPort int    `json:"peer_operations_port"`
	OrdererAddress     string `json:"orderer_address"`
	OrdererHostname    string `json:"orderer_hostname"`
	// OrdererReachableAddr, when set, is where the orderer is ACTUALLY reachable
	// from this office (an IP:port — LAN address for a real cross-machine
	// deployment, 127.0.0.1:port for same-machine testing). OrdererAddress stays
	// the hostname:port baked into the channel config and TLS cert (e.g.
	// "orderer.example.com:7050"), which a native, non-Dockerized peer usually
	// cannot resolve by DNS (docs/adr/0011 bug #4). When this is set, cmdJoin
	// writes a deliveryclient.addressOverrides entry into core.yaml so the peer
	// dials OrdererReachableAddr while still verifying the TLS cert against
	// OrdererHostname — no hosts-file or DNS change needed on the office machine.
	OrdererReachableAddr string `json:"orderer_reachable_addr"`
}

type nodeState struct {
	ChannelJoined bool `json:"channel_joined"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "join":
		err = cmdJoin(os.Args[2:])
	case "start":
		err = cmdStart(os.Args[2:])
	case "status":
		err = cmdStatus(os.Args[2:])
	default:
		usage()
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "office-node:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `office-node join <package.zip>   one-time setup from the admin's join package
office-node start                run the peer node, join the channel if needed, stay up
office-node status                one-off: this node's ledger height`)
}

// --- paths -----------------------------------------------------------

func exeDir() string {
	exe, err := os.Executable()
	if err != nil {
		return "."
	}
	return filepath.Dir(exe)
}

func dataDir() string       { return filepath.Join(exeDir(), "office-node-data") }
func joinDir() string       { return filepath.Join(dataDir(), "join") }
func peerCfgDir() string    { return filepath.Join(dataDir(), "peercfg") }
func productionDir() string { return filepath.Join(dataDir(), "production") }
func statePath() string     { return filepath.Join(dataDir(), "state.json") }
func joinJSONPath() string  { return filepath.Join(joinDir(), "join.json") }

// --- join --------------------------------------------------------------

func cmdJoin(args []string) error {
	fs := flag.NewFlagSet("join", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() != 1 {
		return fmt.Errorf("usage: office-node join <package.zip>")
	}
	pkgPath := fs.Arg(0)

	if _, err := os.Stat(joinJSONPath()); err == nil {
		return fmt.Errorf("already joined (found %s) — delete %s first if you really want to re-join", joinJSONPath(), dataDir())
	}

	if err := os.MkdirAll(joinDir(), 0o700); err != nil {
		return err
	}
	if err := unzip(pkgPath, joinDir()); err != nil {
		return fmt.Errorf("extract package: %w", err)
	}

	cfg, err := loadJoinConfig()
	if err != nil {
		os.RemoveAll(joinDir())
		return fmt.Errorf("package did not contain a valid join.json: %w", err)
	}
	// admin-msp is intentionally NOT required here — pack-join.sh can omit it
	// (INCLUDE_ADMIN_MSP=false) so this office never holds an admin credential
	// at all; see the admin-msp handling in cmdStart and remote-join.sh.
	for _, must := range []string{"msp", "tls/server.crt", "tls/server.key", "tls/ca.crt", "orderer-tls-ca.crt", "genesis.block"} {
		if _, err := os.Stat(filepath.Join(joinDir(), must)); err != nil {
			os.RemoveAll(joinDir())
			return fmt.Errorf("package is missing %s — it may be corrupt or incomplete", must)
		}
	}

	if err := os.MkdirAll(peerCfgDir(), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(peerCfgDir(), "core.yaml"), embeddedCoreYAML, 0o644); err != nil {
		return err
	}
	if err := os.MkdirAll(productionDir(), 0o755); err != nil {
		return err
	}
	if err := writeState(nodeState{ChannelJoined: false}); err != nil {
		return err
	}

	fmt.Printf("Bergabung sebagai %q (peer %s, MSP %s) untuk channel %q.\n", cfg.OrgLabel, cfg.PeerID, cfg.MSPID, cfg.ChannelName)
	ensureOrdererHostsEntry(cfg)
	fmt.Println("Jalankan `office-node start` untuk menyalakan node-nya.")
	return nil
}

// ensureOrdererHostsEntry tries to make cfg.OrdererHostname resolve to
// cfg.OrdererReachableAddr's host by appending a line to the OS hosts file —
// best-effort, never fatal. The channel config bakes in per-org orderer
// endpoints by their configured hostname (docs/adr/0011 bug #4); a native,
// non-Dockerized peer has no other DNS source for that hostname. A local
// core.yaml deliveryclient.addressOverrides entry was tried first and does NOT
// work here: Fabric's own log says so plainly — "Config defines both orderer
// org specific endpoints and global endpoints, global endpoints will be
// ignored" — the override only ever covered the legacy global address, and
// this channel (like most modern configtx.yaml profiles) uses per-org
// endpoints instead. The hosts file is therefore the one mechanism actually
// proven to work (verified end-to-end on both Linux and native Windows).
func ensureOrdererHostsEntry(cfg joinConfig) {
	if cfg.OrdererReachableAddr == "" {
		return
	}
	ip, _, ok := strings.Cut(cfg.OrdererReachableAddr, ":")
	if !ok || ip == "" || ip == cfg.OrdererHostname {
		return
	}
	path := "/etc/hosts"
	if runtime.GOOS == "windows" {
		sysroot := os.Getenv("SystemRoot")
		if sysroot == "" {
			sysroot = `C:\Windows`
		}
		path = filepath.Join(sysroot, "System32", "drivers", "etc", "hosts")
	}
	existing, err := os.ReadFile(path)
	if err == nil && strings.Contains(string(existing), cfg.OrdererHostname) {
		return // already there (a previous join, or someone set it up manually) — leave it alone
	}
	line := fmt.Sprintf("\n%s %s # added by office-node join (%s)\n", ip, cfg.OrdererHostname, cfg.PeerID)
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		warnHostsEntryNeeded(path, ip, cfg.OrdererHostname, err)
		return
	}
	defer f.Close()
	if _, err := f.WriteString(line); err != nil {
		warnHostsEntryNeeded(path, ip, cfg.OrdererHostname, err)
	}
}

func warnHostsEntryNeeded(path, ip, hostname string, cause error) {
	admin := "sudo"
	if runtime.GOOS == "windows" {
		admin = "an elevated (Administrator) prompt"
	}
	fmt.Printf("PERINGATAN: tidak bisa menulis %s otomatis (%v).\n", path, cause)
	fmt.Printf("  Node ini TIDAK akan bisa sinkron sampai ini ditambahkan — pakai %s, tambahkan baris:\n", admin)
	fmt.Printf("    %s %s\n", ip, hostname)
}

// --- start ---------------------------------------------------------------

func cmdStart(args []string) error {
	fs := flag.NewFlagSet("start", flag.ExitOnError)
	advertise := fs.String("advertise", "127.0.0.1", "alamat yang diumumkan ke peer lain untuk menjangkau node ini (LAN IP komputer ini pada pemakaian sungguhan)")
	peerBin := fs.String("peer-bin", "", "path ke binary peer Fabric (default: cari 'peer'/'peer.exe' di samping office-node, lalu di PATH)")
	fs.Parse(args)

	cfg, err := loadJoinConfig()
	if err != nil {
		return fmt.Errorf("belum join — jalankan `office-node join <package.zip>` dulu (%w)", err)
	}
	bin, err := resolvePeerBinary(*peerBin)
	if err != nil {
		return err
	}

	env := peerEnv(cfg, *advertise)

	fmt.Printf("Menjalankan peer %s (org %s) — dengar di %s:%d\n", cfg.PeerID, cfg.OrgLabel, *advertise, cfg.PeerPort)
	cmd := exec.Command(bin, "node", "start")
	cmd.Env = env
	stdout, _ := cmd.StdoutPipe()
	stderr, _ := cmd.StderrPipe()
	go prefixCopy("peer", stdout)
	go prefixCopy("peer", stderr)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start peer process: %w", err)
	}

	// stop the child cleanly on Ctrl+C / termination instead of leaving it orphaned
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	addr := fmt.Sprintf("127.0.0.1:%d", cfg.PeerPort)
	if !waitForPort(addr, 30*time.Second) {
		fmt.Println("!! peer belum menerima koneksi setelah 30 detik — cek log 'peer' di atas untuk error")
	} else {
		fmt.Println(">> peer aktif dan mendengarkan.")
		st, _ := readState()
		if !st.ChannelJoined {
			if _, err := os.Stat(filepath.Join(joinDir(), "admin-msp")); err != nil {
				// No admin-msp in this package (pack-join.sh run with
				// INCLUDE_ADMIN_MSP=false — see ADR-0011): this office never holds an
				// admin credential, so it cannot join itself. The central admin joins
				// it remotely instead (network/tools/office-node/remote-join.sh),
				// using an identity that never left the central machine. Just keep
				// running and polling — statusLoop below reports "belum join" until
				// that remote join happens.
				fmt.Println(">> tidak ada admin-msp di paket ini — menunggu admin pusat men-join node ini dari jarak jauh (lihat remote-join.sh).")
			} else if err := joinChannel(bin, cfg, env); err != nil {
				fmt.Println("!! gagal join channel:", err)
			} else {
				fmt.Println(">> berhasil join channel", cfg.ChannelName)
				_ = writeState(nodeState{ChannelJoined: true})
			}
		}
		go statusLoop(bin, cfg, env, done)
	}

	select {
	case <-sigCh:
		fmt.Println("\n>> berhenti diminta, mematikan peer...")
		_ = cmd.Process.Kill()
		<-done
	case err := <-done:
		if err != nil {
			return fmt.Errorf("proses peer berhenti sendiri: %w", err)
		}
	}
	return nil
}

// joinChannel asks the LOCAL peer (still addressed via env's CORE_PEER_ADDRESS)
// to create the channel's ledger from the genesis block. Fabric's default
// Admins policy on this action requires an identity with OU=admin — the peer's
// own server identity (OU=peer) is correctly refused, so this swaps in the
// admin identity from the join package for just this one call (see
// pack-join.sh's comment on admin-msp for the v1 trust tradeoff that implies).
func joinChannel(bin string, cfg joinConfig, env []string) error {
	genesis := filepath.Join(joinDir(), "genesis.block")
	cmd := exec.Command(bin, "channel", "join", "-b", genesis)
	cmd.Env = withAdminMSP(env)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// withAdminMSP returns env with CORE_PEER_MSPCONFIGPATH swapped to the join
// package's admin identity, for the handful of CLI calls that need it.
func withAdminMSP(env []string) []string {
	out := make([]string, 0, len(env))
	adminMSP := filepath.Join(joinDir(), "admin-msp")
	for _, kv := range env {
		if strings.HasPrefix(kv, "CORE_PEER_MSPCONFIGPATH=") {
			continue
		}
		out = append(out, kv)
	}
	return append(out, "CORE_PEER_MSPCONFIGPATH="+adminMSP)
}

func statusLoop(bin string, cfg joinConfig, env []string, done <-chan error) {
	t := time.NewTicker(20 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			h, err := ledgerHeight(bin, cfg, env)
			if err != nil {
				fmt.Println(">> status: gagal cek tinggi ledger:", err)
				continue
			}
			fmt.Printf(">> status: tersambung, tinggi ledger channel %q = %d blok\n", cfg.ChannelName, h)
		}
	}
}

// --- status --------------------------------------------------------------

func cmdStatus(args []string) error {
	fs := flag.NewFlagSet("status", flag.ExitOnError)
	advertise := fs.String("advertise", "127.0.0.1", "alamat yang diumumkan node ini (lihat 'start')")
	peerBin := fs.String("peer-bin", "", "path ke binary peer Fabric")
	fs.Parse(args)

	cfg, err := loadJoinConfig()
	if err != nil {
		return fmt.Errorf("belum join: %w", err)
	}
	bin, err := resolvePeerBinary(*peerBin)
	if err != nil {
		return err
	}
	env := peerEnv(cfg, *advertise)
	h, err := ledgerHeight(bin, cfg, env)
	if err != nil {
		return fmt.Errorf("node ini sepertinya tidak sedang jalan (jalankan 'office-node start' di jendela lain dulu): %w", err)
	}
	fmt.Printf("Kantor: %s\nPeer: %s (%s)\nChannel: %s\nTinggi ledger: %d blok\n", cfg.OrgLabel, cfg.PeerID, cfg.MSPID, cfg.ChannelName, h)
	return nil
}

func ledgerHeight(bin string, cfg joinConfig, env []string) (int, error) {
	cmd := exec.Command(bin, "channel", "getinfo", "-c", cfg.ChannelName)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		return 0, fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	// output looks like: Blockchain info: {"height":7,"currentBlockHash":"..."}
	idx := strings.Index(string(out), "{")
	if idx < 0 {
		return 0, fmt.Errorf("unexpected output: %s", out)
	}
	var info struct {
		Height int `json:"height"`
	}
	if err := json.Unmarshal(out[idx:], &info); err != nil {
		return 0, err
	}
	return info.Height, nil
}

// --- env / config ----------------------------------------------------

func peerEnv(cfg joinConfig, advertise string) []string {
	env := os.Environ()
	set := func(k, v string) { env = append(env, k+"="+v) }
	set("FABRIC_CFG_PATH", peerCfgDir())
	set("FABRIC_LOGGING_SPEC", "INFO")
	set("CORE_PEER_TLS_ENABLED", "true")
	set("CORE_PEER_PROFILE_ENABLED", "false")
	set("CORE_PEER_TLS_CERT_FILE", filepath.Join(joinDir(), "tls", "server.crt"))
	set("CORE_PEER_TLS_KEY_FILE", filepath.Join(joinDir(), "tls", "server.key"))
	set("CORE_PEER_TLS_ROOTCERT_FILE", filepath.Join(joinDir(), "tls", "ca.crt"))
	set("CORE_PEER_ID", cfg.PeerID)
	set("CORE_PEER_ADDRESS", fmt.Sprintf("%s:%d", advertise, cfg.PeerPort))
	set("CORE_PEER_LISTENADDRESS", fmt.Sprintf("0.0.0.0:%d", cfg.PeerPort))
	set("CORE_PEER_CHAINCODEADDRESS", fmt.Sprintf("%s:%d", advertise, cfg.PeerChaincodePort))
	set("CORE_PEER_CHAINCODELISTENADDRESS", fmt.Sprintf("0.0.0.0:%d", cfg.PeerChaincodePort))
	set("CORE_PEER_GOSSIP_BOOTSTRAP", fmt.Sprintf("%s:%d", advertise, cfg.PeerPort))
	set("CORE_PEER_GOSSIP_EXTERNALENDPOINT", fmt.Sprintf("%s:%d", advertise, cfg.PeerPort))
	set("CORE_PEER_LOCALMSPID", cfg.MSPID)
	set("CORE_PEER_MSPCONFIGPATH", filepath.Join(joinDir(), "msp"))
	set("CORE_PEER_FILESYSTEMPATH", productionDir())
	// core.yaml (embedded from fabric-samples, meant for a Docker container that owns
	// /var/hyperledger) hardcodes ledger.snapshots.rootDir separately from
	// peer.fileSystemPath — running as a plain OS process without that directory
	// (and without permission to create it) makes the peer panic on startup unless
	// this is overridden too.
	set("CORE_LEDGER_SNAPSHOTS_ROOTDIR", filepath.Join(productionDir(), "snapshots"))
	set("CORE_OPERATIONS_LISTENADDRESS", fmt.Sprintf("0.0.0.0:%d", cfg.PeerOperationsPort))
	set("CORE_METRICS_PROVIDER", "disabled")
	set("CORE_CHAINCODE_EXECUTETIMEOUT", "300s")
	// ORDERER_CA is for any future CLI call that actually talks to the orderer
	// (e.g. chaincode approve/commit) — pass --ordererTLSHostnameOverride as a
	// per-command FLAG on those, never as a global env var here: this env is
	// also read by `peer channel join`/`getinfo`, which talk to this peer's OWN
	// admin API on CORE_PEER_ADDRESS, not the orderer — setting the override
	// globally made the CLI expect *this peer's* TLS cert to say
	// "orderer.example.com", which it correctly doesn't, and every local call
	// failed TLS verification.
	set("ORDERER_CA", filepath.Join(joinDir(), "orderer-tls-ca.crt"))
	return env
}

func loadJoinConfig() (joinConfig, error) {
	var cfg joinConfig
	b, err := os.ReadFile(joinJSONPath())
	if err != nil {
		return cfg, err
	}
	if err := json.Unmarshal(b, &cfg); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func readState() (nodeState, error) {
	var st nodeState
	b, err := os.ReadFile(statePath())
	if err != nil {
		return st, nil // no state file yet = not joined
	}
	_ = json.Unmarshal(b, &st)
	return st, nil
}

func writeState(st nodeState) error {
	b, _ := json.MarshalIndent(st, "", "  ")
	return os.WriteFile(statePath(), b, 0o644)
}

// --- helpers -----------------------------------------------------------

func resolvePeerBinary(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	name := "peer"
	if runtime.GOOS == "windows" {
		name = "peer.exe"
	}
	local := filepath.Join(exeDir(), name)
	if _, err := os.Stat(local); err == nil {
		return local, nil
	}
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("binary %q tidak ditemukan di samping office-node maupun di PATH — taruh binary peer Fabric (unduh dari rilis Hyperledger Fabric) di folder yang sama dengan office-node, atau pakai -peer-bin", name)
}

func waitForPort(addr string, timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		conn, err := net.DialTimeout("tcp", addr, time.Second)
		if err == nil {
			conn.Close()
			return true
		}
		time.Sleep(500 * time.Millisecond)
	}
	return false
}

func prefixCopy(prefix string, r io.Reader) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		fmt.Printf("[%s] %s\n", prefix, sc.Text())
	}
}

func unzip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()
	for _, f := range r.File {
		path := filepath.Join(dest, f.Name)
		if !strings.HasPrefix(path, filepath.Clean(dest)+string(os.PathSeparator)) && path != filepath.Clean(dest) {
			return fmt.Errorf("entri zip tidak aman: %s", f.Name)
		}
		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(path, 0o755); err != nil {
				return err
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		rc, err := f.Open()
		if err != nil {
			return err
		}
		out, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
		if err != nil {
			rc.Close()
			return err
		}
		_, err = io.Copy(out, rc)
		rc.Close()
		out.Close()
		if err != nil {
			return err
		}
	}
	return nil
}
