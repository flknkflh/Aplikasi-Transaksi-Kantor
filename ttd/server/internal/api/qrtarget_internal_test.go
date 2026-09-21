package api

import (
	"net/http/httptest"
	"testing"
)

// The QR points at the address the signer's /stamp request came in on (their
// own session server URL). A loopback address is useless from another device,
// so it falls through to the bare verification ID.
func TestQRTarget(t *testing.T) {
	srv := &Server{cfg: Config{PublicBaseURL: "http://localhost:8443"}}

	// request Host is a real LAN IP -> QR is a link there
	r := httptest.NewRequest("POST", "http://172.16.23.177:8099/api/v1/signatures/x/stamp", nil)
	if got := srv.qrTarget(r, "sig_abc"); got != "http://172.16.23.177:8099/v/sig_abc" {
		t.Errorf("LAN host: got %q", got)
	}

	// explicit ?base= wins over Host
	r = httptest.NewRequest("POST", "http://172.16.23.177:8099/api/v1/signatures/x/stamp?base=http://10.0.0.5:8098", nil)
	if got := srv.qrTarget(r, "sig_abc"); got != "http://10.0.0.5:8098/v/sig_abc" {
		t.Errorf("?base=: got %q", got)
	}

	// everything loopback -> bare id
	r = httptest.NewRequest("POST", "http://localhost:8099/api/v1/signatures/x/stamp", nil)
	if got := srv.qrTarget(r, "sig_abc"); got != "sig_abc" {
		t.Errorf("loopback: got %q, want bare id", got)
	}

	// configured PublicBaseURL is used when Host is loopback but the config is real
	srv2 := &Server{cfg: Config{PublicBaseURL: "https://verify.example"}}
	r = httptest.NewRequest("POST", "http://127.0.0.1:8099/api/v1/signatures/x/stamp", nil)
	if got := srv2.qrTarget(r, "sig_abc"); got != "https://verify.example/v/sig_abc" {
		t.Errorf("configured base: got %q", got)
	}
}
