package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"ledger/api/internal/keystore"
)

// Integration tests for the office workflow. They need a real PostgreSQL
// (the SQL — locking, JSONB, unique indexes — is the point); point
// TEST_DATABASE_URL at any database server, e.g.
//
//	docker run -d -e POSTGRES_PASSWORD=t -p 55432:5432 postgres:16-alpine
//	TEST_DATABASE_URL=postgres://postgres:t@localhost:55432/postgres?sslmode=disable go test ./...
//
// Each test creates and drops its own database. Skipped when unset.

type memObjects struct {
	mu sync.Mutex
	m  map[string][]byte
}

func (o *memObjects) Put(_ context.Context, k string, d []byte, _ string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.m == nil {
		o.m = map[string][]byte{}
	}
	o.m[k] = append([]byte(nil), d...)
	return nil
}
func (o *memObjects) Get(_ context.Context, k string) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if d, ok := o.m[k]; ok {
		return d, nil
	}
	return nil, fmt.Errorf("no such object %s", k)
}

// fakeTTD stands in for the TTD server: tests register the signature records
// (and signed PDFs) it should vouch for.
type fakeTTD struct {
	recs map[string]TTDRecord
	pdfs map[string][]byte
}

func (f *fakeTTD) Record(_ context.Context, id string) (TTDRecord, error) {
	if r, ok := f.recs[id]; ok {
		return r, nil
	}
	return TTDRecord{}, fmt.Errorf("unknown signature")
}
func (f *fakeTTD) SignedPDF(_ context.Context, id string) ([]byte, error) {
	if p, ok := f.pdfs[id]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("no pdf")
}

type harness struct {
	t   *testing.T
	srv *Server
	h   http.Handler
	db  *pgxpool.Pool
	ttd *fakeTTD
	obj *memObjects
}

const testSecret = "test-proxy-secret"

func newHarness(t *testing.T) *harness {
	t.Helper()
	admin := os.Getenv("TEST_DATABASE_URL")
	if admin == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	adminPool, err := pgxpool.New(ctx, admin)
	if err != nil {
		t.Fatal(err)
	}
	name := "office_" + strings.ReplaceAll(strings.ToLower(t.Name()), "/", "_")
	if len(name) > 60 {
		name = name[:60]
	}
	_, _ = adminPool.Exec(ctx, "DROP DATABASE IF EXISTS "+name)
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+name); err != nil {
		t.Fatal(err)
	}
	cfg := adminPool.Config().ConnConfig
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%d/%s?sslmode=disable", cfg.User, cfg.Password, cfg.Host, cfg.Port, name)
	db, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		db.Close()
		_, _ = adminPool.Exec(ctx, "DROP DATABASE IF EXISTS "+name+" WITH (FORCE)")
		adminPool.Close()
	})

	files, _ := filepath.Glob(filepath.Join("..", "..", "..", "migrations", "*.up.sql"))
	sort.Strings(files)
	if len(files) < 3 {
		t.Fatalf("migrations not found: %v", files)
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(ctx, string(b)); err != nil {
			t.Fatalf("apply %s: %v", f, err)
		}
	}
	if _, err := db.Exec(ctx, `INSERT INTO organization (id,name,msp_id) VALUES ('org-a','Org A','Org1MSP')`); err != nil {
		t.Fatal(err)
	}
	ks, err := keystore.Open(filepath.Join(t.TempDir(), "ks.json"), db)
	if err != nil {
		t.Fatal(err)
	}
	obj := &memObjects{}
	ttd := &fakeTTD{recs: map[string]TTDRecord{}, pdfs: map[string][]byte{}}
	srv := &Server{
		DB: db, Keystore: ks, Objects: obj, TTD: ttd, Application: "test", Environment: "test", Bucket: "b",
		Logger: slog.New(slog.NewTextHandler(testWriter{t}, nil)),
		Office: &OfficeConfig{ProxySecret: testSecret},
	}
	return &harness{t: t, srv: srv, h: srv.Routes(), db: db, ttd: ttd, obj: obj}
}

type user struct{ id, role string } // role = TTD role (user/admin)

var (
	alice = user{"acct_alice", "user"} // requester
	bob   = user{"acct_bob", "user"}   // becomes approver
	carol = user{"acct_carol", "user"} // plain requester
	root  = user{"acct_root", "superadmin"}
)

func (h *harness) do(u *user, method, path string, body io.Reader, ctype string) (int, []byte) {
	h.t.Helper()
	req := httptest.NewRequest(method, "/office"+path, body)
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	if u != nil {
		req.Header.Set("X-Office-Secret", testSecret)
		req.Header.Set("X-Office-Account", u.id)
		req.Header.Set("X-Office-Email", u.id+"@test")
		req.Header.Set("X-Office-Name", strings.TrimPrefix(u.id, "acct_"))
		req.Header.Set("X-Office-Role", u.role)
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	b, _ := io.ReadAll(w.Body)
	return w.Code, b
}

func (h *harness) json(u *user, method, path string, v interface{}) (int, map[string]interface{}) {
	var body io.Reader
	if v != nil {
		b, _ := json.Marshal(v)
		body = bytes.NewReader(b)
	}
	code, raw := h.do(u, method, path, body, "application/json")
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return code, out
}

var samplePDF = []byte("%PDF-1.4\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF\n" + strings.Repeat("x", 200))

func (h *harness) create(u *user, title string, pdf []byte) (int, map[string]interface{}) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	_ = mw.WriteField("title", title)
	_ = mw.WriteField("category", "pengadaan")
	_ = mw.WriteField("amount", "1500000")
	_ = mw.WriteField("description", "Pembelian ATK")
	fw, _ := mw.CreateFormFile("file", "surat.pdf")
	_, _ = fw.Write(pdf)
	_ = mw.Close()
	code, raw := h.do(u, "POST", "/transactions", &buf, mw.FormDataContentType())
	var out map[string]interface{}
	_ = json.Unmarshal(raw, &out)
	return code, out
}

func (h *harness) makeApprover(u user) {
	h.t.Helper()
	if code, out := h.json(&root, "PUT", "/roles/"+u.id, map[string]string{"role": "approver", "email": u.id + "@test", "name": u.id}); code != 200 {
		h.t.Fatalf("set role: %d %v", code, out)
	}
}

func (h *harness) status(u *user, id string) string {
	h.t.Helper()
	code, out := h.json(u, "GET", "/transactions/"+id, nil)
	if code != 200 {
		h.t.Fatalf("get %s: %d %v", id, code, out)
	}
	return out["transaction"].(map[string]interface{})["status"].(string)
}

// registerSignature makes the fake TTD vouch for a signature by acct over the
// given original PDF; it returns the public id.
func (h *harness) registerSignature(id, acct string, original []byte) string {
	signed := append(append([]byte(nil), original...), []byte("\n%signed-by-"+id)...)
	h.ttd.recs[id] = TTDRecord{PublicID: id, AccountID: acct, OriginalSHA512: sha512Hex(original),
		SignedSHA512: sha512Hex(signed), VerificationStatus: "accepted", VerificationURL: "http://ttd/v/" + id}
	h.ttd.pdfs[id] = signed
	return id
}

func TestOfficeRequiresTheProxySecret(t *testing.T) {
	h := newHarness(t)
	for _, u := range []*user{nil} {
		if code, _ := h.do(u, "GET", "/me", nil, ""); code != 401 {
			t.Fatalf("no secret: %d", code)
		}
	}
	req := httptest.NewRequest("GET", "/office/me", nil)
	req.Header.Set("X-Office-Secret", "wrong")
	req.Header.Set("X-Office-Account", "x")
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	if w.Code != 401 {
		t.Fatalf("wrong secret: %d", w.Code)
	}
	if code, out := h.json(&alice, "GET", "/me", nil); code != 200 || out["office_role"] != "requester" {
		t.Fatalf("me: %d %v", code, out)
	}
}

func TestOfficeHappyPathSubmitApproveWithTTDComplete(t *testing.T) {
	h := newHarness(t)
	h.makeApprover(bob)

	code, out := h.create(&alice, "Beli ATK", samplePDF)
	if code != 201 {
		t.Fatalf("create: %d %v", code, out)
	}
	id := out["id"].(string)
	if h.status(&alice, id) != "DRAFT" {
		t.Fatal("new request must be DRAFT")
	}

	// Not visible to the approver's inbox until submitted; invisible to strangers always.
	if _, inbox := h.json(&bob, "GET", "/transactions?scope=inbox", nil); len(inbox["transactions"].([]interface{})) != 0 {
		t.Fatal("a DRAFT must not be in the approval inbox")
	}
	if code, _ := h.json(&carol, "GET", "/transactions/"+id, nil); code != 404 {
		t.Fatalf("another requester must not see it: %d", code)
	}

	if code, o := h.json(&alice, "POST", "/transactions/"+id+"/submit", nil); code != 200 {
		t.Fatalf("submit: %d %v", code, o)
	}
	if code, _ := h.json(&alice, "POST", "/transactions/"+id+"/submit", nil); code != 409 {
		t.Fatalf("second submit must conflict, got %d", code)
	}
	if _, inbox := h.json(&bob, "GET", "/transactions?scope=inbox", nil); len(inbox["transactions"].([]interface{})) != 1 {
		t.Fatal("the submitted request must be in the approver's inbox")
	}

	// The requester may not decide on their own request.
	sig := h.registerSignature("sig_own", alice.id, samplePDF)
	if code, _ := h.json(&alice, "POST", "/transactions/"+id+"/decision", map[string]string{"decision": "approve", "ttd_public_id": sig}); code != 403 {
		t.Fatalf("self-approval must be 403, got %d", code)
	}
	// A non-approver may not either.
	sigC := h.registerSignature("sig_carol", carol.id, samplePDF)
	if code, _ := h.json(&carol, "POST", "/transactions/"+id+"/decision", map[string]string{"decision": "approve", "ttd_public_id": sigC}); code != 404 && code != 403 {
		t.Fatalf("non-approver must be refused, got %d", code)
	}

	// The approver approves with their own TTD signature.
	good := h.registerSignature("sig_bob", bob.id, samplePDF)
	if code, o := h.json(&bob, "POST", "/transactions/"+id+"/decision", map[string]string{"decision": "approve", "ttd_public_id": good}); code != 200 {
		t.Fatalf("approve: %d %v", code, o)
	}
	if h.status(&alice, id) != "ENDORSED" {
		t.Fatal("approved request must be ENDORSED")
	}

	// Detail: events chained 1..3, signed document stored, TTD link exposed.
	_, det := h.json(&alice, "GET", "/transactions/"+id, nil)
	events := det["events"].([]interface{})
	var types []string
	for i, e := range events {
		em := e.(map[string]interface{})
		if int(em["sequence"].(float64)) != i+1 {
			t.Fatalf("event sequence gap: %v", events)
		}
		types = append(types, em["type"].(string))
	}
	if strings.Join(types, ",") != "CREATED,SUBMITTED,APPROVED_SIGNED" {
		t.Fatalf("events = %v", types)
	}
	if det["ttd"].(map[string]interface{})["public_id"] != "sig_bob" {
		t.Fatalf("ttd link missing: %v", det["ttd"])
	}
	kinds := map[string]string{}
	for _, d := range det["documents"].([]interface{}) {
		dm := d.(map[string]interface{})
		kinds[dm["kind"].(string)] = dm["id"].(string)
	}
	if kinds["attachment"] == "" || kinds["signed"] == "" {
		t.Fatalf("documents: %v", det["documents"])
	}
	// Both are downloadable by the requester, byte-exact; strangers get 404.
	if c, b := h.do(&alice, "GET", "/documents/"+kinds["signed"], nil, ""); c != 200 || !bytes.Equal(b, h.ttd.pdfs["sig_bob"]) {
		t.Fatalf("signed download: %d", c)
	}
	if c, _ := h.do(&carol, "GET", "/documents/"+kinds["attachment"], nil, ""); c != 404 {
		t.Fatalf("stranger download must be 404, got %d", c)
	}

	// The same TTD signature cannot back a second approval.
	_, o2 := h.create(&alice, "Lain", samplePDF)
	id2 := o2["id"].(string)
	h.json(&alice, "POST", "/transactions/"+id2+"/submit", nil)
	if code, _ := h.json(&bob, "POST", "/transactions/"+id2+"/decision", map[string]string{"decision": "approve", "ttd_public_id": good}); code == 200 {
		t.Fatal("a TTD signature must not be reusable for another request")
	}
	if h.status(&alice, id2) != "VERIFIED" {
		t.Fatal("a refused approval must leave the status untouched")
	}

	// Complete: requester only after approval.
	if code, _ := h.json(&carol, "POST", "/transactions/"+id+"/complete", nil); code == 200 {
		t.Fatal("a stranger must not complete")
	}
	if code, o := h.json(&alice, "POST", "/transactions/"+id+"/complete", nil); code != 200 {
		t.Fatalf("complete: %d %v", code, o)
	}
	if h.status(&alice, id) != "COMMITTED" {
		t.Fatal("completed request must be COMMITTED")
	}
	if code, _ := h.json(&alice, "POST", "/transactions/"+id+"/cancel", nil); code != 409 {
		t.Fatalf("cancel after commit must conflict, got %d", code)
	}

	// Every step is queued for the ledger in order, with the on-chain approval last-but-in-sequence.
	rows, err := h.db.Query(context.Background(), `SELECT fn_name, status FROM outbox_event WHERE aggregate_id=$1 ORDER BY created_at`, id)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var fns []string
	for rows.Next() {
		var fn, st string
		_ = rows.Scan(&fn, &st)
		if st != "pending" {
			t.Fatalf("with Fabric disabled events stay pending, got %s", st)
		}
		fns = append(fns, fn)
	}
	want := "CreateTransaction,RecordEvent,RecordEvent,RecordEvent,Approve,RecordEvent"
	if strings.Join(fns, ",") != want {
		t.Fatalf("outbox order = %v, want %s", fns, want)
	}
	if det["ledger"].(map[string]interface{})["state"] != "queued" {
		t.Fatalf("ledger state: %v", det["ledger"])
	}
}

func TestOfficeRefusesForgedOrMismatchedTTDApprovals(t *testing.T) {
	h := newHarness(t)
	h.makeApprover(bob)
	_, out := h.create(&alice, "Beli ATK", samplePDF)
	id := out["id"].(string)
	h.json(&alice, "POST", "/transactions/"+id+"/submit", nil)

	other := append([]byte("%PDF-1.4 something else\n"), bytes.Repeat([]byte("y"), 100)...)
	cases := map[string]func() string{
		"unknown signature": func() string { return "sig_missing" },
		"someone else's":    func() string { return h.registerSignature("sig_x1", carol.id, samplePDF) },
		"another document":  func() string { return h.registerSignature("sig_x2", bob.id, other) },
		"not accepted by server": func() string {
			s := h.registerSignature("sig_x3", bob.id, samplePDF)
			r := h.ttd.recs[s]
			r.VerificationStatus = "stored_unverified"
			h.ttd.recs[s] = r
			return s
		},
		"signed bytes swapped": func() string {
			s := h.registerSignature("sig_x4", bob.id, samplePDF)
			h.ttd.pdfs[s] = []byte("%PDF-1.4 tampered")
			return s
		},
	}
	for name, mk := range cases {
		sig := mk()
		code, o := h.json(&bob, "POST", "/transactions/"+id+"/decision", map[string]string{"decision": "approve", "ttd_public_id": sig})
		if code == 200 {
			t.Errorf("%s: must be refused", name)
		}
		if st := h.status(&alice, id); st != "VERIFIED" {
			t.Errorf("%s: status moved to %s (%v)", name, st, o)
		}
	}
	if code, _ := h.json(&bob, "POST", "/transactions/"+id+"/decision", map[string]string{"decision": "approve"}); code != 400 {
		t.Errorf("approve without a TTD signature must be 400, got %d", code)
	}
	var n int
	_ = h.db.QueryRow(context.Background(), `SELECT count(*) FROM document_reference WHERE kind='signed'`).Scan(&n)
	if n != 0 {
		t.Errorf("refused approvals must not store signed documents, found %d", n)
	}
}

func TestOfficeRejectAndCancelAndValidation(t *testing.T) {
	h := newHarness(t)
	h.makeApprover(bob)

	_, out := h.create(&alice, "Ditolak", samplePDF)
	id := out["id"].(string)
	h.json(&alice, "POST", "/transactions/"+id+"/submit", nil)
	if code, _ := h.json(&bob, "POST", "/transactions/"+id+"/decision", map[string]string{"decision": "reject"}); code != 400 {
		t.Fatalf("reject needs a reason: %d", code)
	}
	if code, o := h.json(&bob, "POST", "/transactions/"+id+"/decision", map[string]string{"decision": "reject", "reason": "Anggaran tidak tersedia"}); code != 200 {
		t.Fatalf("reject: %d %v", code, o)
	}
	if h.status(&alice, id) != "REJECTED" {
		t.Fatal("must be REJECTED")
	}
	var approves int
	_ = h.db.QueryRow(context.Background(), `SELECT count(*) FROM outbox_event WHERE aggregate_id=$1 AND fn_name='Approve'`, id).Scan(&approves)
	if approves != 0 {
		t.Fatal("a rejection must not queue the chaincode Approve (it would collide with the REJECTED event)")
	}

	// Cancel a fresh DRAFT; a stranger cannot.
	_, o2 := h.create(&alice, "Batal", samplePDF)
	id2 := o2["id"].(string)
	if code, _ := h.json(&carol, "POST", "/transactions/"+id2+"/cancel", nil); code == 200 {
		t.Fatal("stranger cancelled")
	}
	if code, _ := h.json(&alice, "POST", "/transactions/"+id2+"/cancel", nil); code != 200 || h.status(&alice, id2) != "CANCELLED" {
		t.Fatal("creator must be able to cancel a DRAFT")
	}

	// Validation
	if code, _ := h.create(&alice, "Bukan PDF", []byte("hello world, not a pdf")); code != 400 {
		t.Fatalf("non-PDF attachment must be 400, got %d", code)
	}
	if code, _ := h.create(&alice, "ab", samplePDF); code != 400 {
		t.Fatalf("short title must be 400, got %d", code)
	}
	// Roles are admin-only.
	if code, _ := h.json(&alice, "PUT", "/roles/"+carol.id, map[string]string{"role": "approver"}); code != 403 {
		t.Fatalf("a requester must not assign roles: %d", code)
	}
	if code, _ := h.json(&root, "PUT", "/roles/"+carol.id, map[string]string{"role": "superuser"}); code != 400 {
		t.Fatalf("unknown role must be 400: %d", code)
	}
}

func TestOfficeListScopes(t *testing.T) {
	h := newHarness(t)
	h.makeApprover(bob)
	h.create(&alice, "Alice satu", samplePDF)
	h.create(&carol, "Carol satu", samplePDF)

	count := func(u *user, q string) int {
		_, o := h.json(u, "GET", "/transactions"+q, nil)
		return len(o["transactions"].([]interface{}))
	}
	if n := count(&alice, "?scope=mine"); n != 1 {
		t.Fatalf("alice mine = %d", n)
	}
	if n := count(&alice, "?scope=all"); n != 1 {
		t.Fatalf("a requester's 'all' must still be only their own, got %d", n)
	}
	if n := count(&bob, "?scope=all"); n != 2 {
		t.Fatalf("an approver sees everything, got %d", n)
	}
	if n := count(&root, "?scope=all"); n != 2 {
		t.Fatalf("an admin sees everything, got %d", n)
	}
	if n := count(&bob, "?scope=all&status=DRAFT"); n != 2 {
		t.Fatalf("status filter: %d", n)
	}
}

// testWriter routes server log lines into the test log (shown on failure).
type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}
