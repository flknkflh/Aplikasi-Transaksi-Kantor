package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// Integration tests for the archive (upload -> server-side signature -> ledger
// events -> receipt -> admin console). Same requirements as office_test.go
// (TEST_DATABASE_URL); the object store and TTD are in-memory fakes.

var (
	dina  = user{"acct_dina", "user"}  // sender, office A
	eko   = user{"acct_eko", "user"}   // sender, office B
	fajar = user{"acct_fajar", "user"} // has an account but no office yet
)

func (h *harness) req(u *user, method, path string, body []byte, hdr map[string]string) (int, []byte) {
	h.t.Helper()
	req := httptest.NewRequest(method, "/office"+path, bytes.NewReader(body))
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	if u != nil {
		req.Header.Set("X-Office-Secret", testSecret)
		req.Header.Set("X-Office-Account", u.id)
		req.Header.Set("X-Office-Email", u.id+"@test")
		req.Header.Set("X-Office-Name", strings.TrimPrefix(u.id, "acct_"))
		req.Header.Set("X-Office-Role", u.role)
		req.Header.Set("X-Forwarded-For", "203.0.113.7")
	}
	w := httptest.NewRecorder()
	h.h.ServeHTTP(w, req)
	b, _ := io.ReadAll(w.Body)
	return w.Code, b
}

func asMap(b []byte) map[string]interface{} {
	var m map[string]interface{}
	_ = json.Unmarshal(b, &m)
	return m
}

func (h *harness) office(name string) string {
	h.t.Helper()
	code, out := h.json(&root, "POST", "/archive/offices", map[string]string{"name": name})
	if code != 201 {
		h.t.Fatalf("create office %q: %d %v", name, code, out)
	}
	return out["id"].(string)
}

func (h *harness) assign(u user, office string) {
	h.t.Helper()
	if code, out := h.json(&root, "PUT", "/archive/members/"+u.id, map[string]string{"organization_id": office, "email": u.id + "@test", "name": strings.TrimPrefix(u.id, "acct_")}); code != 200 {
		h.t.Fatalf("assign: %d %v", code, out)
	}
}

func randomBytes(n int) []byte { b := make([]byte, n); _, _ = rand.Read(b); return b }

func sum256(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// startUpload begins an upload and returns its id.
func (h *harness) startUpload(u *user, name string, size int) string {
	h.t.Helper()
	code, out := h.json(u, "POST", "/archive/uploads", map[string]interface{}{"file_name": name, "size": size, "media_type": "application/zip", "description": "uji"})
	if code != 201 {
		h.t.Fatalf("start upload: %d %v", code, out)
	}
	return out["upload_id"].(string)
}

func (h *harness) chunk(u *user, id string, offset int, data []byte) (int, map[string]interface{}) {
	code, b := h.req(u, "PATCH", "/archive/uploads/"+id, data, map[string]string{"Upload-Offset": strconv.Itoa(offset), "Content-Type": "application/offset+octet-stream"})
	return code, asMap(b)
}

// upload sends data in chunks of the given size and completes it.
func (h *harness) upload(u *user, name string, data []byte, chunk int) (int, map[string]interface{}) {
	h.t.Helper()
	id := h.startUpload(u, name, len(data))
	for off := 0; off < len(data); off += chunk {
		end := min(off+chunk, len(data))
		if code, out := h.chunk(u, id, off, data[off:end]); code != 200 {
			h.t.Fatalf("chunk @%d: %d %v", off, code, out)
		}
	}
	return h.json(u, "POST", "/archive/uploads/"+id+"/complete", map[string]string{"client_sha256": sum256(data)})
}

func TestArchiveUploadIsSignedChainedAndVerifiable(t *testing.T) {
	h := newHarness(t)
	officeA, officeB := h.office("Kantor Cabang A"), h.office("Kantor Cabang B")
	h.assign(dina, officeA)
	h.assign(eko, officeB)

	data := randomBytes(3<<20 + 12345)
	code, rc := h.upload(&dina, "laporan/../q3 final.zip", data, 1<<20)
	if code != 201 {
		t.Fatalf("complete: %d %v", code, rc)
	}
	receipt := rc["receipt"].(map[string]interface{})
	body := receipt["body"].(map[string]interface{})
	manifest := body["manifest"].(map[string]interface{})
	if manifest["sha256"] != sum256(data) || int(manifest["size_bytes"].(float64)) != len(data) {
		t.Fatalf("manifest does not describe the upload: %v", manifest)
	}
	if manifest["file_name"] != "q3 final.zip" {
		t.Fatalf("the file name must be sanitized to a base name, got %q", manifest["file_name"])
	}
	if manifest["organization_name"] != "Kantor Cabang A" || manifest["sender_id"] != dina.id || manifest["client_ip"] != "203.0.113.7" {
		t.Fatalf("manifest identity fields: %v", manifest)
	}
	if !strings.HasPrefix(rc["receipt_id"].(string), "rcp_") || len(rc["receipt_id"].(string)) < 30 {
		t.Fatalf("receipt id must be long and unguessable: %v", rc["receipt_id"])
	}
	if receipt["server_signature"].(map[string]interface{})["algorithm_suite"] != "HYBRID_ED25519_MLDSA65_V1" {
		t.Fatalf("receipt must be signed with the hybrid suite: %v", receipt["server_signature"])
	}

	// The whole chain is recorded: create + 3 events, status ENDORSED, queued for the ledger in order.
	var status, txnID string
	var events int
	if err := h.db.QueryRow(context.Background(), `SELECT t.status, t.id, (SELECT count(*) FROM transaction_event e WHERE e.transaction_id=t.id) FROM transaction t WHERE t.workflow_type='arsip-kiriman'`).Scan(&status, &txnID, &events); err != nil {
		t.Fatal(err)
	}
	if status != "ENDORSED" || events != 3 {
		t.Fatalf("status=%s events=%d", status, events)
	}
	rows, _ := h.db.Query(context.Background(), `SELECT fn_name FROM outbox_event WHERE aggregate_id=$1 ORDER BY created_at`, txnID)
	var fns []string
	for rows.Next() {
		var f string
		_ = rows.Scan(&f)
		fns = append(fns, f)
	}
	rows.Close()
	if strings.Join(fns, ",") != "CreateTransaction,RecordEvent,RecordEvent,RecordEvent" {
		t.Fatalf("outbox = %v", fns)
	}
	ledger := rc["ledger"].(map[string]interface{})
	if ledger["state"] != "queued" {
		t.Fatalf("ledger: %v", ledger)
	}

	// The admin sees it, downloads the identical bytes, and verification passes (deep).
	code, list := h.json(&root, "GET", "/archive/items", nil)
	if code != 200 || int(list["total"].(float64)) != 1 {
		t.Fatalf("admin list: %d %v", code, list)
	}
	itemID := list["items"].([]interface{})[0].(map[string]interface{})["id"].(string)
	if c, dl := h.req(&root, "GET", "/archive/items/"+itemID+"/download", nil, nil); c != 200 || !bytes.Equal(dl, data) {
		t.Fatalf("download must return exactly the uploaded bytes: %d", c)
	}
	code, ver := h.json(&root, "POST", "/archive/items/"+itemID+"/verify?deep=1", nil)
	if code != 200 || ver["ok"] != true {
		t.Fatalf("verify: %d %v", code, ver)
	}
	names := map[string]bool{}
	for _, c := range ver["checks"].([]interface{}) {
		cm := c.(map[string]interface{})
		names[cm["name"].(string)] = cm["ok"].(bool)
	}
	for _, want := range []string{"manifest_hash", "sender_signature", "event_chain", "event_signatures", "receipt_signature", "stored_file"} {
		if !names[want] {
			t.Errorf("check %q missing or failed: %v", want, names)
		}
	}
	// Admin access is itself logged.
	var accesses int
	_ = h.db.QueryRow(context.Background(), `SELECT count(*) FROM archive_access`).Scan(&accesses)
	if accesses < 2 {
		t.Errorf("admin downloads/verifications must be logged, got %d", accesses)
	}

	// Access control: a sender sees nothing but their own receipt.
	for _, p := range []string{"/archive/items", "/archive/items/" + itemID, "/archive/items/" + itemID + "/download", "/archive/stats", "/archive/offices", "/archive/members"} {
		if c, _ := h.req(&dina, "GET", p, nil, nil); c != 403 {
			t.Errorf("a sender must not reach %s (got %d)", p, c)
		}
	}
	if c, _ := h.req(&dina, "GET", "/archive/receipts/"+rc["receipt_id"].(string), nil, nil); c != 200 {
		t.Errorf("the sender must be able to re-fetch their own receipt: %d", c)
	}
	if c, _ := h.req(&eko, "GET", "/archive/receipts/"+rc["receipt_id"].(string), nil, nil); c != 404 {
		t.Errorf("another office's sender must not get the receipt: %d", c)
	}
	if c, _ := h.req(&dina, "POST", "/archive/items/"+itemID+"/verify", nil, nil); c != 403 {
		t.Errorf("verify is admin-only: %d", c)
	}
}

func TestArchiveUploadCanBeResumedAndSurvivesARestart(t *testing.T) {
	h := newHarness(t)
	h.assign(dina, h.office("Kantor A"))
	data := randomBytes(2<<20 + 77)
	id := h.startUpload(&dina, "besar.bin", len(data))

	if c, o := h.chunk(&dina, id, 0, data[:1<<20]); c != 200 {
		t.Fatalf("first chunk: %d %v", c, o)
	}
	// the same chunk again (a client that did not see the reply) is refused, with the real offset
	c, o := h.chunk(&dina, id, 0, data[:1<<20])
	if c != 409 || int(o["offset"].(float64)) != 1<<20 {
		t.Fatalf("a repeated chunk must be 409 with the server's offset: %d %v", c, o)
	}
	// a gap is refused too
	if c, _ := h.chunk(&dina, id, 5<<20, []byte("x")); c != 409 {
		t.Fatalf("a chunk beyond the received offset must be 409: %d", c)
	}
	// "server restart": the in-memory running hashes are gone; the file must still hash correctly
	h.srv.arch.mu.Lock()
	h.srv.arch.uploads = nil
	h.srv.arch.mu.Unlock()
	c, st := h.json(&dina, "GET", "/archive/uploads/"+id, nil)
	if c != 200 || int(st["offset"].(float64)) != 1<<20 {
		t.Fatalf("status must tell the client where to resume: %d %v", c, st)
	}
	if c, o := h.chunk(&dina, id, 1<<20, data[1<<20:]); c != 200 {
		t.Fatalf("resume: %d %v", c, o)
	}
	c, rc := h.json(&dina, "POST", "/archive/uploads/"+id+"/complete", map[string]string{"client_sha256": sum256(data)})
	if c != 201 {
		t.Fatalf("complete after resume: %d %v", c, rc)
	}
	if m := rc["receipt"].(map[string]interface{})["body"].(map[string]interface{})["manifest"].(map[string]interface{}); m["sha256"] != sum256(data) {
		t.Fatal("the recorded hash must be of the whole file")
	}
	// other people's uploads are invisible
	if c, _ := h.json(&eko, "GET", "/archive/uploads/"+id, nil); c != 404 {
		t.Errorf("an upload session belongs to its sender: %d", c)
	}
}

func TestArchiveRejectsACorruptTransferAndRecordsNothing(t *testing.T) {
	h := newHarness(t)
	h.assign(dina, h.office("Kantor A"))
	data := randomBytes(300000)
	id := h.startUpload(&dina, "x.bin", len(data))
	if c, o := h.chunk(&dina, id, 0, data); c != 200 {
		t.Fatalf("chunk: %d %v", c, o)
	}
	wrong := sum256([]byte("something else"))
	c, out := h.json(&dina, "POST", "/archive/uploads/"+id+"/complete", map[string]string{"client_sha256": wrong})
	if c != 422 || out["server_sha256"] != sum256(data) {
		t.Fatalf("a hash the browser computed differently must be refused: %d %v", c, out)
	}
	if c, _ := h.json(&dina, "POST", "/archive/uploads/"+id+"/complete", map[string]string{}); c != 400 {
		t.Fatalf("client_sha256 is mandatory: %d", c)
	}
	var n int
	_ = h.db.QueryRow(context.Background(), `SELECT (SELECT count(*) FROM archive_item)+(SELECT count(*) FROM transaction WHERE workflow_type='arsip-kiriman')+(SELECT count(*) FROM outbox_event)`).Scan(&n)
	if n != 0 || len(h.obj.m) != 0 {
		t.Fatalf("a refused upload must leave no record and no stored object (db rows=%d objects=%d)", n, len(h.obj.m))
	}
	// the session is still open: the right hash completes it
	if c, o := h.json(&dina, "POST", "/archive/uploads/"+id+"/complete", map[string]string{"client_sha256": sum256(data)}); c != 201 {
		t.Fatalf("retry with the right hash: %d %v", c, o)
	}
}

func TestArchiveLimitsAndPreconditions(t *testing.T) {
	h := newHarness(t)
	h.assign(dina, h.office("Kantor A"))

	// no office yet
	if c, o := h.json(&fajar, "POST", "/archive/uploads", map[string]interface{}{"file_name": "a", "size": 1}); c != 403 || !strings.Contains(fmt.Sprint(o["error"]), "kantor") {
		t.Errorf("an account without an office must be told so: %d %v", c, o)
	}
	// over the ceiling (harness limit is 8 MiB)
	if c, _ := h.json(&dina, "POST", "/archive/uploads", map[string]interface{}{"file_name": "a", "size": 9 << 20}); c != 413 {
		t.Errorf("a file above the limit must be 413: %d", c)
	}
	if c, _ := h.json(&dina, "POST", "/archive/uploads", map[string]interface{}{"file_name": "a", "size": -1}); c != 400 {
		t.Errorf("negative size: %d", c)
	}
	// more bytes than declared are refused and rolled back
	id := h.startUpload(&dina, "kecil.bin", 100)
	if c, _ := h.chunk(&dina, id, 0, randomBytes(150)); c != 400 {
		t.Errorf("overshooting the declared size must be 400: %d", c)
	}
	if c, st := h.json(&dina, "GET", "/archive/uploads/"+id, nil); c != 200 || st["offset"].(float64) != 0 {
		t.Errorf("a refused chunk must not advance the offset: %v", st)
	}
	// completing early
	if c, _ := h.json(&dina, "POST", "/archive/uploads/"+id+"/complete", map[string]string{"client_sha256": sum256(nil)}); c != 409 {
		t.Errorf("completing an incomplete upload must be 409: %d", c)
	}
	// zero-byte files are legitimate
	if c, o := h.upload(&dina, "kosong.txt", nil, 1); c != 201 {
		t.Errorf("an empty file must be archivable: %d %v", c, o)
	}
	// too many unfinished uploads
	for i := 0; i < 5; i++ {
		if c, _ := h.json(&dina, "POST", "/archive/uploads", map[string]interface{}{"file_name": "p", "size": 10}); c != 201 && c != 429 {
			t.Fatalf("open upload %d: %d", i, c)
		}
	}
	if c, _ := h.json(&dina, "POST", "/archive/uploads", map[string]interface{}{"file_name": "p", "size": 10}); c != 429 {
		t.Errorf("too many open uploads must be 429: %d", c)
	}
	// abort frees the slot and removes the scratch file
	if c, _ := h.json(&dina, "DELETE", "/archive/uploads/"+id, nil); c != 200 {
		t.Errorf("abort: %d", c)
	}
	if c, _ := h.json(&dina, "POST", "/archive/uploads", map[string]interface{}{"file_name": "p", "size": 10}); c != 201 {
		t.Errorf("after an abort a new upload must be possible: %d", c)
	}
}

func TestArchiveVerificationCatchesTampering(t *testing.T) {
	h := newHarness(t)
	h.assign(dina, h.office("Kantor A"))
	data := randomBytes(50000)
	if c, o := h.upload(&dina, "a.bin", data, 20000); c != 201 {
		t.Fatalf("upload: %d %v", c, o)
	}
	ctx := context.Background()
	var itemID, key, txnID string
	_ = h.db.QueryRow(ctx, `SELECT id, storage_key, transaction_id FROM archive_item`).Scan(&itemID, &key, &txnID)

	verify := func() map[string]bool {
		_, ver := h.json(&root, "POST", "/archive/items/"+itemID+"/verify?deep=1", nil)
		m := map[string]bool{}
		for _, c := range ver["checks"].([]interface{}) {
			cm := c.(map[string]interface{})
			m[cm["name"].(string)] = cm["ok"].(bool)
		}
		return m
	}
	if m := verify(); !m["stored_file"] || !m["manifest_hash"] {
		t.Fatalf("baseline must verify: %v", m)
	}

	// 1. the stored file is altered
	orig := append([]byte(nil), h.obj.m[key]...)
	h.obj.m[key][10] ^= 0xff
	if m := verify(); m["stored_file"] {
		t.Error("an altered stored file must fail the deep check")
	}
	h.obj.m[key] = orig

	// 2. the archived manifest is edited (e.g. the sender's name)
	if _, err := h.db.Exec(ctx, `UPDATE archive_item SET manifest = jsonb_set(manifest, '{sender_name}', '"orang lain"')`); err != nil {
		t.Fatal(err)
	}
	if m := verify(); m["manifest_hash"] {
		t.Error("an edited manifest must fail")
	}
	if _, err := h.db.Exec(ctx, `UPDATE archive_item SET manifest = jsonb_set(manifest, '{sender_name}', '"dina"')`); err != nil {
		t.Fatal(err)
	}
	if m := verify(); !m["manifest_hash"] {
		t.Fatalf("restoring the manifest must verify again: %v", m)
	}

	// 3. an event's signature is replaced / the chain link is cut
	if _, err := h.db.Exec(ctx, `UPDATE transaction_event SET pqc_signature = pqc_signature || '\x00'::bytea WHERE transaction_id=$1 AND event_sequence=2`, txnID); err != nil {
		t.Fatal(err)
	}
	if m := verify(); m["event_signatures"] {
		t.Error("a damaged event signature must fail")
	}
}

func TestArchivePublicReceiptShowsOnlyWhatTheReceiptSays(t *testing.T) {
	h := newHarness(t)
	h.assign(dina, h.office("Kantor A"))
	data := randomBytes(1000)
	_, rc := h.upload(&dina, "surat.pdf", data, 1000)
	rid := rc["receipt_id"].(string)

	get := func(secret string, path string) (int, []byte) {
		req := httptest.NewRequest("GET", path, nil)
		if secret != "" {
			req.Header.Set("X-Office-Secret", secret)
		}
		w := httptest.NewRecorder()
		h.h.ServeHTTP(w, req)
		b, _ := io.ReadAll(w.Body)
		return w.Code, b
	}
	if c, _ := get("", "/public/receipts/"+rid); c != 401 {
		t.Errorf("only the TTD proxy may reach the public receipt route: %d", c)
	}
	c, b := get(testSecret, "/public/receipts/"+rid)
	if c != 200 {
		t.Fatalf("public receipt: %d %s", c, b)
	}
	pub := asMap(b)
	if pub["sha256"] != sum256(data) || pub["sender_name"] != "dina" || pub["organization_name"] != "Kantor A" {
		t.Fatalf("public receipt content: %v", pub)
	}
	if pub["verification"].(map[string]interface{})["ok"] != true {
		t.Fatalf("the public receipt must carry a passing live verification: %v", pub["verification"])
	}
	for _, leak := range []string{"@test", "203.0.113.7", "uji", "client_ip", "user_agent", "sender_email"} {
		if strings.Contains(string(b), leak) {
			t.Errorf("the public receipt must not expose %q", leak)
		}
	}
	if c, _ := get(testSecret, "/public/receipts/rcp_doesnotexist"); c != 404 {
		t.Errorf("unknown receipt: %d", c)
	}
}

func TestArchiveOfficesAndMembersAreAdminOnly(t *testing.T) {
	h := newHarness(t)
	if c, _ := h.json(&dina, "POST", "/archive/offices", map[string]string{"name": "Kantor X"}); c != 403 {
		t.Errorf("a sender must not create offices: %d", c)
	}
	id := h.office("Kantor Utama")
	if c, _ := h.json(&root, "POST", "/archive/offices", map[string]string{"name": "Kantor Utama"}); c != 409 {
		t.Errorf("a duplicate office must be 409: %d", c)
	}
	if c, _ := h.json(&root, "POST", "/archive/offices", map[string]string{"name": "x"}); c != 400 {
		t.Errorf("a too-short name must be 400: %d", c)
	}
	if c, _ := h.json(&root, "PUT", "/archive/members/"+dina.id, map[string]string{"organization_id": "tidak-ada"}); c != 400 {
		t.Errorf("assigning to an unknown office must be 400: %d", c)
	}
	h.assign(dina, id)
	_, ms := h.json(&root, "GET", "/archive/members", nil)
	found := false
	for _, m := range ms["members"].([]interface{}) {
		mm := m.(map[string]interface{})
		if mm["account_id"] == dina.id && mm["organization_id"] == id {
			found = true
		}
		if mm["account_id"] == systemArchiveID {
			t.Error("the system identity must not be listed as a member")
		}
	}
	if !found {
		t.Errorf("member not listed: %v", ms)
	}
	// removing the assignment stops uploads again
	if c, _ := h.json(&root, "PUT", "/archive/members/"+dina.id, map[string]string{"organization_id": ""}); c != 200 {
		t.Fatal("unassign")
	}
	if c, _ := h.json(&dina, "POST", "/archive/uploads", map[string]interface{}{"file_name": "a", "size": 1}); c != 403 {
		t.Errorf("after unassigning, uploads must be refused: %d", c)
	}
	_, offs := h.json(&root, "GET", "/archive/offices", nil)
	for _, o := range offs["offices"].([]interface{}) {
		if id := o.(map[string]interface{})["id"]; id == systemOrgID || id == "org-a" {
			t.Errorf("system offices must not be listed: %v", id)
		}
	}
}

func TestArchiveListFiltersAndSearch(t *testing.T) {
	h := newHarness(t)
	a, b := h.office("Kantor A"), h.office("Kantor B")
	h.assign(dina, a)
	h.assign(eko, b)
	h.upload(&dina, "anggaran-2026.xlsx", randomBytes(500), 500)
	h.upload(&eko, "kontrak.pdf", randomBytes(600), 600)
	h.upload(&eko, "foto_100%.jpg", randomBytes(700), 700)

	count := func(q string) int {
		_, o := h.json(&root, "GET", "/archive/items"+q, nil)
		return len(o["items"].([]interface{}))
	}
	if n := count(""); n != 3 {
		t.Fatalf("all = %d", n)
	}
	if n := count("?org=" + b); n != 2 {
		t.Errorf("by office = %d", n)
	}
	if n := count("?sender=" + dina.id); n != 1 {
		t.Errorf("by sender = %d", n)
	}
	if n := count("?q=kontrak"); n != 1 {
		t.Errorf("by name = %d", n)
	}
	if n := count("?q=%25"); n != 1 { // a literal % must not act as a wildcard
		t.Errorf("a literal percent sign matched %d items", n)
	}
	if n := count("?q=eko"); n != 2 {
		t.Errorf("by sender name = %d", n)
	}
	if n := count("?from=2999-01-01"); n != 0 {
		t.Errorf("future date = %d", n)
	}
	if n := count("?limit=2"); n != 2 {
		t.Errorf("limit = %d", n)
	}
	_, st := h.json(&root, "GET", "/archive/stats", nil)
	if int(st["items"].(float64)) != 3 || int(st["bytes"].(float64)) != 1800 {
		t.Errorf("stats: %v", st)
	}
}
