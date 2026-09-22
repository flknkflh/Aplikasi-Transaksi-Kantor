package api_test

import (
	"net/http"
	"testing"

	"example.internal/pqc-pdf-sign/server/internal/store"
)

// Output validation (docs/adr/0010): a signature's owner-facing responses must
// be an explicit allowlist, not the raw store.Signature — in particular never
// StorageObjectKey, an internal object-storage reference with no legitimate
// client use.

func TestSignatureResponsesNeverLeakStorageObjectKeyOrAccountID(t *testing.T) {
	e := newEnv(t)
	user := e.account("owner@test", store.RoleUser)
	admin := e.adminTok()
	d := e.enrolledDevice(user, admin, "laptop")
	pid := e.reserve(user, d.id)
	mustCode(t, e.do("PUT", "/api/v1/signatures/"+pid+"/document", user, signWith(t, d, pid)), http.StatusOK)

	assertClean := func(t *testing.T, m map[string]any) {
		t.Helper()
		for _, forbidden := range []string{"StorageObjectKey", "storage_object_key", "AccountID", "account_id"} {
			if _, ok := m[forbidden]; ok {
				t.Fatalf("response leaks %q: %v", forbidden, m)
			}
		}
		for _, want := range []string{"public_id", "verification_status", "cert_serial", "signed_sha512"} {
			if _, ok := m[want]; !ok {
				t.Fatalf("response missing expected field %q: %v", want, m)
			}
		}
	}

	// GET /api/v1/signatures/{public_id}
	w := e.do("GET", "/api/v1/signatures/"+pid, user, nil)
	mustCode(t, w, http.StatusOK)
	assertClean(t, jbody(t, w))

	// GET /api/v1/me/signatures
	w = e.do("GET", "/api/v1/me/signatures", user, nil)
	mustCode(t, w, http.StatusOK)
	list, ok := jbody(t, w)["signatures"].([]any)
	if !ok || len(list) != 1 {
		t.Fatalf("expected exactly 1 signature in the list: %v", jbody(t, w))
	}
	assertClean(t, list[0].(map[string]any))
}
