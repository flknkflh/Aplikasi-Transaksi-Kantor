package crypto

import "testing"

func TestCanonicalizeSortsKeysDeterministically(t *testing.T) {
	a := map[string]interface{}{"b": 1, "a": 2, "c": map[string]interface{}{"z": 1, "y": 2}}
	b := map[string]interface{}{"c": map[string]interface{}{"y": 2, "z": 1}, "a": 2, "b": 1}

	ca, err := Canonicalize(a)
	if err != nil {
		t.Fatalf("canonicalize a: %v", err)
	}
	cb, err := Canonicalize(b)
	if err != nil {
		t.Fatalf("canonicalize b: %v", err)
	}
	if string(ca) != string(cb) {
		t.Fatalf("expected identical canonical bytes regardless of key order, got %q vs %q", ca, cb)
	}

	want := `{"a":2,"b":1,"c":{"y":2,"z":1}}`
	if string(ca) != want {
		t.Fatalf("canonical bytes = %q, want %q", ca, want)
	}
}

func TestCanonicalizePreservesArrayOrder(t *testing.T) {
	v := map[string]interface{}{"items": []interface{}{3, 1, 2}}
	got, err := Canonicalize(v)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	want := `{"items":[3,1,2]}`
	if string(got) != want {
		t.Fatalf("canonical bytes = %q, want %q", got, want)
	}
}

func TestPayloadHashChangesWithPayload(t *testing.T) {
	h1, err := PayloadHash(map[string]interface{}{"amount": 100})
	if err != nil {
		t.Fatalf("hash 1: %v", err)
	}
	h2, err := PayloadHash(map[string]interface{}{"amount": 101})
	if err != nil {
		t.Fatalf("hash 2: %v", err)
	}
	if h1 == h2 {
		t.Fatalf("expected different hashes for different payloads, got %q for both", h1)
	}

	h1Again, err := PayloadHash(map[string]interface{}{"amount": 100})
	if err != nil {
		t.Fatalf("hash 1 again: %v", err)
	}
	if h1 != h1Again {
		t.Fatalf("expected stable hash for identical payload, got %q then %q", h1, h1Again)
	}
}
