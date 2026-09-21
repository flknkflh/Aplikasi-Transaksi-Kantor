// Package crypto implements the hybrid classical+PQC signing and key
// exchange primitives described in docs/Hybrid_PQC_Permissioned_Blockchain_PRD.md
// §7 and §10: crypto-agile algorithm_suite envelopes, domain-separated
// signing contexts, and fail-closed verification. See docs/adr/0001 for the
// Fase 1 spike's scope decisions (Ed25519 classical half, ML-DSA-65 via
// liboqs, ML-KEM-768 via the Go standard library).
package crypto

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

// Canonicalize produces a deterministic JSON encoding of v: object keys
// sorted recursively, no insignificant whitespace, UTF-8. It is a pragmatic
// subset of RFC 8785 (JCS) sufficient for this project's envelope payloads
// (strings, integers, booleans, nulls, arrays, nested objects). It does not
// attempt JCS's exact floating-point (ECMA-262 ToString) number formatting —
// ledger payloads must not carry floats; use integer minor units or strings
// for amounts instead.
func Canonicalize(v interface{}) ([]byte, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("crypto: marshal for canonicalization: %w", err)
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	var generic interface{}
	if err := dec.Decode(&generic); err != nil {
		return nil, fmt.Errorf("crypto: decode for canonicalization: %w", err)
	}

	var buf bytes.Buffer
	if err := writeCanonical(&buf, generic); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func writeCanonical(buf *bytes.Buffer, v interface{}) error {
	switch val := v.(type) {
	case nil:
		buf.WriteString("null")
	case bool:
		if val {
			buf.WriteString("true")
		} else {
			buf.WriteString("false")
		}
	case json.Number:
		buf.WriteString(val.String())
	case string:
		b, err := json.Marshal(val)
		if err != nil {
			return fmt.Errorf("crypto: encode canonical string: %w", err)
		}
		buf.Write(b)
	case []interface{}:
		buf.WriteByte('[')
		for i, item := range val {
			if i > 0 {
				buf.WriteByte(',')
			}
			if err := writeCanonical(buf, item); err != nil {
				return err
			}
		}
		buf.WriteByte(']')
	case map[string]interface{}:
		keys := make([]string, 0, len(val))
		for k := range val {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		buf.WriteByte('{')
		for i, k := range keys {
			if i > 0 {
				buf.WriteByte(',')
			}
			kb, err := json.Marshal(k)
			if err != nil {
				return fmt.Errorf("crypto: encode canonical key: %w", err)
			}
			buf.Write(kb)
			buf.WriteByte(':')
			if err := writeCanonical(buf, val[k]); err != nil {
				return err
			}
		}
		buf.WriteByte('}')
	default:
		return fmt.Errorf("crypto: unsupported type %T in canonical payload", v)
	}
	return nil
}

// PayloadHash returns sha256(Canonicalize(v)) formatted as "sha256:<hex>",
// matching the `payload_hash` field format used throughout the PRD's ledger
// envelope (§7).
func PayloadHash(v interface{}) (string, error) {
	canon, err := Canonicalize(v)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(canon)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}
