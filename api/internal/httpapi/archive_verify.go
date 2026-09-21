package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/jackc/pgx/v5"

	"ledger/crypto"
)

type verifyCheck struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail,omitempty"`
}

type archiveVerification struct {
	OK     bool          `json:"ok"`
	Checks []verifyCheck `json:"checks"`
}

func (v *archiveVerification) add(name string, ok bool, detail string) {
	v.Checks = append(v.Checks, verifyCheck{Name: name, OK: ok, Detail: detail})
}

// lookupKeys loads the public halves of a hybrid identity from key_reference
// (never from the private keystore) and reports whether either was revoked.
func (s *Server) lookupKeys(ctx context.Context, classicalID, pqcID string) (crypto.VerificationKeys, bool, error) {
	var keys crypto.VerificationKeys
	revoked := false
	for _, k := range []struct {
		id  string
		dst *[]byte
	}{{classicalID, new([]byte)}, {pqcID, new([]byte)}} {
		var pub []byte
		var status string
		if err := s.DB.QueryRow(ctx, `SELECT public_key, status FROM key_reference WHERE id = $1`, k.id).Scan(&pub, &status); err != nil {
			return keys, false, fmt.Errorf("kunci %s tidak ditemukan", k.id)
		}
		revoked = revoked || status == "revoked"
		if k.id == classicalID {
			keys.ClassicalPublic = ed25519.PublicKey(pub)
		} else {
			keys.PQCPublic = pub
		}
	}
	return keys, revoked, nil
}

func decodeSig(j sigJSON) (*crypto.HybridSignature, error) {
	cs, err := base64.StdEncoding.DecodeString(j.ClassicalSignature)
	if err != nil {
		return nil, err
	}
	ps, err := base64.StdEncoding.DecodeString(j.PQCSignature)
	if err != nil {
		return nil, err
	}
	return &crypto.HybridSignature{AlgorithmSuite: crypto.AlgorithmSuite(j.Suite), ClassicalKeyID: j.ClassicalKeyID,
		PQCKeyID: j.PQCKeyID, ClassicalSignature: cs, PQCSignature: ps}, nil
}

func decodeUseNumber(raw []byte, v interface{}) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	return d.Decode(v)
}

// verifyItem independently re-checks everything the archive claims about one
// item, from the stored records and the public keys only:
//
//   - the manifest hashes to the value the sender's signature covered;
//   - the sender's hybrid signature (Ed25519 AND ML-DSA-65) verifies, key not revoked;
//   - the event chain is contiguous (each event names the previous event's hash)
//     and every event's signature verifies;
//   - the receipt's server signature verifies and matches the manifest;
//   - with deep=true, the stored file still hashes to the manifest's SHA-256/512.
func (s *Server) verifyItem(ctx context.Context, itemID string, deep bool) (*archiveVerification, error) {
	var txnID, manifestHash, storageKey string
	var manifestRaw, receiptRaw []byte
	var size int64
	err := s.DB.QueryRow(ctx, `SELECT transaction_id, manifest, manifest_hash, receipt, storage_key, size_bytes FROM archive_item WHERE id = $1`, itemID).
		Scan(&txnID, &manifestRaw, &manifestHash, &receiptRaw, &storageKey, &size)
	if err != nil {
		return nil, err
	}
	v := &archiveVerification{}

	var manifest map[string]interface{}
	if err := decodeUseNumber(manifestRaw, &manifest); err != nil {
		return nil, err
	}
	got, err := crypto.PayloadHash(manifest)
	v.add("manifest_hash", err == nil && got == manifestHash, "manifest yang tersimpan menghasilkan hash yang ditandatangani pengirim")

	// events
	rows, err := s.DB.Query(ctx, `
		SELECT event_sequence, event_type, payload_hash, COALESCE(previous_event_hash,''), algorithm_suite,
		       classical_key_id, pqc_key_id, classical_signature, pqc_signature
		FROM transaction_event WHERE transaction_id = $1 ORDER BY event_sequence`, txnID)
	if err != nil {
		return nil, err
	}
	type ev struct {
		seq                            int
		typ, hash, prev, suite, ck, pk string
		cs, ps                         []byte
	}
	var evs []ev
	for rows.Next() {
		var e ev
		if err := rows.Scan(&e.seq, &e.typ, &e.hash, &e.prev, &e.suite, &e.ck, &e.pk, &e.cs, &e.ps); err != nil {
			rows.Close()
			return nil, err
		}
		evs = append(evs, e)
	}
	rows.Close()
	if len(evs) == 0 {
		return nil, errors.New("no events")
	}

	chainOK, chainDetail := true, "peristiwa berurutan dan saling menunjuk hash sebelumnya"
	for i, e := range evs {
		if e.seq != i+1 || (i == 0 && e.prev != "") || (i > 0 && e.prev != evs[i-1].hash) {
			chainOK, chainDetail = false, fmt.Sprintf("rantai putus pada peristiwa #%d (%s)", e.seq, e.typ)
			break
		}
	}
	v.add("event_chain", chainOK, chainDetail)

	verifyEvent := func(e ev) (bool, string) {
		keys, revoked, err := s.lookupKeys(ctx, e.ck, e.pk)
		if err != nil {
			return false, err.Error()
		}
		res, err := crypto.VerifyHybridWithHash(keys, &crypto.HybridSignature{AlgorithmSuite: crypto.AlgorithmSuite(e.suite),
			ClassicalKeyID: e.ck, PQCKeyID: e.pk, ClassicalSignature: e.cs, PQCSignature: e.ps}, s.sigContext(e.typ, txnID), e.hash)
		switch {
		case err != nil:
			return false, err.Error()
		case !res.OK():
			return false, fmt.Sprintf("Ed25519=%v ML-DSA-65=%v", res.ClassicalValid, res.PQCValid)
		case revoked:
			return false, "kunci sudah dicabut"
		}
		return true, "Ed25519 dan ML-DSA-65 sah"
	}
	first := evs[0]
	ok, detail := verifyEvent(first)
	v.add("sender_signature", ok && first.typ == "UPLOAD_RECEIVED" && first.hash == manifestHash, "tanda tangan hybrid pengirim atas manifest: "+detail)
	allOK, allDetail := true, "semua peristiwa bertanda tangan sah"
	for _, e := range evs[1:] {
		if ok, d := verifyEvent(e); !ok {
			allOK, allDetail = false, fmt.Sprintf("peristiwa #%d %s: %s", e.seq, e.typ, d)
			break
		}
	}
	v.add("event_signatures", allOK, allDetail)

	// receipt
	var receipt struct {
		Body   map[string]interface{} `json:"body"`
		Server sigJSON                `json:"server_signature"`
	}
	rok, rdetail := false, "bukti tidak dapat dibaca"
	if err := decodeUseNumber(receiptRaw, &receipt); err == nil && receipt.Body != nil {
		sig, derr := decodeSig(receipt.Server)
		keys, revoked, kerr := s.lookupKeys(ctx, receipt.Server.ClassicalKeyID, receipt.Server.PQCKeyID)
		if derr == nil && kerr == nil {
			bodyHash, herr := crypto.PayloadHash(receipt.Body)
			if herr == nil {
				res, verr := crypto.VerifyHybridWithHash(keys, sig, s.sigContext("ARCHIVE_RECEIPT", txnID), bodyHash)
				rok = verr == nil && res.OK() && !revoked && receipt.Body["manifest_hash"] == manifestHash
				rdetail = "tanda tangan server pada bukti sah dan cocok dengan manifest"
				if !rok {
					rdetail = "tanda tangan server pada bukti tidak sah atau tidak cocok"
				}
			}
		}
	}
	v.add("receipt_signature", rok, rdetail)

	if deep {
		fok, fdetail := false, "berkas tersimpan tidak dapat dibaca"
		if rc, err := s.Objects.GetStream(ctx, storageKey); err == nil {
			h256, h512 := sha256.New(), sha512.New()
			n, cerr := io.Copy(io.MultiWriter(h256, h512), rc)
			rc.Close()
			fok = cerr == nil && n == size && hexSum(h256) == manifest["sha256"] && hexSum(h512) == manifest["sha512"]
			fdetail = "berkas di penyimpanan cocok dengan SHA-256/SHA-512 pada manifest"
			if !fok {
				fdetail = "berkas di penyimpanan BERBEDA dari yang tercatat"
			}
		}
		v.add("stored_file", fok, fdetail)
	}

	v.OK = true
	for _, c := range v.Checks {
		v.OK = v.OK && c.OK
	}
	return v, nil
}

var errNoItem = pgx.ErrNoRows
