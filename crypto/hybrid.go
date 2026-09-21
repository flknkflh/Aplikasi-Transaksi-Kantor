package crypto

import (
	"crypto/ed25519"
	"fmt"
)

// HybridSignature is the pair of independent signatures that make up a
// hybrid envelope, matching the PRD §7 event fields
// (classical_signature/pqc_signature/algorithm_suite/*_key_id).
type HybridSignature struct {
	AlgorithmSuite     AlgorithmSuite
	ClassicalKeyID     string
	PQCKeyID           string
	ClassicalSignature []byte
	PQCSignature       []byte
}

// SigningIdentity bundles the private key material needed to produce a
// hybrid signature. Real deployments source this from a KMS/HSM (PRD §7);
// in this spike, only the dev keystore (api/internal/keystore) constructs one,
// and never logs or serializes it.
type SigningIdentity struct {
	ClassicalKeyID   string
	ClassicalPrivate ed25519.PrivateKey
	PQCKeyID         string
	PQCPrivate       []byte
}

// SignHybrid computes payload_hash, binds it to the signing context, and
// signs that bound value with both algorithms — never the raw payload alone —
// per PRD §7's cross-protocol-signing requirement. It returns the resulting
// signature envelope plus the payload_hash to store alongside it.
func SignHybrid(identity SigningIdentity, ctx SigningContext, payload interface{}) (*HybridSignature, string, error) {
	payloadHash, err := PayloadHash(payload)
	if err != nil {
		return nil, "", err
	}
	bound := ctx.bind(payloadHash)

	classicalSig := SignClassical(identity.ClassicalPrivate, bound)

	pqcSig, err := SignMLDSA(identity.PQCPrivate, bound)
	if err != nil {
		return nil, "", fmt.Errorf("crypto: hybrid sign: %w", err)
	}

	return &HybridSignature{
		AlgorithmSuite:     SuiteHybridEd25519MLDSA65V1,
		ClassicalKeyID:     identity.ClassicalKeyID,
		PQCKeyID:           identity.PQCKeyID,
		ClassicalSignature: classicalSig,
		PQCSignature:       pqcSig,
	}, payloadHash, nil
}

// VerificationKeys carries the public keys needed to verify a HybridSignature.
type VerificationKeys struct {
	ClassicalPublic ed25519.PublicKey
	PQCPublic       []byte
}

// VerifyHybridResult reports each half's outcome independently so callers
// (notably the audit-service) can produce a detailed verification receipt
// (PRD FR-014) instead of a single opaque pass/fail.
type VerifyHybridResult struct {
	SuiteAllowed   bool
	ClassicalValid bool
	PQCValid       bool
}

// OK reports whether every check passed. Fail-closed (PRD §3): a signature
// is only good if the suite is allow-listed AND both halves verify — a valid
// classical signature with a missing/invalid PQC half is not accepted, and
// vice versa.
func (r VerifyHybridResult) OK() bool {
	return r.SuiteAllowed && r.ClassicalValid && r.PQCValid
}

func VerifyHybrid(keys VerificationKeys, sig *HybridSignature, ctx SigningContext, payload interface{}) (VerifyHybridResult, error) {
	payloadHash, err := PayloadHash(payload)
	if err != nil {
		return VerifyHybridResult{}, err
	}
	return VerifyHybridWithHash(keys, sig, ctx, payloadHash)
}

// VerifyHybridWithHash is VerifyHybrid for callers that only have the
// payload_hash, not the original payload — which is exactly the
// audit-service's situation: the ledger stores payload_hash, never the raw
// business payload (PRD §6's on-chain/off-chain split), and the signing
// context binds the hash rather than the payload itself (see
// SigningContext.bind), so re-verification only ever needs the hash.
func VerifyHybridWithHash(keys VerificationKeys, sig *HybridSignature, ctx SigningContext, payloadHash string) (VerifyHybridResult, error) {
	var result VerifyHybridResult

	if err := ValidateSuite(sig.AlgorithmSuite); err != nil {
		return result, err
	}
	result.SuiteAllowed = true

	bound := ctx.bind(payloadHash)

	result.ClassicalValid = VerifyClassical(keys.ClassicalPublic, bound, sig.ClassicalSignature)

	pqcValid, err := VerifyMLDSA(keys.PQCPublic, bound, sig.PQCSignature)
	if err != nil {
		return result, fmt.Errorf("crypto: hybrid verify: %w", err)
	}
	result.PQCValid = pqcValid

	return result, nil
}
