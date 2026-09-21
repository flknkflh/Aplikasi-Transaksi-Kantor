package crypto

import (
	"fmt"

	"github.com/open-quantum-safe/liboqs-go/oqs"
)

// MLDSAAlgorithm is the liboqs algorithm identifier for ML-DSA-65 (FIPS 204),
// the post-quantum half of SuiteHybridEd25519MLDSA65V1. Go's standard library
// does not implement ML-DSA as of Go 1.27 (only ML-KEM, used in kem.go), so
// this is the one place in the module that needs liboqs/cgo — see
// infra/Dockerfile.godev.
const MLDSAAlgorithm = "ML-DSA-65"

// GenerateMLDSAKeyPair generates a fresh ML-DSA-65 keypair. The private key
// must only ever be handed to a keystore for local persistence — per PRD §7
// it must never be logged or embedded in a ledger payload, only referenced
// by key_id.
//
// liboqs-go's Signature.Clean() zeroes its internal secretKey buffer in
// place, and ExportSecretKey returns that same backing array rather than a
// copy — so the exported key must be copied out before Clean() runs, or the
// deferred Clean() below would zero out the key this function is about to
// return.
func GenerateMLDSAKeyPair() (public []byte, private []byte, err error) {
	signer := oqs.Signature{}
	defer signer.Clean()

	if err := signer.Init(MLDSAAlgorithm, nil); err != nil {
		return nil, nil, fmt.Errorf("crypto: init ML-DSA-65: %w", err)
	}
	public, err = signer.GenerateKeyPair()
	if err != nil {
		return nil, nil, fmt.Errorf("crypto: generate ML-DSA-65 keypair: %w", err)
	}
	exported := signer.ExportSecretKey()
	private = make([]byte, len(exported))
	copy(private, exported)
	return public, private, nil
}

// SignMLDSA copies the caller's private key before handing it to liboqs-go:
// Init stores the exact slice it's given as its internal secretKey, and the
// deferred Clean() zeroes that slice in place — without the copy, signing
// would destroy the caller's key after a single use.
func SignMLDSA(private []byte, message []byte) ([]byte, error) {
	signer := oqs.Signature{}
	defer signer.Clean()

	privateCopy := make([]byte, len(private))
	copy(privateCopy, private)

	if err := signer.Init(MLDSAAlgorithm, privateCopy); err != nil {
		return nil, fmt.Errorf("crypto: init ML-DSA-65 signer: %w", err)
	}
	sig, err := signer.Sign(message)
	if err != nil {
		return nil, fmt.Errorf("crypto: ML-DSA-65 sign: %w", err)
	}
	return sig, nil
}

func VerifyMLDSA(public []byte, message, sig []byte) (bool, error) {
	verifier := oqs.Signature{}
	defer verifier.Clean()

	if err := verifier.Init(MLDSAAlgorithm, nil); err != nil {
		return false, fmt.Errorf("crypto: init ML-DSA-65 verifier: %w", err)
	}
	ok, err := verifier.Verify(message, sig, public)
	if err != nil {
		return false, fmt.Errorf("crypto: ML-DSA-65 verify: %w", err)
	}
	return ok, nil
}
