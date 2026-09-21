package crypto

import "fmt"

// AlgorithmSuite identifies a hybrid classical+PQC combination, matching the
// PRD's `algorithm_suite` envelope field (§7). Crypto-agility (PRD §3): every
// signature and key envelope carries this so verifiers know exactly which
// algorithms and parameters produced it, and so migrating to a new suite
// later never requires a big-bang rewrite of historical events.
type AlgorithmSuite string

// SuiteHybridEd25519MLDSA65V1 is the only suite this Fase 1 spike issues:
// classical Ed25519 + post-quantum ML-DSA-65 (FIPS 204), version 1. See
// docs/adr/0001-fase1-spike-scope.md decision #2 for why Ed25519 over ECDSA.
const SuiteHybridEd25519MLDSA65V1 AlgorithmSuite = "HYBRID_ED25519_MLDSA65_V1"

type suiteInfo struct {
	ClassicalAlgorithm string
	PQCAlgorithm       string
}

// suiteRegistry lists every suite this deployment is willing to accept.
// Fail-closed (PRD §3, §10 "Downgrade dari hybrid ke klasik"): anything not
// explicitly listed here — including a classical-only signature with no PQC
// component — is rejected outright rather than silently accepted.
var suiteRegistry = map[AlgorithmSuite]suiteInfo{
	SuiteHybridEd25519MLDSA65V1: {ClassicalAlgorithm: "Ed25519", PQCAlgorithm: MLDSAAlgorithm},
}

// ValidateSuite rejects any algorithm_suite value that isn't explicitly
// allow-listed. This is the fail-closed check that stops a downgrade attempt
// (PRD §10 threat model) from being silently accepted.
func ValidateSuite(s AlgorithmSuite) error {
	if _, ok := suiteRegistry[s]; !ok {
		return fmt.Errorf("crypto: algorithm_suite %q is not an allowed suite (possible downgrade attempt)", s)
	}
	return nil
}
