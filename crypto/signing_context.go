package crypto

import "fmt"

// SigningContext carries the domain-separation fields the PRD requires be
// bound into every signature (§7: "Signature context harus mencakup domain
// aplikasi, environment, transaction type, schema version, dan transaction
// ID untuk mencegah cross-protocol signing"). It is prepended to the payload
// hash before signing, so a signature produced for one
// app/environment/transaction-type/schema/transaction-id can never be
// replayed as a valid signature for another.
type SigningContext struct {
	Application     string // e.g. "pqc-ledger"
	Environment     string // e.g. "dev", "staging", "production"
	TransactionType string // e.g. "ASSET_HANDOVER_CONFIRMED"
	SchemaVersion   string // e.g. "transaction.v1"
	TransactionID   string
}

// bind produces the exact byte string that gets signed: the payload hash is
// never signed on its own, always together with the context that scopes it.
func (c SigningContext) bind(payloadHash string) []byte {
	return []byte(fmt.Sprintf(
		"pqc-ledger-sig-ctx/v1\napplication=%s\nenvironment=%s\ntransaction_type=%s\nschema_version=%s\ntransaction_id=%s\npayload_hash=%s",
		c.Application, c.Environment, c.TransactionType, c.SchemaVersion, c.TransactionID, payloadHash,
	))
}
