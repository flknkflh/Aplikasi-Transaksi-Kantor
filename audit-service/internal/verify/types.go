package verify

// These mirror the chaincode's on-ledger JSON shapes exactly (see
// chaincode/transaction/chaincode/contract.go and
// chaincode/asset/chaincode/contract.go) so the results of
// GetTransaction/GetEventHistory/GetAsset/GetCustodyHistory — read straight
// from the ledger via EvaluateTransaction, not from Postgres — can be
// unmarshaled here. Duplicated rather than shared for the same reason as
// api/internal/httpapi/wire.go: chaincode has no dependency on this module.

type wireTransaction struct {
	ID                     string `json:"id"`
	OrganizationID         string `json:"organization_id"`
	WorkflowType           string `json:"workflow_type"`
	SchemaVersion          string `json:"schema_version"`
	CreatedBy              string `json:"created_by"`
	Status                 string `json:"status"`
	LatestEventSequence    int    `json:"latest_event_sequence"`
	LatestEventPayloadHash string `json:"latest_event_payload_hash"`
}

type wireTransactionEvent struct {
	TransactionID      string `json:"transaction_id"`
	EventSequence      int    `json:"event_sequence"`
	EventType          string `json:"event_type"`
	PayloadHash        string `json:"payload_hash"`
	PreviousEventHash  string `json:"previous_event_hash"`
	AlgorithmSuite     string `json:"algorithm_suite"`
	ClassicalKeyID     string `json:"classical_key_id"`
	PQCKeyID           string `json:"pqc_key_id"`
	ClassicalSignature []byte `json:"classical_signature"`
	PQCSignature       []byte `json:"pqc_signature"`
	IdempotencyKey     string `json:"idempotency_key"`
	CreatedAtServer    string `json:"created_at_server"`
	NewStatus          string `json:"new_status"`
}

type wireAsset struct {
	ID                     string `json:"id"`
	OrganizationID         string `json:"organization_id"`
	AssetTag               string `json:"asset_tag"`
	Status                 string `json:"status"`
	LatestEventSequence    int    `json:"latest_event_sequence"`
	LatestEventPayloadHash string `json:"latest_event_payload_hash"`
}

type wireCustodyEvent struct {
	AssetID            string `json:"asset_id"`
	EventSequence      int    `json:"event_sequence"`
	FromParty          string `json:"from_party"`
	ToParty            string `json:"to_party"`
	LocationZone       string `json:"location_zone"`
	ConditionNote      string `json:"condition_note"`
	InspectionResult   string `json:"inspection_result"`
	PayloadHash        string `json:"payload_hash"`
	PreviousEventHash  string `json:"previous_event_hash"`
	AlgorithmSuite     string `json:"algorithm_suite"`
	ClassicalKeyID     string `json:"classical_key_id"`
	PQCKeyID           string `json:"pqc_key_id"`
	ClassicalSignature []byte `json:"classical_signature"`
	PQCSignature       []byte `json:"pqc_signature"`
	IdempotencyKey     string `json:"idempotency_key"`
	CreatedAtServer    string `json:"created_at_server"`
	NewStatus          string `json:"new_status"`
}

// EventResult is one event's verification outcome within a Receipt.
type EventResult struct {
	EventSequence  int      `json:"event_sequence"`
	SuiteAllowed   bool     `json:"suite_allowed"`
	ClassicalValid bool     `json:"classical_valid"`
	PQCValid       bool     `json:"pqc_valid"`
	HashChainValid bool     `json:"hash_chain_valid"`
	KeyRevoked     bool     `json:"key_revoked"`
	Valid          bool     `json:"valid"`
	Reasons        []string `json:"reasons,omitempty"`
}

// Receipt is the verification receipt PRD FR-014 asks for: enough detail for
// an auditor to see exactly what passed or failed, without exposing
// anything beyond what the ledger and key_reference already disclose.
type Receipt struct {
	ID          string        `json:"id"`
	OverallValid bool         `json:"overall_valid"`
	EventCount  int           `json:"event_count"`
	Events      []EventResult `json:"events"`
}
