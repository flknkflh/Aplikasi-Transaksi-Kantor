package httpapi

// These two types are the JSON wire contract submitted to the chaincode's
// RecordEvent/RecordCustodyEvent functions (as the single JSON-string
// argument in an outbox row's payload). Field names and types must match
// chaincode/transaction/chaincode/contract.go's TransactionEvent and
// chaincode/asset/chaincode/contract.go's CustodyEvent exactly — this is a
// deliberate duplication rather than a shared dependency, since chaincode
// has no dependency on this module (or on ledger/crypto) by design; see
// docs/adr/0001-fase1-spike-scope.md decision #1.

type chaincodeTransactionEvent struct {
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

type chaincodeCustodyEvent struct {
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
