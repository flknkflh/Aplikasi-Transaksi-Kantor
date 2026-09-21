// Package chaincode implements the transaction/approval Fabric smart
// contract. Per docs/adr/0001-fase1-spike-scope.md decision #1, it does NOT
// cryptographically verify the hybrid signatures it stores — that happens in
// the API (before submission) and independently in the audit-service
// (against committed ledger data). What it does enforce, on-chain, fail
// closed (PRD §3):
//
//   - append-only ordering: event_sequence and previous_event_hash must
//     chain correctly onto the transaction's latest recorded event;
//   - idempotency: an idempotency_key can never be committed twice
//     (PRD §7 "Event yang sama tidak boleh dapat di-commit dua kali");
//   - algorithm_suite allow-listing, as a ledger-layer belt on top of the
//     API/audit-service's actual signature verification — an event
//     claiming a non-allow-listed suite (e.g. a classical-only downgrade)
//     is rejected here too, not just upstream;
//   - valid transaction status transitions;
//   - self-approval rejection (PRD FR-003).
package chaincode

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// allowedAlgorithmSuite must match crypto.SuiteHybridEd25519MLDSA65V1 in
// ledger/crypto. Duplicated as a plain string here (rather than importing
// the crypto module) because chaincode deliberately has no dependency on it
// (signatures are verified in the API and audit-service) — see ADR-0001.
const allowedAlgorithmSuite = "HYBRID_ED25519_MLDSA65_V1"

// allowedTransitions encodes the status state machine from PRD §5.1/§5.2.
// REVOKED is handled separately in isTransitionAllowed since it can be
// reached from any non-terminal status (emergency/compromise response,
// PRD §15 "Respons kompromi kunci").
var allowedTransitions = map[string][]string{
	"DRAFT":     {"VERIFIED", "CANCELLED"},
	"VERIFIED":  {"ENDORSED", "REJECTED", "CANCELLED"},
	"ENDORSED":  {"COMMITTED", "REJECTED"},
	"COMMITTED": {"SETTLED", "REJECTED"},
	"SETTLED":   {"SUPERSEDED"},
}

func isTransitionAllowed(current, next string) bool {
	if next == "REVOKED" {
		return current != "REVOKED"
	}
	for _, allowed := range allowedTransitions[current] {
		if allowed == next {
			return true
		}
	}
	return false
}

// Transaction is the on-chain transaction header. LatestEventSequence and
// LatestEventPayloadHash are maintained here so RecordEvent can validate the
// next event's linkage in O(1) instead of scanning the full event history on
// every append.
type Transaction struct {
	ID                     string `json:"id"`
	OrganizationID         string `json:"organization_id"`
	WorkflowType           string `json:"workflow_type"`
	SchemaVersion          string `json:"schema_version"`
	CreatedBy              string `json:"created_by"`
	Status                 string `json:"status"`
	LatestEventSequence    int    `json:"latest_event_sequence"`
	LatestEventPayloadHash string `json:"latest_event_payload_hash"`
}

// TransactionEvent mirrors the PRD §7 ledger envelope fields. Signatures are
// stored as-is (base64 via Go's []byte JSON encoding) for the API/
// audit-service to verify; this contract never inspects their bytes beyond
// checking they are present.
type TransactionEvent struct {
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
	// NewStatus, if non-empty, is the status the transaction should move to
	// as a result of this event, validated against allowedTransitions.
	NewStatus string `json:"new_status"`
}

// Approval records a single approver's decision on a specific event.
type Approval struct {
	TransactionID string `json:"transaction_id"`
	EventSequence int    `json:"event_sequence"`
	ApproverID    string `json:"approver_id"`
	Decision      string `json:"decision"`
	PolicyVersion string `json:"policy_version"`
}

// TransactionContract is the Fabric smart contract.
type TransactionContract struct {
	contractapi.Contract
}

func transactionKey(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	return ctx.GetStub().CreateCompositeKey("transaction", []string{id})
}

func eventKey(ctx contractapi.TransactionContextInterface, transactionID string, sequence int) (string, error) {
	return ctx.GetStub().CreateCompositeKey("transaction_event", []string{transactionID, fmt.Sprintf("%09d", sequence)})
}

func idempotencyKey(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	return ctx.GetStub().CreateCompositeKey("idempotency", []string{key})
}

func approvalKey(ctx contractapi.TransactionContextInterface, transactionID string, sequence int, approverID string) (string, error) {
	return ctx.GetStub().CreateCompositeKey("approval", []string{transactionID, fmt.Sprintf("%09d", sequence), approverID})
}

// CreateTransaction creates the DRAFT header for a new transaction. Fails if
// a transaction with the same id already exists (world state is keyed by id,
// so this is also where a client-supplied duplicate create is caught).
func (c *TransactionContract) CreateTransaction(ctx contractapi.TransactionContextInterface, id, organizationID, workflowType, schemaVersion, createdBy string) error {
	if id == "" {
		return errors.New("transaction id is required")
	}
	key, err := transactionKey(ctx, id)
	if err != nil {
		return err
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("read transaction: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("transaction %s already exists", id)
	}

	txn := Transaction{
		ID:             id,
		OrganizationID: organizationID,
		WorkflowType:   workflowType,
		SchemaVersion:  schemaVersion,
		CreatedBy:      createdBy,
		Status:         "DRAFT",
	}
	data, err := json.Marshal(txn)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return err
	}
	// Emitted so the indexer (PRD FR-009) can update the Postgres read model
	// without polling the ledger.
	return ctx.GetStub().SetEvent("TransactionCreated", data)
}

// GetTransaction reads the current transaction header.
func (c *TransactionContract) GetTransaction(ctx contractapi.TransactionContextInterface, id string) (*Transaction, error) {
	key, err := transactionKey(ctx, id)
	if err != nil {
		return nil, err
	}
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("read transaction: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("transaction %s does not exist", id)
	}
	var txn Transaction
	if err := json.Unmarshal(data, &txn); err != nil {
		return nil, err
	}
	return &txn, nil
}

// RecordEvent appends one event to a transaction's history. See the package
// doc for exactly what is and isn't enforced here.
func (c *TransactionContract) RecordEvent(ctx contractapi.TransactionContextInterface, eventJSON string) error {
	var event TransactionEvent
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return fmt.Errorf("invalid event payload: %w", err)
	}
	if event.TransactionID == "" {
		return errors.New("transaction_id is required")
	}
	if event.IdempotencyKey == "" {
		return errors.New("idempotency_key is required")
	}
	if event.AlgorithmSuite != allowedAlgorithmSuite {
		return fmt.Errorf("algorithm_suite %q is not allowed (possible downgrade attempt)", event.AlgorithmSuite)
	}
	if len(event.ClassicalSignature) == 0 || len(event.PQCSignature) == 0 {
		return errors.New("both classical_signature and pqc_signature are required")
	}

	txn, err := c.GetTransaction(ctx, event.TransactionID)
	if err != nil {
		return err
	}

	if event.NewStatus != "" && !isTransitionAllowed(txn.Status, event.NewStatus) {
		return fmt.Errorf("invalid status transition from %s to %s", txn.Status, event.NewStatus)
	}

	expectedSequence := txn.LatestEventSequence + 1
	if event.EventSequence != expectedSequence {
		return fmt.Errorf("expected event_sequence %d, got %d", expectedSequence, event.EventSequence)
	}
	if event.PreviousEventHash != txn.LatestEventPayloadHash {
		return fmt.Errorf("previous_event_hash mismatch: expected %q, got %q", txn.LatestEventPayloadHash, event.PreviousEventHash)
	}

	idemKey, err := idempotencyKey(ctx, event.IdempotencyKey)
	if err != nil {
		return err
	}
	existingIdem, err := ctx.GetStub().GetState(idemKey)
	if err != nil {
		return fmt.Errorf("read idempotency marker: %w", err)
	}
	if existingIdem != nil {
		return fmt.Errorf("idempotency_key %q has already been committed (duplicate/replay rejected)", event.IdempotencyKey)
	}

	evtKey, err := eventKey(ctx, event.TransactionID, event.EventSequence)
	if err != nil {
		return err
	}
	evtBytes, err := json.Marshal(event)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(evtKey, evtBytes); err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(idemKey, []byte(evtKey)); err != nil {
		return err
	}

	txn.LatestEventSequence = event.EventSequence
	txn.LatestEventPayloadHash = event.PayloadHash
	if event.NewStatus != "" {
		txn.Status = event.NewStatus
	}
	txnKey, err := transactionKey(ctx, event.TransactionID)
	if err != nil {
		return err
	}
	txnBytes, err := json.Marshal(txn)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(txnKey, txnBytes); err != nil {
		return err
	}
	// evtBytes (not txnBytes) is the payload: the indexer's read model wants
	// the event that was just recorded, not the transaction header.
	return ctx.GetStub().SetEvent("TransactionEventRecorded", evtBytes)
}

// GetEventHistory returns every event recorded for a transaction, in
// event_sequence order (guaranteed by the zero-padded sequence component of
// the composite key).
func (c *TransactionContract) GetEventHistory(ctx contractapi.TransactionContextInterface, transactionID string) ([]*TransactionEvent, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey("transaction_event", []string{transactionID})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	events := make([]*TransactionEvent, 0)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var evt TransactionEvent
		if err := json.Unmarshal(kv.Value, &evt); err != nil {
			return nil, err
		}
		events = append(events, &evt)
	}
	return events, nil
}

// Approve records an approver's decision on a specific event. Self-approval
// is rejected per PRD FR-003 ("tidak boleh menyetujui pengajuannya
// sendiri"). A reject decision moves the transaction to REJECTED (subject to
// the same transition validation as RecordEvent); an approve decision is
// recorded but does not itself change status — the API layer decides when
// enough approvals exist to advance the transaction via RecordEvent.
func (c *TransactionContract) Approve(ctx contractapi.TransactionContextInterface, transactionID string, eventSequence int, approverID, decision, policyVersion string) error {
	if decision != "approve" && decision != "reject" {
		return fmt.Errorf("decision must be 'approve' or 'reject', got %q", decision)
	}

	txn, err := c.GetTransaction(ctx, transactionID)
	if err != nil {
		return err
	}
	if approverID == txn.CreatedBy {
		return fmt.Errorf("self-approval is not allowed: approver %q created this transaction", approverID)
	}

	key, err := approvalKey(ctx, transactionID, eventSequence, approverID)
	if err != nil {
		return err
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("read approval: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("approver %q has already recorded a decision for event %d", approverID, eventSequence)
	}

	approval := Approval{
		TransactionID: transactionID,
		EventSequence: eventSequence,
		ApproverID:    approverID,
		Decision:      decision,
		PolicyVersion: policyVersion,
	}
	data, err := json.Marshal(approval)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return err
	}

	if decision == "reject" {
		if !isTransitionAllowed(txn.Status, "REJECTED") {
			return fmt.Errorf("cannot reject transaction in status %s", txn.Status)
		}
		txn.Status = "REJECTED"
		txnKey, err := transactionKey(ctx, transactionID)
		if err != nil {
			return err
		}
		txnBytes, err := json.Marshal(txn)
		if err != nil {
			return err
		}
		if err := ctx.GetStub().PutState(txnKey, txnBytes); err != nil {
			return err
		}
	}
	return ctx.GetStub().SetEvent("ApprovalRecorded", data)
}
