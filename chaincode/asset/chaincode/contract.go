// Package chaincode implements the asset custody Fabric smart contract
// (PRD §5.2). Same scope decisions as the transaction contract apply — see
// docs/adr/0001-fase1-spike-scope.md decision #1: signatures are stored and
// idempotency/ordering/lifecycle are enforced on-chain, but cryptographic
// signature verification happens in the API and audit-service, not here.
package chaincode

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"
)

// allowedAlgorithmSuite must match crypto.SuiteHybridEd25519MLDSA65V1 in
// ledger/crypto (duplicated here for the same reason as the transaction
// contract — chaincode has no dependency on the crypto module).
const allowedAlgorithmSuite = "HYBRID_ED25519_MLDSA65_V1"

// allowedLifecycleTransitions is a superset of PRD §5.2's suggested linear
// flow (CREATED → RECEIVED → INSPECTED → STORED → ISSUED → TRANSFERRED →
// MAINTENANCE → RETURNED → RETIRED): real custody histories loop (an asset
// gets issued, returned, transferred, and inspected many times before
// retirement), so this models a graph rather than a single linear path.
var allowedLifecycleTransitions = map[string][]string{
	"CREATED":     {"RECEIVED"},
	"RECEIVED":    {"INSPECTED"},
	"INSPECTED":   {"STORED", "MAINTENANCE"},
	"STORED":      {"ISSUED", "MAINTENANCE", "RETIRED"},
	"ISSUED":      {"TRANSFERRED", "RETURNED"},
	"TRANSFERRED": {"RECEIVED", "MAINTENANCE"},
	"MAINTENANCE": {"RETURNED", "STORED"},
	"RETURNED":    {"STORED", "INSPECTED"},
}

func isLifecycleTransitionAllowed(current, next string) bool {
	for _, allowed := range allowedLifecycleTransitions[current] {
		if allowed == next {
			return true
		}
	}
	return false
}

// Asset is the on-chain asset header, mirroring the migrations `asset`
// table. LatestEventSequence/LatestEventPayloadHash mirror the transaction
// contract's pattern for O(1) append-only linkage checks.
type Asset struct {
	ID                     string `json:"id"`
	OrganizationID         string `json:"organization_id"`
	AssetTag               string `json:"asset_tag"`
	Status                 string `json:"status"`
	LatestEventSequence    int    `json:"latest_event_sequence"`
	LatestEventPayloadHash string `json:"latest_event_payload_hash"`
}

// CustodyEvent mirrors the PRD §5.2 custody event fields.
type CustodyEvent struct {
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
	// NewStatus is the lifecycle status this event moves the asset to,
	// validated against allowedLifecycleTransitions.
	NewStatus string `json:"new_status"`
}

// AssetContract is the Fabric smart contract for asset custody.
type AssetContract struct {
	contractapi.Contract
}

func assetKey(ctx contractapi.TransactionContextInterface, id string) (string, error) {
	return ctx.GetStub().CreateCompositeKey("asset", []string{id})
}

func custodyEventKey(ctx contractapi.TransactionContextInterface, assetID string, sequence int) (string, error) {
	return ctx.GetStub().CreateCompositeKey("custody_event", []string{assetID, fmt.Sprintf("%09d", sequence)})
}

func idempotencyKey(ctx contractapi.TransactionContextInterface, key string) (string, error) {
	return ctx.GetStub().CreateCompositeKey("idempotency", []string{key})
}

// CreateAsset registers a new asset in CREATED status.
func (c *AssetContract) CreateAsset(ctx contractapi.TransactionContextInterface, id, organizationID, assetTag string) error {
	if id == "" {
		return errors.New("asset id is required")
	}
	key, err := assetKey(ctx, id)
	if err != nil {
		return err
	}
	existing, err := ctx.GetStub().GetState(key)
	if err != nil {
		return fmt.Errorf("read asset: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("asset %s already exists", id)
	}

	asset := Asset{
		ID:             id,
		OrganizationID: organizationID,
		AssetTag:       assetTag,
		Status:         "CREATED",
	}
	data, err := json.Marshal(asset)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(key, data); err != nil {
		return err
	}
	return ctx.GetStub().SetEvent("AssetCreated", data)
}

// GetAsset reads the current asset header.
func (c *AssetContract) GetAsset(ctx contractapi.TransactionContextInterface, id string) (*Asset, error) {
	key, err := assetKey(ctx, id)
	if err != nil {
		return nil, err
	}
	data, err := ctx.GetStub().GetState(key)
	if err != nil {
		return nil, fmt.Errorf("read asset: %w", err)
	}
	if data == nil {
		return nil, fmt.Errorf("asset %s does not exist", id)
	}
	var asset Asset
	if err := json.Unmarshal(data, &asset); err != nil {
		return nil, err
	}
	return &asset, nil
}

// RecordCustodyEvent appends one custody event: enforces append-only
// ordering, idempotency, algorithm_suite allow-listing, and a valid
// lifecycle transition — the same fail-closed pattern as the transaction
// contract's RecordEvent.
func (c *AssetContract) RecordCustodyEvent(ctx contractapi.TransactionContextInterface, eventJSON string) error {
	var event CustodyEvent
	if err := json.Unmarshal([]byte(eventJSON), &event); err != nil {
		return fmt.Errorf("invalid custody event payload: %w", err)
	}
	if event.AssetID == "" {
		return errors.New("asset_id is required")
	}
	if event.ToParty == "" {
		return errors.New("to_party is required")
	}
	if event.IdempotencyKey == "" {
		return errors.New("idempotency_key is required")
	}
	if event.NewStatus == "" {
		return errors.New("new_status is required")
	}
	if event.AlgorithmSuite != allowedAlgorithmSuite {
		return fmt.Errorf("algorithm_suite %q is not allowed (possible downgrade attempt)", event.AlgorithmSuite)
	}
	if len(event.ClassicalSignature) == 0 || len(event.PQCSignature) == 0 {
		return errors.New("both classical_signature and pqc_signature are required")
	}

	asset, err := c.GetAsset(ctx, event.AssetID)
	if err != nil {
		return err
	}

	if !isLifecycleTransitionAllowed(asset.Status, event.NewStatus) {
		return fmt.Errorf("invalid lifecycle transition from %s to %s", asset.Status, event.NewStatus)
	}

	expectedSequence := asset.LatestEventSequence + 1
	if event.EventSequence != expectedSequence {
		return fmt.Errorf("expected event_sequence %d, got %d", expectedSequence, event.EventSequence)
	}
	if event.PreviousEventHash != asset.LatestEventPayloadHash {
		return fmt.Errorf("previous_event_hash mismatch: expected %q, got %q", asset.LatestEventPayloadHash, event.PreviousEventHash)
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

	evtKey, err := custodyEventKey(ctx, event.AssetID, event.EventSequence)
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

	asset.LatestEventSequence = event.EventSequence
	asset.LatestEventPayloadHash = event.PayloadHash
	asset.Status = event.NewStatus
	assetKeyStr, err := assetKey(ctx, event.AssetID)
	if err != nil {
		return err
	}
	assetBytes, err := json.Marshal(asset)
	if err != nil {
		return err
	}
	if err := ctx.GetStub().PutState(assetKeyStr, assetBytes); err != nil {
		return err
	}
	return ctx.GetStub().SetEvent("CustodyEventRecorded", evtBytes)
}

// GetCustodyHistory returns every custody event recorded for an asset, in
// event_sequence order.
func (c *AssetContract) GetCustodyHistory(ctx contractapi.TransactionContextInterface, assetID string) ([]*CustodyEvent, error) {
	iter, err := ctx.GetStub().GetStateByPartialCompositeKey("custody_event", []string{assetID})
	if err != nil {
		return nil, err
	}
	defer iter.Close()

	events := make([]*CustodyEvent, 0)
	for iter.HasNext() {
		kv, err := iter.Next()
		if err != nil {
			return nil, err
		}
		var evt CustodyEvent
		if err := json.Unmarshal(kv.Value, &evt); err != nil {
			return nil, err
		}
		events = append(events, &evt)
	}
	return events, nil
}
