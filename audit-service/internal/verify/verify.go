// Package verify implements independent re-verification of ledger events
// (PRD FR-010): it queries the Fabric ledger directly via EvaluateTransaction
// — never Postgres — recomputes the previous_event_hash chain, and
// re-verifies both halves of every hybrid signature against key_reference.
// An admin who tampers with Postgres's read model cannot fool this: the
// ledger itself, and the chaincode's own append-only/idempotency guarantees,
// are the source of truth here.
package verify

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"fmt"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"ledger/crypto"
)

type Verifier struct {
	DB          *pgxpool.Pool
	Application string
	Environment string
}

// Transaction re-verifies every event of one transaction directly from the
// ledger.
func (v *Verifier) Transaction(ctx context.Context, contract *client.Contract, transactionID string) (*Receipt, error) {
	txnBytes, err := contract.EvaluateTransaction("GetTransaction", transactionID)
	if err != nil {
		return nil, fmt.Errorf("verify: query ledger for transaction: %w", err)
	}
	var txn wireTransaction
	if err := json.Unmarshal(txnBytes, &txn); err != nil {
		return nil, fmt.Errorf("verify: unmarshal transaction: %w", err)
	}

	historyBytes, err := contract.EvaluateTransaction("GetEventHistory", transactionID)
	if err != nil {
		return nil, fmt.Errorf("verify: query ledger for event history: %w", err)
	}
	var events []wireTransactionEvent
	if err := json.Unmarshal(historyBytes, &events); err != nil {
		return nil, fmt.Errorf("verify: unmarshal event history: %w", err)
	}

	receipt := &Receipt{ID: transactionID, OverallValid: true, EventCount: len(events)}
	previousHash := ""

	for _, evt := range events {
		result := EventResult{EventSequence: evt.EventSequence}

		result.HashChainValid = evt.PreviousEventHash == previousHash
		if !result.HashChainValid {
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"previous_event_hash %q does not match prior event's payload_hash %q", evt.PreviousEventHash, previousHash))
		}
		previousHash = evt.PayloadHash

		signCtx := crypto.SigningContext{
			Application:     v.Application,
			Environment:     v.Environment,
			TransactionType: evt.EventType,
			SchemaVersion:   txn.SchemaVersion,
			TransactionID:   transactionID,
		}
		v.verifySignature(ctx, &result, signCtx, evt.PayloadHash, evt.AlgorithmSuite, evt.ClassicalKeyID, evt.PQCKeyID, evt.ClassicalSignature, evt.PQCSignature)

		result.Valid = result.SuiteAllowed && result.ClassicalValid && result.PQCValid && result.HashChainValid && !result.KeyRevoked
		if !result.Valid {
			receipt.OverallValid = false
		}
		receipt.Events = append(receipt.Events, result)
	}

	return receipt, nil
}

// Asset is the asset-custody twin of Transaction.
func (v *Verifier) Asset(ctx context.Context, contract *client.Contract, assetID string) (*Receipt, error) {
	historyBytes, err := contract.EvaluateTransaction("GetCustodyHistory", assetID)
	if err != nil {
		return nil, fmt.Errorf("verify: query ledger for custody history: %w", err)
	}
	var events []wireCustodyEvent
	if err := json.Unmarshal(historyBytes, &events); err != nil {
		return nil, fmt.Errorf("verify: unmarshal custody history: %w", err)
	}

	receipt := &Receipt{ID: assetID, OverallValid: true, EventCount: len(events)}
	previousHash := ""

	for _, evt := range events {
		result := EventResult{EventSequence: evt.EventSequence}

		result.HashChainValid = evt.PreviousEventHash == previousHash
		if !result.HashChainValid {
			result.Reasons = append(result.Reasons, fmt.Sprintf(
				"previous_event_hash %q does not match prior event's payload_hash %q", evt.PreviousEventHash, previousHash))
		}
		previousHash = evt.PayloadHash

		signCtx := crypto.SigningContext{
			Application:     v.Application,
			Environment:     v.Environment,
			TransactionType: "ASSET_CUSTODY_" + evt.NewStatus,
			SchemaVersion:   "custody_event.v1",
			TransactionID:   assetID,
		}
		v.verifySignature(ctx, &result, signCtx, evt.PayloadHash, evt.AlgorithmSuite, evt.ClassicalKeyID, evt.PQCKeyID, evt.ClassicalSignature, evt.PQCSignature)

		result.Valid = result.SuiteAllowed && result.ClassicalValid && result.PQCValid && result.HashChainValid && !result.KeyRevoked
		if !result.Valid {
			receipt.OverallValid = false
		}
		receipt.Events = append(receipt.Events, result)
	}

	return receipt, nil
}

func (v *Verifier) verifySignature(ctx context.Context, result *EventResult, signCtx crypto.SigningContext, payloadHash, algorithmSuite, classicalKeyID, pqcKeyID string, classicalSig, pqcSig []byte) {
	classicalPub, classicalRevoked, err := v.lookupKey(ctx, classicalKeyID)
	if err != nil {
		result.Reasons = append(result.Reasons, fmt.Sprintf("classical_key_id %q: %v", classicalKeyID, err))
		return
	}
	pqcPub, pqcRevoked, err := v.lookupKey(ctx, pqcKeyID)
	if err != nil {
		result.Reasons = append(result.Reasons, fmt.Sprintf("pqc_key_id %q: %v", pqcKeyID, err))
		return
	}
	// Simplification for this spike: flags current revocation status only,
	// not whether the key was already revoked *at the time of the event*
	// (that needs revocation_record.revoked_at vs the event's
	// created_at_server, deferred to Fase 2 — see docs/adr/0001).
	result.KeyRevoked = classicalRevoked || pqcRevoked

	sig := &crypto.HybridSignature{
		AlgorithmSuite:     crypto.AlgorithmSuite(algorithmSuite),
		ClassicalSignature: classicalSig,
		PQCSignature:       pqcSig,
	}
	keys := crypto.VerificationKeys{
		ClassicalPublic: ed25519.PublicKey(classicalPub),
		PQCPublic:       pqcPub,
	}

	verifyResult, err := crypto.VerifyHybridWithHash(keys, sig, signCtx, payloadHash)
	if err != nil {
		result.Reasons = append(result.Reasons, err.Error())
	}
	result.SuiteAllowed = verifyResult.SuiteAllowed
	result.ClassicalValid = verifyResult.ClassicalValid
	result.PQCValid = verifyResult.PQCValid
}

func (v *Verifier) lookupKey(ctx context.Context, keyID string) (publicKey []byte, revoked bool, err error) {
	var status string
	err = v.DB.QueryRow(ctx, `SELECT public_key, status FROM key_reference WHERE id = $1`, keyID).Scan(&publicKey, &status)
	if err == pgx.ErrNoRows {
		return nil, false, fmt.Errorf("no key_reference found")
	}
	if err != nil {
		return nil, false, err
	}
	return publicKey, status == "revoked", nil
}
