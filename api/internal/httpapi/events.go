package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ledger/crypto"
)

// eventInput describes one business event to append to a transaction's
// hash-chained history.
type eventInput struct {
	TransactionID  string
	EventType      string
	SignerIdentity string // user_identity id whose hybrid key signs the event
	Payload        map[string]interface{}
	NewStatus      string // "" = no status change
	IdempotencyKey string // "" = generate
}

type appendedEvent struct {
	Sequence    int
	PayloadHash string
}

// appendTransactionEvent is the single write path for transaction events: it
// computes event_sequence/previous_event_hash from Postgres, signs the payload
// with the hybrid (Ed25519 + ML-DSA-65) identity, stores the event and queues
// the ledger submission through the transactional outbox — all inside the
// caller's DB transaction tx. It is what RecordTransactionEvent always did,
// extracted so the office workflow reuses exactly the same signing/outbox path.
//
// The transaction row is locked (FOR UPDATE) so two concurrent events on one
// transaction serialize instead of racing for the same sequence number.
//
// When updateReadModel is set the transaction's status column is advanced
// here too. The Fase 1 indexer normally does that from chaincode events, but
// with Fabric disabled nothing else would, and the value written is the same
// one the chaincode will commit.
func (s *Server) appendTransactionEvent(ctx context.Context, tx pgx.Tx, in eventInput, updateReadModel bool) (appendedEvent, error) {
	var schemaVersion string
	if err := tx.QueryRow(ctx, `SELECT schema_version FROM transaction WHERE id = $1 FOR UPDATE`, in.TransactionID).Scan(&schemaVersion); err != nil {
		return appendedEvent{}, err
	}
	if in.IdempotencyKey == "" {
		in.IdempotencyKey = uuid.NewString()
	}

	nextSequence := 1
	previousHash := ""
	var lastSeq int
	var lastHash string
	err := tx.QueryRow(ctx, `
		SELECT event_sequence, payload_hash FROM transaction_event
		WHERE transaction_id = $1 ORDER BY event_sequence DESC LIMIT 1`, in.TransactionID,
	).Scan(&lastSeq, &lastHash)
	switch {
	case err == nil:
		nextSequence = lastSeq + 1
		previousHash = lastHash
	case errors.Is(err, pgx.ErrNoRows):
		// first event for this transaction
	default:
		return appendedEvent{}, err
	}

	identity, err := s.Keystore.SigningIdentity(ctx, in.SignerIdentity)
	if err != nil {
		return appendedEvent{}, fmt.Errorf("signing identity: %w", err)
	}
	sig, payloadHash, err := crypto.SignHybrid(identity, crypto.SigningContext{
		Application:     s.Application,
		Environment:     s.Environment,
		TransactionType: in.EventType,
		SchemaVersion:   schemaVersion,
		TransactionID:   in.TransactionID,
	}, in.Payload)
	if err != nil {
		return appendedEvent{}, fmt.Errorf("sign: %w", err)
	}

	payloadJSON, err := json.Marshal(in.Payload)
	if err != nil {
		return appendedEvent{}, err
	}
	createdAtServer := time.Now().UTC().Format(time.RFC3339)
	if _, err := tx.Exec(ctx, `
		INSERT INTO transaction_event (
			id, transaction_id, event_sequence, event_type, payload_hash, previous_event_hash,
			algorithm_suite, classical_key_id, pqc_key_id, classical_signature, pqc_signature,
			idempotency_key, created_at_server, payload, actor_id
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)`,
		uuid.NewString(), in.TransactionID, nextSequence, in.EventType, payloadHash, previousHash,
		string(sig.AlgorithmSuite), sig.ClassicalKeyID, sig.PQCKeyID, sig.ClassicalSignature, sig.PQCSignature,
		in.IdempotencyKey, createdAtServer, payloadJSON, in.SignerIdentity,
	); err != nil {
		return appendedEvent{}, err
	}

	evtJSON, err := json.Marshal(chaincodeTransactionEvent{
		TransactionID:      in.TransactionID,
		EventSequence:      nextSequence,
		EventType:          in.EventType,
		PayloadHash:        payloadHash,
		PreviousEventHash:  previousHash,
		AlgorithmSuite:     string(sig.AlgorithmSuite),
		ClassicalKeyID:     sig.ClassicalKeyID,
		PQCKeyID:           sig.PQCKeyID,
		ClassicalSignature: sig.ClassicalSignature,
		PQCSignature:       sig.PQCSignature,
		IdempotencyKey:     in.IdempotencyKey,
		CreatedAtServer:    createdAtServer,
		NewStatus:          in.NewStatus,
	})
	if err != nil {
		return appendedEvent{}, err
	}
	payload, err := json.Marshal([]string{string(evtJSON)})
	if err != nil {
		return appendedEvent{}, err
	}
	if err := enqueueOutbox(ctx, tx, "transaction", in.TransactionID, "transaction", "RecordEvent", payload); err != nil {
		return appendedEvent{}, err
	}

	if updateReadModel && in.NewStatus != "" {
		if _, err := tx.Exec(ctx, `UPDATE transaction SET status = $2, updated_at = now() WHERE id = $1`, in.TransactionID, in.NewStatus); err != nil {
			return appendedEvent{}, err
		}
	}
	return appendedEvent{Sequence: nextSequence, PayloadHash: payloadHash}, nil
}
