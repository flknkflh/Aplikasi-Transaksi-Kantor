package httpapi

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ledger/crypto"
)

type createTransactionRequest struct {
	OrganizationID string `json:"organization_id"`
	WorkflowType   string `json:"workflow_type"`
	SchemaVersion  string `json:"schema_version"`
	CreatedBy      string `json:"created_by"`
}

// CreateTransaction handles PRD §5.1 steps 1-2: a validated DRAFT is
// recorded operationally; the ledger-facing CreateTransaction chaincode call
// is queued via the outbox rather than called inline, keeping every
// chaincode-bound write on the same reliable path (PRD §9's transactional
// outbox requirement).
func (s *Server) CreateTransaction(w http.ResponseWriter, r *http.Request) {
	var req createTransactionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.OrganizationID == "" || req.WorkflowType == "" || req.SchemaVersion == "" || req.CreatedBy == "" {
		writeError(w, http.StatusBadRequest, "organization_id, workflow_type, schema_version, and created_by are required")
		return
	}

	ctx := r.Context()
	id := "txn_" + uuid.NewString()

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO transaction (id, organization_id, workflow_type, schema_version, created_by, status)
		VALUES ($1, $2, $3, $4, $5, 'DRAFT')`,
		id, req.OrganizationID, req.WorkflowType, req.SchemaVersion, req.CreatedBy,
	); err != nil {
		s.Logger.Error("create transaction: insert", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	payload, err := json.Marshal([]string{id, req.OrganizationID, req.WorkflowType, req.SchemaVersion, req.CreatedBy})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := enqueueOutbox(ctx, tx, "transaction", id, "transaction", "CreateTransaction", payload); err != nil {
		s.Logger.Error("create transaction: enqueue outbox", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "DRAFT"})
}

type recordEventRequest struct {
	EventType      string                 `json:"event_type"`
	Payload        map[string]interface{} `json:"payload"`
	NewStatus      string                 `json:"new_status"`
	SignerIdentity string                 `json:"signer_identity"`
	IdempotencyKey string                 `json:"idempotency_key,omitempty"`
}

// RecordTransactionEvent handles PRD §5.1 steps 4-7: canonicalize, hybrid
// sign, and queue the event for ledger submission. event_sequence and
// previous_event_hash are computed here from Postgres's view of this
// transaction's history (optimistic, single-writer-per-transaction
// assumption — see docs/adr/0001-fase1-spike-scope.md for this spike's known
// limitations); the chaincode independently re-validates both fields
// authoritatively before committing (defense in depth, PRD §3).
func (s *Server) RecordTransactionEvent(w http.ResponseWriter, r *http.Request) {
	transactionID := chi.URLParam(r, "id")

	var req recordEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.EventType == "" || req.SignerIdentity == "" {
		writeError(w, http.StatusBadRequest, "event_type and signer_identity are required")
		return
	}
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = uuid.NewString()
	}

	ctx := r.Context()

	var schemaVersion string
	if err := s.DB.QueryRow(ctx, `SELECT schema_version FROM transaction WHERE id = $1`, transactionID).Scan(&schemaVersion); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "transaction not found")
			return
		}
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)

	nextSequence := 1
	previousHash := ""
	var lastSeq int
	var lastHash string
	err = tx.QueryRow(ctx, `
		SELECT event_sequence, payload_hash FROM transaction_event
		WHERE transaction_id = $1 ORDER BY event_sequence DESC LIMIT 1`, transactionID,
	).Scan(&lastSeq, &lastHash)
	switch {
	case err == nil:
		nextSequence = lastSeq + 1
		previousHash = lastHash
	case errors.Is(err, pgx.ErrNoRows):
		// first event for this transaction
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	identity, err := s.Keystore.SigningIdentity(ctx, req.SignerIdentity)
	if err != nil {
		s.Logger.Error("record event: signing identity", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	signCtx := crypto.SigningContext{
		Application:     s.Application,
		Environment:     s.Environment,
		TransactionType: req.EventType,
		SchemaVersion:   schemaVersion,
		TransactionID:   transactionID,
	}
	sig, payloadHash, err := crypto.SignHybrid(identity, signCtx, req.Payload)
	if err != nil {
		s.Logger.Error("record event: sign", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	createdAtServer := time.Now().UTC().Format(time.RFC3339)
	eventID := uuid.NewString()

	if _, err := tx.Exec(ctx, `
		INSERT INTO transaction_event (
			id, transaction_id, event_sequence, event_type, payload_hash, previous_event_hash,
			algorithm_suite, classical_key_id, pqc_key_id, classical_signature, pqc_signature,
			idempotency_key, created_at_server
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		eventID, transactionID, nextSequence, req.EventType, payloadHash, previousHash,
		string(sig.AlgorithmSuite), sig.ClassicalKeyID, sig.PQCKeyID, sig.ClassicalSignature, sig.PQCSignature,
		req.IdempotencyKey, createdAtServer,
	); err != nil {
		s.Logger.Error("record event: insert", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	evt := chaincodeTransactionEvent{
		TransactionID:      transactionID,
		EventSequence:      nextSequence,
		EventType:          req.EventType,
		PayloadHash:        payloadHash,
		PreviousEventHash:  previousHash,
		AlgorithmSuite:     string(sig.AlgorithmSuite),
		ClassicalKeyID:     sig.ClassicalKeyID,
		PQCKeyID:           sig.PQCKeyID,
		ClassicalSignature: sig.ClassicalSignature,
		PQCSignature:       sig.PQCSignature,
		IdempotencyKey:     req.IdempotencyKey,
		CreatedAtServer:    createdAtServer,
		NewStatus:          req.NewStatus,
	}
	evtJSON, err := json.Marshal(evt)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	payload, err := json.Marshal([]string{string(evtJSON)})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := enqueueOutbox(ctx, tx, "transaction", transactionID, "transaction", "RecordEvent", payload); err != nil {
		s.Logger.Error("record event: enqueue outbox", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]interface{}{
		"event_sequence": nextSequence,
		"payload_hash":   payloadHash,
		"status":         "queued",
	})
}

type approveRequest struct {
	EventSequence int    `json:"event_sequence"`
	ApproverID    string `json:"approver_id"`
	Decision      string `json:"decision"`
	PolicyVersion string `json:"policy_version"`
}

// ApproveTransaction records an approval decision, queued via the outbox
// like everything else. Self-approval (PRD FR-003) is ultimately enforced by
// the chaincode; the read model here just needs the decision recorded.
func (s *Server) ApproveTransaction(w http.ResponseWriter, r *http.Request) {
	transactionID := chi.URLParam(r, "id")

	var req approveRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.Decision != "approve" && req.Decision != "reject" {
		writeError(w, http.StatusBadRequest, "decision must be 'approve' or 'reject'")
		return
	}
	if req.ApproverID == "" || req.PolicyVersion == "" {
		writeError(w, http.StatusBadRequest, "approver_id and policy_version are required")
		return
	}

	ctx := r.Context()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)

	var eventRowID string
	err = tx.QueryRow(ctx, `
		SELECT id FROM transaction_event WHERE transaction_id = $1 AND event_sequence = $2`,
		transactionID, req.EventSequence,
	).Scan(&eventRowID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "event not found for this transaction")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	approvalID := uuid.NewString()
	if _, err := tx.Exec(ctx, `
		INSERT INTO approval (id, transaction_id, event_id, approver_id, decision, policy_version)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		approvalID, transactionID, eventRowID, req.ApproverID, req.Decision, req.PolicyVersion,
	); err != nil {
		s.Logger.Error("approve: insert", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	payload, err := json.Marshal([]string{transactionID, fmt.Sprintf("%d", req.EventSequence), req.ApproverID, req.Decision, req.PolicyVersion})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := enqueueOutbox(ctx, tx, "transaction", transactionID, "transaction", "Approve", payload); err != nil {
		s.Logger.Error("approve: enqueue outbox", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusAccepted, map[string]string{"status": "queued"})
}

// GetTransaction reads the operational read model only (PRD FR-011:
// "Search membaca read model, bukan query langsung ke ledger") — it never
// queries Fabric directly.
func (s *Server) GetTransaction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var resp struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organization_id"`
		WorkflowType   string `json:"workflow_type"`
		SchemaVersion  string `json:"schema_version"`
		CreatedBy      string `json:"created_by"`
		Status         string `json:"status"`
	}
	err := s.DB.QueryRow(ctx, `
		SELECT id, organization_id, workflow_type, schema_version, created_by, status
		FROM transaction WHERE id = $1`, id,
	).Scan(&resp.ID, &resp.OrganizationID, &resp.WorkflowType, &resp.SchemaVersion, &resp.CreatedBy, &resp.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "transaction not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	rows, err := s.DB.Query(ctx, `
		SELECT event_sequence, event_type, payload_hash, previous_event_hash, algorithm_suite,
		       idempotency_key, created_at_server, fabric_tx_id, fabric_block_number, committed_at
		FROM transaction_event WHERE transaction_id = $1 ORDER BY event_sequence`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	type eventView struct {
		EventSequence     int        `json:"event_sequence"`
		EventType         string     `json:"event_type"`
		PayloadHash       string     `json:"payload_hash"`
		PreviousEventHash string     `json:"previous_event_hash"`
		AlgorithmSuite    string     `json:"algorithm_suite"`
		IdempotencyKey    string     `json:"idempotency_key"`
		CreatedAtServer   string     `json:"created_at_server"`
		FabricTxID        *string    `json:"fabric_tx_id,omitempty"`
		FabricBlockNumber *int64     `json:"fabric_block_number,omitempty"`
		CommittedAt       *time.Time `json:"committed_at,omitempty"`
	}
	events := make([]eventView, 0)
	for rows.Next() {
		var e eventView
		if err := rows.Scan(&e.EventSequence, &e.EventType, &e.PayloadHash, &e.PreviousEventHash, &e.AlgorithmSuite,
			&e.IdempotencyKey, &e.CreatedAtServer, &e.FabricTxID, &e.FabricBlockNumber, &e.CommittedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		events = append(events, e)
	}

	approvalRows, err := s.DB.Query(ctx, `
		SELECT approver_id, decision, policy_version, created_at
		FROM approval WHERE transaction_id = $1 ORDER BY created_at`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer approvalRows.Close()

	type approvalView struct {
		ApproverID    string    `json:"approver_id"`
		Decision      string    `json:"decision"`
		PolicyVersion string    `json:"policy_version"`
		CreatedAt     time.Time `json:"created_at"`
	}
	approvals := make([]approvalView, 0)
	for approvalRows.Next() {
		var a approvalView
		if err := approvalRows.Scan(&a.ApproverID, &a.Decision, &a.PolicyVersion, &a.CreatedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		approvals = append(approvals, a)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"transaction": resp,
		"events":      events,
		"approvals":   approvals,
	})
}
