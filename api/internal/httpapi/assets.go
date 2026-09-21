package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ledger/crypto"
)

type createAssetRequest struct {
	OrganizationID string `json:"organization_id"`
	AssetTag       string `json:"asset_tag"`
}

// CreateAsset mirrors CreateTransaction's shape for the asset aggregate
// (PRD §5.2).
func (s *Server) CreateAsset(w http.ResponseWriter, r *http.Request) {
	var req createAssetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.OrganizationID == "" || req.AssetTag == "" {
		writeError(w, http.StatusBadRequest, "organization_id and asset_tag are required")
		return
	}

	ctx := r.Context()
	id := "asset_" + uuid.NewString()

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO asset (id, organization_id, asset_tag, status)
		VALUES ($1, $2, $3, 'CREATED')`,
		id, req.OrganizationID, req.AssetTag,
	); err != nil {
		s.Logger.Error("create asset: insert", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	payload, err := json.Marshal([]string{id, req.OrganizationID, req.AssetTag})
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := enqueueOutbox(ctx, tx, "asset", id, "asset", "CreateAsset", payload); err != nil {
		s.Logger.Error("create asset: enqueue outbox", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "status": "CREATED"})
}

type recordCustodyEventRequest struct {
	FromParty        string                 `json:"from_party"`
	ToParty          string                 `json:"to_party"`
	LocationZone     string                 `json:"location_zone"`
	ConditionNote    string                 `json:"condition_note"`
	InspectionResult string                 `json:"inspection_result"`
	Payload          map[string]interface{} `json:"payload"`
	NewStatus        string                 `json:"new_status"`
	SignerIdentity   string                 `json:"signer_identity"`
	IdempotencyKey   string                 `json:"idempotency_key,omitempty"`
}

// RecordCustodyEvent mirrors RecordTransactionEvent for asset custody
// (PRD §5.2's required fields: parties, location, condition, inspection,
// signatures, previous-event hash).
func (s *Server) RecordCustodyEvent(w http.ResponseWriter, r *http.Request) {
	assetID := chi.URLParam(r, "id")

	var req recordCustodyEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON body")
		return
	}
	if req.ToParty == "" || req.NewStatus == "" || req.SignerIdentity == "" {
		writeError(w, http.StatusBadRequest, "to_party, new_status, and signer_identity are required")
		return
	}
	if req.IdempotencyKey == "" {
		req.IdempotencyKey = uuid.NewString()
	}

	ctx := r.Context()

	var exists bool
	if err := s.DB.QueryRow(ctx, `SELECT true FROM asset WHERE id = $1`, assetID).Scan(&exists); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			writeError(w, http.StatusNotFound, "asset not found")
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
		SELECT event_sequence, payload_hash FROM custody_event
		WHERE asset_id = $1 ORDER BY event_sequence DESC LIMIT 1`, assetID,
	).Scan(&lastSeq, &lastHash)
	switch {
	case err == nil:
		nextSequence = lastSeq + 1
		previousHash = lastHash
	case errors.Is(err, pgx.ErrNoRows):
		// first custody event for this asset
	default:
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	identity, err := s.Keystore.SigningIdentity(ctx, req.SignerIdentity)
	if err != nil {
		s.Logger.Error("record custody event: signing identity", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	signCtx := crypto.SigningContext{
		Application:     s.Application,
		Environment:     s.Environment,
		TransactionType: "ASSET_CUSTODY_" + req.NewStatus,
		SchemaVersion:   "custody_event.v1",
		TransactionID:   assetID,
	}
	sig, payloadHash, err := crypto.SignHybrid(identity, signCtx, req.Payload)
	if err != nil {
		s.Logger.Error("record custody event: sign", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	createdAtServer := time.Now().UTC().Format(time.RFC3339)
	eventID := uuid.NewString()

	if _, err := tx.Exec(ctx, `
		INSERT INTO custody_event (
			id, asset_id, event_sequence, from_party, to_party, location_zone, condition_note,
			inspection_result, payload_hash, previous_event_hash, algorithm_suite,
			classical_key_id, pqc_key_id, classical_signature, pqc_signature,
			idempotency_key, created_at_server
		) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)`,
		eventID, assetID, nextSequence, req.FromParty, req.ToParty, req.LocationZone, req.ConditionNote,
		req.InspectionResult, payloadHash, previousHash, string(sig.AlgorithmSuite),
		sig.ClassicalKeyID, sig.PQCKeyID, sig.ClassicalSignature, sig.PQCSignature,
		req.IdempotencyKey, createdAtServer,
	); err != nil {
		s.Logger.Error("record custody event: insert", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	evt := chaincodeCustodyEvent{
		AssetID:            assetID,
		EventSequence:      nextSequence,
		FromParty:          req.FromParty,
		ToParty:            req.ToParty,
		LocationZone:       req.LocationZone,
		ConditionNote:      req.ConditionNote,
		InspectionResult:   req.InspectionResult,
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
	if err := enqueueOutbox(ctx, tx, "asset", assetID, "asset", "RecordCustodyEvent", payload); err != nil {
		s.Logger.Error("record custody event: enqueue outbox", "error", err)
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

// GetAsset reads the operational read model (custody header + full custody
// history) — never Fabric directly (PRD FR-011).
func (s *Server) GetAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var resp struct {
		ID             string `json:"id"`
		OrganizationID string `json:"organization_id"`
		AssetTag       string `json:"asset_tag"`
		Status         string `json:"status"`
	}
	err := s.DB.QueryRow(ctx, `
		SELECT id, organization_id, asset_tag, status FROM asset WHERE id = $1`, id,
	).Scan(&resp.ID, &resp.OrganizationID, &resp.AssetTag, &resp.Status)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "asset not found")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	rows, err := s.DB.Query(ctx, `
		SELECT event_sequence, from_party, to_party, location_zone, condition_note, inspection_result,
		       payload_hash, previous_event_hash, algorithm_suite, idempotency_key, created_at_server,
		       fabric_tx_id, fabric_block_number, committed_at
		FROM custody_event WHERE asset_id = $1 ORDER BY event_sequence`, id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()

	type custodyEventView struct {
		EventSequence     int        `json:"event_sequence"`
		FromParty         string     `json:"from_party"`
		ToParty           string     `json:"to_party"`
		LocationZone      string     `json:"location_zone"`
		ConditionNote     string     `json:"condition_note"`
		InspectionResult  string     `json:"inspection_result"`
		PayloadHash       string     `json:"payload_hash"`
		PreviousEventHash string     `json:"previous_event_hash"`
		AlgorithmSuite    string     `json:"algorithm_suite"`
		IdempotencyKey    string     `json:"idempotency_key"`
		CreatedAtServer   string     `json:"created_at_server"`
		FabricTxID        *string    `json:"fabric_tx_id,omitempty"`
		FabricBlockNumber *int64     `json:"fabric_block_number,omitempty"`
		CommittedAt       *time.Time `json:"committed_at,omitempty"`
	}
	events := make([]custodyEventView, 0)
	for rows.Next() {
		var e custodyEventView
		if err := rows.Scan(&e.EventSequence, &e.FromParty, &e.ToParty, &e.LocationZone, &e.ConditionNote, &e.InspectionResult,
			&e.PayloadHash, &e.PreviousEventHash, &e.AlgorithmSuite, &e.IdempotencyKey, &e.CreatedAtServer,
			&e.FabricTxID, &e.FabricBlockNumber, &e.CommittedAt); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		events = append(events, e)
	}

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"asset":          resp,
		"custody_events": events,
	})
}
