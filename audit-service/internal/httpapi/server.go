// Package httpapi exposes the audit-service's read-only verification API
// (PRD FR-010, FR-014): verification receipts and ledger checkpoints. There
// is no write path here beyond creating checkpoint records — this service
// never touches the ledger's business state.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/jackc/pgx/v5/pgxpool"

	"ledger/audit-service/internal/checkpoint"
	"ledger/audit-service/internal/verify"
)

type Server struct {
	DB          *pgxpool.Pool
	Network     *client.Network
	Verifier    *verify.Verifier
	ChannelName string
	Logger      *slog.Logger
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Get("/verify/transactions/{id}", s.VerifyTransaction)
	r.Get("/verify/assets/{id}", s.VerifyAsset)
	r.Post("/checkpoints", s.CreateCheckpoint)

	return r
}

func (s *Server) VerifyTransaction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	receipt, err := s.Verifier.Transaction(r.Context(), s.Network.GetContract("transaction"), id)
	if err != nil {
		s.Logger.Error("verify transaction", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "verification failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) VerifyAsset(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	receipt, err := s.Verifier.Asset(r.Context(), s.Network.GetContract("asset"), id)
	if err != nil {
		s.Logger.Error("verify asset", "id", id, "error", err)
		writeError(w, http.StatusInternalServerError, "verification failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusOK, receipt)
}

func (s *Server) CreateCheckpoint(w http.ResponseWriter, r *http.Request) {
	blockNumber, blockHash, err := checkpoint.Create(r.Context(), s.DB, s.Network, s.ChannelName)
	if err != nil {
		s.Logger.Error("create checkpoint", "error", err)
		writeError(w, http.StatusInternalServerError, "checkpoint failed: "+err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"block_number": blockNumber,
		"block_hash":   blockHash,
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}
