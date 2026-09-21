// Package httpapi is the Fase 1 spike's REST API: transactions, assets,
// approvals, and documents (PRD §8 FR-002, FR-003, FR-005, FR-006). Every
// write here follows the same shape: validate, write Postgres + an
// outbox_event row in one DB transaction, respond — the outbox worker
// (ledger/api/internal/outbox) is solely responsible for getting the event
// onto the Fabric ledger from there. See docs/adr/0001-fase1-spike-scope.md.
package httpapi

import (
	"log/slog"
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/minio/minio-go/v7"

	"ledger/api/internal/keystore"
)

type Server struct {
	DB          *pgxpool.Pool
	Keystore    *keystore.Store
	MinIO       *minio.Client
	Bucket      string
	Application string
	Environment string
	Logger      *slog.Logger

	// Office app (nil Office = the routes are not mounted). See office.go.
	Office  *OfficeConfig
	Objects ObjectStore
	TTD     TTDVerifier
}

func (s *Server) Routes() http.Handler {
	r := chi.NewRouter()

	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	r.Route("/transactions", func(r chi.Router) {
		r.Post("/", s.CreateTransaction)
		r.Get("/{id}", s.GetTransaction)
		r.Post("/{id}/events", s.RecordTransactionEvent)
		r.Post("/{id}/approve", s.ApproveTransaction)
	})

	r.Route("/assets", func(r chi.Router) {
		r.Post("/", s.CreateAsset)
		r.Get("/{id}", s.GetAsset)
		r.Post("/{id}/custody-events", s.RecordCustodyEvent)
	})

	r.Post("/documents", s.UploadDocument)

	if s.Office != nil {
		r.Route("/office", s.officeRoutes)
	}

	return r
}
