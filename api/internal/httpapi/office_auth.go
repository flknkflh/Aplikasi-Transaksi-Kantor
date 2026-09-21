package httpapi

import (
	"context"
	"crypto/subtle"
	"net/http"
	"strings"
)

// OfficeConfig enables the /office routes (the integrated office app).
type OfficeConfig struct {
	// ProxySecret is shared with the TTD server. The office routes are only
	// reachable through that server's authenticated reverse proxy: it validates
	// the user's session, then vouches for the identity with this secret.
	ProxySecret string
	// FabricEnabled only affects what the UI says about ledger recording;
	// events are queued in the outbox either way.
	FabricEnabled bool
}

const (
	roleRequester = "requester"
	roleApprover  = "approver"
	roleAuditor   = "auditor"
)

var validOfficeRoles = map[string]bool{roleRequester: true, roleApprover: true, roleAuditor: true}

type officeIdentity struct {
	ID         string
	Email      string
	Name       string
	TTDRole    string // user | admin | superadmin (from the TTD account)
	OfficeRole string // requester | approver | auditor
}

func (i officeIdentity) isAdmin() bool { return i.TTDRole == "admin" || i.TTDRole == "superadmin" }

// canSeeAll: approvers, auditors and admins see every request; a requester
// sees only their own.
func (i officeIdentity) canSeeAll() bool {
	return i.isAdmin() || i.OfficeRole == roleApprover || i.OfficeRole == roleAuditor
}

type officeCtxKey struct{}

func identityFrom(r *http.Request) officeIdentity {
	v, _ := r.Context().Value(officeCtxKey{}).(officeIdentity)
	return v
}

// officeAuth authenticates a request that arrived through the TTD proxy and
// provisions the user's ledger identity on first use. Without the shared
// secret nothing under /office is reachable, so the (unauthenticated) Fase 1
// endpoints are never the way in for the office app.
func (s *Server) officeAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := r.Header.Get("X-Office-Secret")
		if s.Office == nil || s.Office.ProxySecret == "" ||
			subtle.ConstantTimeCompare([]byte(got), []byte(s.Office.ProxySecret)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		id := officeIdentity{
			ID:      strings.TrimSpace(r.Header.Get("X-Office-Account")),
			Email:   strings.TrimSpace(r.Header.Get("X-Office-Email")),
			Name:    strings.TrimSpace(r.Header.Get("X-Office-Name")),
			TTDRole: strings.TrimSpace(r.Header.Get("X-Office-Role")),
		}
		if id.ID == "" {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		if id.Name == "" {
			id.Name = id.Email
		}
		ctx := r.Context()
		// Provision (idempotent): identity row + effective role.
		if _, err := s.DB.Exec(ctx, `
			INSERT INTO user_identity (id, organization_id, display_name, role, email)
			VALUES ($1, 'org-a', $2, 'requester', $3)
			ON CONFLICT (id) DO UPDATE SET display_name = EXCLUDED.display_name, email = EXCLUDED.email`,
			id.ID, id.Name, id.Email); err != nil {
			s.Logger.Error("office: provision identity", "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		id.OfficeRole = roleRequester
		var role string
		if err := s.DB.QueryRow(ctx, `SELECT role FROM office_role WHERE account_id = $1`, id.ID).Scan(&role); err == nil && validOfficeRoles[role] {
			id.OfficeRole = role
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(ctx, officeCtxKey{}, id)))
	})
}
