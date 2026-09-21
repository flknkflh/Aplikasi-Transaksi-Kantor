package httpapi

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// The office workflow ("pengajuan-kantor", policy-v1 = one approver):
//
//	DRAFT --submit--> VERIFIED --approve (TTD-signed PDF)--> ENDORSED --complete--> COMMITTED
//	                     |--reject--> REJECTED        DRAFT|VERIFIED --cancel--> CANCELLED
//
// Every step is a hybrid-signed, hash-chained event written through
// appendTransactionEvent (=> transactional outbox => ledger). Approval is
// tied to a document signature made in the approver's browser with the TTD
// mechanism; this file only ever *verifies* that signature's record with the
// TTD server, it never signs a document.
const (
	officeWorkflow = "pengajuan-kantor"
	officeSchema   = "1"
	officePolicy   = "policy-v1"
	officeOrg      = "org-a"
)

var officeCategories = map[string]bool{"pengadaan": true, "perjalanan-dinas": true, "reimbursement": true, "lainnya": true}

// officeTransitions mirrors the chaincode's state machine
// (chaincode/transaction/chaincode/contract.go). With Fabric disabled nothing
// else would enforce it, so the API does — and keeps doing so when it is on.
var officeTransitions = map[string][]string{
	"DRAFT":     {"VERIFIED", "CANCELLED"},
	"VERIFIED":  {"ENDORSED", "REJECTED", "CANCELLED"},
	"ENDORSED":  {"COMMITTED", "REJECTED"},
	"COMMITTED": {"SETTLED", "REJECTED"},
	"SETTLED":   {"SUPERSEDED"},
}

func canTransition(cur, next string) bool {
	for _, n := range officeTransitions[cur] {
		if n == next {
			return true
		}
	}
	return false
}

type officePerms struct {
	CanSubmit   bool `json:"can_submit"`
	CanCancel   bool `json:"can_cancel"`
	CanApprove  bool `json:"can_approve"`
	CanReject   bool `json:"can_reject"`
	CanComplete bool `json:"can_complete"`
}

func permsFor(id officeIdentity, createdBy, status string) officePerms {
	creator := id.ID == createdBy
	approver := id.OfficeRole == roleApprover && !creator && status == "VERIFIED"
	return officePerms{
		CanSubmit:   creator && status == "DRAFT",
		CanCancel:   creator && (status == "DRAFT" || status == "VERIFIED"),
		CanApprove:  approver,
		CanReject:   approver,
		CanComplete: (creator || id.isAdmin()) && status == "ENDORSED",
	}
}

func (s *Server) officeRoutes(r chi.Router) {
	r.Use(s.officeAuth)
	r.Get("/me", s.officeMe)
	r.Get("/roles", s.officeListRoles)
	r.Put("/roles/{account_id}", s.officeSetRole)
	r.Get("/transactions", s.officeListTransactions)
	r.Post("/transactions", s.officeCreateTransaction)
	r.Get("/transactions/{id}", s.officeGetTransaction)
	r.Post("/transactions/{id}/submit", s.officeSubmit)
	r.Post("/transactions/{id}/decision", s.officeDecision)
	r.Post("/transactions/{id}/complete", s.officeComplete)
	r.Post("/transactions/{id}/cancel", s.officeCancel)
	r.Get("/documents/{id}", s.officeDownload)
}

// ---------------------------------------------------------------- identity/roles

func (s *Server) officeMe(w http.ResponseWriter, r *http.Request) {
	id := identityFrom(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id": id.ID, "email": id.Email, "name": id.Name,
		"office_role": id.OfficeRole, "ttd_role": id.TTDRole, "is_admin": id.isAdmin(),
		"fabric_enabled": s.Office.FabricEnabled,
	})
}

func (s *Server) officeListRoles(w http.ResponseWriter, r *http.Request) {
	if !identityFrom(r).isAdmin() {
		writeError(w, http.StatusForbidden, "hanya admin")
		return
	}
	rows, err := s.DB.Query(r.Context(), `
		SELECT u.id, COALESCE(u.email,''), u.display_name, COALESCE(o.role, 'requester')
		FROM user_identity u LEFT JOIN office_role o ON o.account_id = u.id
		WHERE u.id NOT IN ('requester-1','approver-1','approver-2','warehouse-1','auditor-1')
		ORDER BY u.display_name`)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var id, email, name, role string
		if err := rows.Scan(&id, &email, &name, &role); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		out = append(out, map[string]string{"account_id": id, "email": email, "name": name, "role": role})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"roles": out})
}

// officeSetRole assigns an office role. The account may not have opened the
// office app yet, so the identity row is provisioned from the admin's request.
func (s *Server) officeSetRole(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if !me.isAdmin() {
		writeError(w, http.StatusForbidden, "hanya admin")
		return
	}
	var in struct {
		Role  string `json:"role"`
		Email string `json:"email"`
		Name  string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil || !validOfficeRoles[in.Role] {
		writeError(w, http.StatusBadRequest, "role harus requester, approver, atau auditor")
		return
	}
	account := chi.URLParam(r, "account_id")
	if account == "" || len(account) > 100 {
		writeError(w, http.StatusBadRequest, "account_id tidak valid")
		return
	}
	ctx := r.Context()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)
	name := in.Name
	if name == "" {
		name = in.Email
	}
	if name == "" {
		name = account
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_identity (id, organization_id, display_name, role, email) VALUES ($1, $2, $3, $4, NULLIF($5,''))
		ON CONFLICT (id) DO UPDATE SET role = EXCLUDED.role`, account, officeOrg, name, in.Role, in.Email); err != nil {
		s.Logger.Error("office: set role (identity)", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO office_role (account_id, role, updated_by) VALUES ($1, $2, $3)
		ON CONFLICT (account_id) DO UPDATE SET role = EXCLUDED.role, updated_by = EXCLUDED.updated_by, updated_at = now()`,
		account, in.Role, me.ID); err != nil {
		s.Logger.Error("office: set role", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"account_id": account, "role": in.Role})
}

// ---------------------------------------------------------------- listing

type txnMeta struct {
	Title       string `json:"title"`
	Category    string `json:"category"`
	Amount      int64  `json:"amount"`
	Description string `json:"description"`
}

func (s *Server) officeListTransactions(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	scope := r.URL.Query().Get("scope")
	status := r.URL.Query().Get("status")

	where := []string{"t.workflow_type = $1"}
	args := []interface{}{officeWorkflow}
	add := func(cond string, v interface{}) {
		args = append(args, v)
		where = append(where, strings.Replace(cond, "?", "$"+strconv.Itoa(len(args)), 1))
	}
	switch scope {
	case "inbox": // waiting for me to approve
		if me.OfficeRole != roleApprover {
			writeJSON(w, http.StatusOK, map[string]interface{}{"transactions": []interface{}{}})
			return
		}
		where = append(where, "t.status = 'VERIFIED'")
		add("t.created_by <> ?", me.ID)
	case "all":
		if !me.canSeeAll() {
			add("t.created_by = ?", me.ID)
		}
	default: // mine
		add("t.created_by = ?", me.ID)
	}
	if status != "" {
		add("t.status = ?", status)
	}

	rows, err := s.DB.Query(r.Context(), `
		SELECT t.id, t.status, t.created_by, COALESCE(u.display_name, t.created_by), t.created_at, t.updated_at,
		       COALESCE(t.office_meta, '{}'::jsonb),
		       (SELECT count(*) FROM outbox_event o WHERE o.aggregate_id = t.id AND o.status IN ('pending','failed')),
		       (SELECT count(*) FROM outbox_event o WHERE o.aggregate_id = t.id AND o.status = 'dead_letter'),
		       (SELECT count(*) FROM transaction_event e WHERE e.transaction_id = t.id AND e.fabric_tx_id IS NOT NULL)
		FROM transaction t LEFT JOIN user_identity u ON u.id = t.created_by
		WHERE `+strings.Join(where, " AND ")+`
		ORDER BY t.updated_at DESC LIMIT 200`, args...)
	if err != nil {
		s.Logger.Error("office: list", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id, st, by, byName string
		var created, updated time.Time
		var metaRaw []byte
		var queued, dead, committed int
		if err := rows.Scan(&id, &st, &by, &byName, &created, &updated, &metaRaw, &queued, &dead, &committed); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		var m txnMeta
		_ = json.Unmarshal(metaRaw, &m)
		out = append(out, map[string]interface{}{
			"id": id, "status": st, "title": m.Title, "category": m.Category, "amount": m.Amount,
			"created_by": by, "created_by_name": byName, "created_at": created, "updated_at": updated,
			"ledger": ledgerState(s.Office.FabricEnabled, queued, dead, committed),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"transactions": out})
}

// ledgerState summarises how far a transaction's events are on the ledger.
func ledgerState(enabled bool, queued, dead, committed int) map[string]interface{} {
	state := "queued"
	switch {
	case dead > 0:
		state = "failed"
	case queued == 0 && committed > 0:
		state = "recorded"
	case !enabled:
		state = "queued"
	}
	return map[string]interface{}{"enabled": enabled, "state": state, "queued": queued, "dead": dead, "committed_events": committed}
}

// ---------------------------------------------------------------- create

const maxOfficeForm = maxDocumentSize + (1 << 20)

func sha512Hex(b []byte) string { s := sha512.Sum512(b); return hex.EncodeToString(s[:]) }

func (s *Server) storeDocument(ctx context.Context, tx pgx.Tx, txnID, kind, fileName, uploadedBy string, data []byte) (string, error) {
	id := uuid.NewString()
	key := fmt.Sprintf("office/%s/%s-%s.pdf", txnID, kind, id)
	if err := s.Objects.Put(ctx, key, data, "application/pdf"); err != nil {
		return "", fmt.Errorf("store object: %w", err)
	}
	sum := sha256.Sum256(data)
	if _, err := tx.Exec(ctx, `
		INSERT INTO document_reference (id, owner_type, owner_id, storage_bucket, storage_key, sha256_hash, content_type,
		                                uploaded_by, kind, file_name, sha512_hash, size_bytes)
		VALUES ($1,'transaction_event',$2,$3,$4,$5,'application/pdf',$6,$7,$8,$9,$10)`,
		id, txnID, s.Bucket, key, "sha256:"+hex.EncodeToString(sum[:]), uploadedBy, kind, fileName, sha512Hex(data), len(data)); err != nil {
		return "", err
	}
	return id, nil
}

func cleanFileName(n string) string {
	n = strings.Map(func(r rune) rune {
		if r < 32 || r == '/' || r == '\\' || r == '"' {
			return '_'
		}
		return r
	}, n)
	if len(n) > 120 {
		n = n[len(n)-120:]
	}
	if n == "" {
		n = "dokumen.pdf"
	}
	return n
}

func (s *Server) officeCreateTransaction(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	r.Body = http.MaxBytesReader(w, r.Body, maxOfficeForm)
	if err := r.ParseMultipartForm(maxDocumentSize); err != nil {
		writeError(w, http.StatusBadRequest, "kirim multipart/form-data dengan berkas PDF (maks 32 MiB)")
		return
	}
	title := strings.TrimSpace(r.FormValue("title"))
	category := strings.TrimSpace(r.FormValue("category"))
	description := strings.TrimSpace(r.FormValue("description"))
	amount, err := strconv.ParseInt(strings.TrimSpace(r.FormValue("amount")), 10, 64)
	switch {
	case utf8.RuneCountInString(title) < 3 || utf8.RuneCountInString(title) > 200:
		writeError(w, http.StatusBadRequest, "judul 3–200 karakter")
		return
	case !officeCategories[category]:
		writeError(w, http.StatusBadRequest, "kategori tidak dikenal")
		return
	case err != nil || amount < 0 || amount > 1_000_000_000_000:
		writeError(w, http.StatusBadRequest, "nominal harus bilangan bulat rupiah ≥ 0")
		return
	case utf8.RuneCountInString(description) > 2000:
		writeError(w, http.StatusBadRequest, "keterangan maksimal 2000 karakter")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "lampiran PDF wajib diisi")
		return
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxDocumentSize+1))
	if err != nil || len(data) > maxDocumentSize {
		writeError(w, http.StatusBadRequest, "berkas terlalu besar (maks 32 MiB)")
		return
	}
	if !bytes.HasPrefix(data, []byte("%PDF-")) {
		writeError(w, http.StatusBadRequest, "lampiran harus berkas PDF")
		return
	}

	ctx := r.Context()
	txnID := "txn_" + uuid.NewString()
	meta, _ := json.Marshal(txnMeta{Title: title, Category: category, Amount: amount, Description: description})

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)

	if _, err := tx.Exec(ctx, `
		INSERT INTO transaction (id, organization_id, workflow_type, schema_version, created_by, status, office_meta)
		VALUES ($1,$2,$3,$4,$5,'DRAFT',$6)`, txnID, officeOrg, officeWorkflow, officeSchema, me.ID, meta); err != nil {
		s.Logger.Error("office: create insert", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	createArgs, _ := json.Marshal([]string{txnID, officeOrg, officeWorkflow, officeSchema, me.ID})
	if err := enqueueOutbox(ctx, tx, "transaction", txnID, "transaction", "CreateTransaction", createArgs); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	docID, err := s.storeDocument(ctx, tx, txnID, "attachment", cleanFileName(header.Filename), me.ID, data)
	if err != nil {
		s.Logger.Error("office: store attachment", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := s.appendTransactionEvent(ctx, tx, eventInput{
		TransactionID: txnID, EventType: "CREATED", SignerIdentity: me.ID,
		Payload: map[string]interface{}{
			"title": title, "category": category, "amount": amount, "description": description,
			"document_id": docID, "document_sha512": sha512Hex(data), "file_name": cleanFileName(header.Filename),
		},
	}, true); err != nil {
		s.Logger.Error("office: create event", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": txnID, "status": "DRAFT"})
}

// ---------------------------------------------------------------- detail

func (s *Server) officeGetTransaction(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	id := chi.URLParam(r, "id")
	ctx := r.Context()

	var status, createdBy, createdByName string
	var metaRaw []byte
	var created, updated time.Time
	err := s.DB.QueryRow(ctx, `
		SELECT t.status, t.created_by, COALESCE(u.display_name, t.created_by), COALESCE(t.office_meta,'{}'::jsonb), t.created_at, t.updated_at
		FROM transaction t LEFT JOIN user_identity u ON u.id = t.created_by
		WHERE t.id = $1 AND t.workflow_type = $2`, id, officeWorkflow).
		Scan(&status, &createdBy, &createdByName, &metaRaw, &created, &updated)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !me.canSeeAll() && createdBy != me.ID) {
		writeError(w, http.StatusNotFound, "transaksi tidak ditemukan") // not 403: do not reveal existence
		return
	}
	if err != nil {
		s.Logger.Error("office: detail", "line", 431, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var m txnMeta
	_ = json.Unmarshal(metaRaw, &m)

	evRows, err := s.DB.Query(ctx, `
		SELECT e.event_sequence, e.event_type, COALESCE(e.actor_id,''), COALESCE(u.display_name, e.actor_id, ''),
		       e.created_at_server, e.payload_hash, COALESCE(e.payload,'{}'::jsonb), e.fabric_tx_id, e.fabric_block_number
		FROM transaction_event e LEFT JOIN user_identity u ON u.id = e.actor_id
		WHERE e.transaction_id = $1 ORDER BY e.event_sequence`, id)
	if err != nil {
		s.Logger.Error("office: detail events", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer evRows.Close()
	events := []map[string]interface{}{}
	var ttd map[string]interface{}
	committed := 0
	for evRows.Next() {
		var seq int
		var typ, actor, actorName, hash string
		var at time.Time
		var payload []byte
		var fabTx *string
		var block *int64
		if err := evRows.Scan(&seq, &typ, &actor, &actorName, &at, &hash, &payload, &fabTx, &block); err != nil {
			s.Logger.Error("office: detail", "line", 458, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		var p map[string]interface{}
		_ = json.Unmarshal(payload, &p)
		ev := map[string]interface{}{
			"sequence": seq, "type": typ, "actor_id": actor, "actor_name": actorName, "at": at.UTC().Format(time.RFC3339),
			"payload_hash": hash, "payload": p, "recorded_on_ledger": fabTx != nil,
		}
		if fabTx != nil {
			committed++
			ev["fabric_tx_id"] = *fabTx
			ev["fabric_block_number"] = block
		}
		if pid, ok := p["ttd_public_id"].(string); ok && pid != "" {
			ttd = map[string]interface{}{"public_id": pid, "verification_url": p["verification_url"], "signed_sha512": p["signed_sha512"]}
		}
		events = append(events, ev)
	}
	evRows.Close()

	docRows, err := s.DB.Query(ctx, `
		SELECT d.id, d.kind, COALESCE(d.file_name,''), COALESCE(d.size_bytes,0), d.sha256_hash, COALESCE(d.sha512_hash,''),
		       d.created_at, COALESCE(u.display_name, d.uploaded_by)
		FROM document_reference d LEFT JOIN user_identity u ON u.id = d.uploaded_by
		WHERE d.owner_id = $1 AND d.kind IN ('attachment','signed') ORDER BY d.created_at`, id)
	if err != nil {
		s.Logger.Error("office: detail", "line", 485, "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer docRows.Close()
	docs := []map[string]interface{}{}
	for docRows.Next() {
		var did, kind, name, sha256h, sha512h, by string
		var size int64
		var at time.Time
		if err := docRows.Scan(&did, &kind, &name, &size, &sha256h, &sha512h, &at, &by); err != nil {
			s.Logger.Error("office: detail", "line", 495, "error", err)
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		docs = append(docs, map[string]interface{}{"id": did, "kind": kind, "file_name": name, "size": size,
			"sha256": sha256h, "sha512": sha512h, "created_at": at, "uploaded_by": by})
	}
	docRows.Close()

	var queued, dead int
	_ = s.DB.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status IN ('pending','failed')), count(*) FILTER (WHERE status = 'dead_letter')
		FROM outbox_event WHERE aggregate_id = $1`, id).Scan(&queued, &dead)

	writeJSON(w, http.StatusOK, map[string]interface{}{
		"transaction": map[string]interface{}{
			"id": id, "status": status, "title": m.Title, "category": m.Category, "amount": m.Amount,
			"description": m.Description, "created_by": createdBy, "created_by_name": createdByName,
			"created_at": created, "updated_at": updated,
		},
		"events": events, "documents": docs, "ttd": ttd,
		"ledger":      ledgerState(s.Office.FabricEnabled, queued, dead, committed),
		"permissions": permsFor(me, createdBy, status),
	})
}

// ---------------------------------------------------------------- actions

// lockTxn loads the transaction's state under a row lock.
func lockTxn(ctx context.Context, tx pgx.Tx, id string) (createdBy, status string, err error) {
	err = tx.QueryRow(ctx, `SELECT created_by, status FROM transaction WHERE id = $1 AND workflow_type = $2 FOR UPDATE`,
		id, officeWorkflow).Scan(&createdBy, &status)
	return
}

// officeAction runs one state-changing step: it opens a DB transaction, locks
// the request, lets check decide (returning an HTTP status + message to refuse),
// then commits whatever apply wrote.
func (s *Server) officeAction(w http.ResponseWriter, r *http.Request,
	check func(me officeIdentity, createdBy, status string) (int, string),
	apply func(ctx context.Context, tx pgx.Tx, me officeIdentity, createdBy string) (int, string)) {

	me := identityFrom(r)
	id := chi.URLParam(r, "id")
	ctx := r.Context()
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer tx.Rollback(ctx)

	createdBy, status, err := lockTxn(ctx, tx, id)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !me.canSeeAll() && createdBy != me.ID) {
		writeError(w, http.StatusNotFound, "transaksi tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if code, msg := check(me, createdBy, status); code != 0 {
		writeError(w, code, msg)
		return
	}
	if code, msg := apply(ctx, tx, me, createdBy); code != 0 {
		writeError(w, code, msg)
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"id": id, "status": "ok"})
}

func (s *Server) simpleStep(w http.ResponseWriter, r *http.Request, eventType, newStatus string, allowed func(officePerms) bool, denyMsg string) {
	id := chi.URLParam(r, "id")
	s.officeAction(w, r,
		func(me officeIdentity, createdBy, status string) (int, string) {
			if !allowed(permsFor(me, createdBy, status)) || !canTransition(status, newStatus) {
				return http.StatusConflict, denyMsg
			}
			return 0, ""
		},
		func(ctx context.Context, tx pgx.Tx, me officeIdentity, createdBy string) (int, string) {
			if _, err := s.appendTransactionEvent(ctx, tx, eventInput{
				TransactionID: id, EventType: eventType, SignerIdentity: me.ID,
				// The event type and transition are part of the signed payload:
				// without them two different steps by one actor hash identically
				// (SUBMITTED and COMPLETED did, on the ledger).
				Payload: map[string]interface{}{
					"actor": me.ID, "event_type": eventType, "new_status": newStatus,
					"at": time.Now().UTC().Format(time.RFC3339Nano),
				},
				NewStatus: newStatus,
			}, true); err != nil {
				s.Logger.Error("office: step "+eventType, "error", err)
				return http.StatusInternalServerError, "internal error"
			}
			return 0, ""
		})
}

func (s *Server) officeSubmit(w http.ResponseWriter, r *http.Request) {
	s.simpleStep(w, r, "SUBMITTED", "VERIFIED", func(p officePerms) bool { return p.CanSubmit },
		"hanya pembuat yang dapat mengirim transaksi berstatus DRAFT")
}

func (s *Server) officeComplete(w http.ResponseWriter, r *http.Request) {
	s.simpleStep(w, r, "COMPLETED", "COMMITTED", func(p officePerms) bool { return p.CanComplete },
		"transaksi hanya dapat diselesaikan oleh pembuat/admin setelah disetujui")
}

func (s *Server) officeCancel(w http.ResponseWriter, r *http.Request) {
	s.simpleStep(w, r, "CANCELLED", "CANCELLED", func(p officePerms) bool { return p.CanCancel },
		"hanya pembuat yang dapat membatalkan DRAFT/menunggu persetujuan")
}

type decisionRequest struct {
	Decision    string `json:"decision"`
	TTDPublicID string `json:"ttd_public_id"`
	Reason      string `json:"reason"`
}

// officeDecision is the approval step. "approve" requires a TTD signature that
// the TTD server confirms was made by THIS approver over THIS request's PDF.
func (s *Server) officeDecision(w http.ResponseWriter, r *http.Request) {
	var in decisionRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}
	id := chi.URLParam(r, "id")
	approve := in.Decision == "approve"
	if !approve && in.Decision != "reject" {
		writeError(w, http.StatusBadRequest, "decision harus approve atau reject")
		return
	}
	if !approve && utf8.RuneCountInString(strings.TrimSpace(in.Reason)) < 3 {
		writeError(w, http.StatusBadRequest, "alasan penolakan wajib diisi")
		return
	}
	if approve && in.TTDPublicID == "" {
		writeError(w, http.StatusBadRequest, "persetujuan harus disertai tanda tangan TTD (ttd_public_id)")
		return
	}

	s.officeAction(w, r,
		func(me officeIdentity, createdBy, status string) (int, string) {
			p := permsFor(me, createdBy, status)
			if !p.CanApprove {
				if me.ID == createdBy {
					return http.StatusForbidden, "pembuat tidak boleh menyetujui/menolak pengajuannya sendiri"
				}
				if me.OfficeRole != roleApprover {
					return http.StatusForbidden, "hanya penyetuju yang dapat memutuskan"
				}
				return http.StatusConflict, "transaksi tidak sedang menunggu persetujuan"
			}
			return 0, ""
		},
		func(ctx context.Context, tx pgx.Tx, me officeIdentity, createdBy string) (int, string) {
			// The event being decided on is the submission.
			var submittedSeq int
			var submittedRowID string
			if err := tx.QueryRow(ctx, `
				SELECT event_sequence, id FROM transaction_event
				WHERE transaction_id = $1 AND event_type = 'SUBMITTED' ORDER BY event_sequence DESC LIMIT 1`, id).
				Scan(&submittedSeq, &submittedRowID); err != nil {
				return http.StatusConflict, "pengajuan belum dikirim"
			}

			payload := map[string]interface{}{"approver_id": me.ID, "policy_version": officePolicy}
			eventType, newStatus := "REJECTED", "REJECTED"
			if approve {
				code, msg, extra := s.verifyTTDApproval(ctx, tx, id, me, in.TTDPublicID)
				if code != 0 {
					return code, msg
				}
				for k, v := range extra {
					payload[k] = v
				}
				eventType, newStatus = "APPROVED_SIGNED", "ENDORSED"
			} else {
				payload["reason"] = strings.TrimSpace(in.Reason)
			}
			if !canTransition("VERIFIED", newStatus) {
				return http.StatusConflict, "transisi status tidak diizinkan"
			}
			if _, err := s.appendTransactionEvent(ctx, tx, eventInput{
				TransactionID: id, EventType: eventType, SignerIdentity: me.ID, Payload: payload, NewStatus: newStatus,
			}, true); err != nil {
				var pg *pgconn.PgError
				if errors.As(err, &pg) && pg.Code == "23505" {
					return http.StatusConflict, "tanda tangan TTD ini sudah dipakai untuk persetujuan lain"
				}
				s.Logger.Error("office: decision event", "error", err)
				return http.StatusInternalServerError, "internal error"
			}
			decision := in.Decision
			if _, err := tx.Exec(ctx, `
				INSERT INTO approval (id, transaction_id, event_id, approver_id, decision, policy_version)
				VALUES ($1,$2,$3,$4,$5,$6)`, uuid.NewString(), id, submittedRowID, me.ID, decision, officePolicy); err != nil {
				s.Logger.Error("office: approval row", "error", err)
				return http.StatusInternalServerError, "internal error"
			}
			// An approval is also recorded on-chain (Approve). A rejection is not:
			// the chaincode's Approve(reject) would itself move the status to
			// REJECTED, colliding with the REJECTED event already queued above.
			if approve {
				args, _ := json.Marshal([]string{id, strconv.Itoa(submittedSeq), me.ID, decision, officePolicy})
				if err := enqueueOutbox(ctx, tx, "transaction", id, "transaction", "Approve", args); err != nil {
					return http.StatusInternalServerError, "internal error"
				}
			}
			return 0, ""
		})
}

// verifyTTDApproval checks the claimed TTD signature against the TTD server —
// the source of truth — and stores the signed PDF next to the request.
func (s *Server) verifyTTDApproval(ctx context.Context, tx pgx.Tx, txnID string, me officeIdentity, publicID string) (int, string, map[string]interface{}) {
	if s.TTD == nil {
		return http.StatusServiceUnavailable, "layanan TTD tidak dikonfigurasi", nil
	}
	rec, err := s.TTD.Record(ctx, publicID)
	if err != nil {
		return http.StatusBadRequest, "tanda tangan TTD tidak ditemukan atau tidak dapat diverifikasi", nil
	}
	if rec.AccountID != me.ID {
		return http.StatusForbidden, "tanda tangan TTD itu bukan milik Anda", nil
	}
	if rec.VerificationStatus != "accepted" {
		return http.StatusConflict, "tanda tangan TTD belum diverifikasi server (status: " + rec.VerificationStatus + ")", nil
	}
	var attachSHA512 string
	if err := tx.QueryRow(ctx, `
		SELECT COALESCE(sha512_hash,'') FROM document_reference
		WHERE owner_id = $1 AND kind = 'attachment' ORDER BY created_at LIMIT 1`, txnID).Scan(&attachSHA512); err != nil || attachSHA512 == "" {
		return http.StatusConflict, "lampiran asli tidak ditemukan", nil
	}
	if !strings.EqualFold(rec.OriginalSHA512, attachSHA512) {
		return http.StatusConflict, "tanda tangan TTD itu dibuat atas dokumen lain, bukan lampiran transaksi ini", nil
	}
	signed, err := s.TTD.SignedPDF(ctx, publicID)
	if err != nil {
		return http.StatusBadGateway, "gagal mengambil PDF bertanda tangan dari server TTD", nil
	}
	if !strings.EqualFold(sha512Hex(signed), rec.SignedSHA512) {
		return http.StatusConflict, "PDF bertanda tangan tidak cocok dengan catatan server TTD", nil
	}
	docID, err := s.storeDocument(ctx, tx, txnID, "signed", "bertandatangan-"+publicID+".pdf", me.ID, signed)
	if err != nil {
		s.Logger.Error("office: store signed document", "error", err)
		return http.StatusInternalServerError, "internal error", nil
	}
	return 0, "", map[string]interface{}{
		"ttd_public_id": publicID, "verification_url": rec.VerificationURL,
		"original_sha512": rec.OriginalSHA512, "signed_sha512": rec.SignedSHA512, "signed_document_id": docID,
	}
}

// ---------------------------------------------------------------- download

func (s *Server) officeDownload(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	var key, name, txnID, createdBy string
	err := s.DB.QueryRow(r.Context(), `
		SELECT d.storage_key, COALESCE(d.file_name,'dokumen.pdf'), t.id, t.created_by
		FROM document_reference d JOIN transaction t ON t.id = d.owner_id
		WHERE d.id = $1 AND d.kind IN ('attachment','signed') AND t.workflow_type = $2`, chi.URLParam(r, "id"), officeWorkflow).
		Scan(&key, &name, &txnID, &createdBy)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !me.canSeeAll() && createdBy != me.ID) {
		writeError(w, http.StatusNotFound, "dokumen tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	data, err := s.Objects.Get(r.Context(), key)
	if err != nil {
		s.Logger.Error("office: download", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	w.Header().Set("Content-Type", "application/pdf")
	w.Header().Set("Content-Disposition", `attachment; filename="`+cleanFileName(name)+`"`)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Cache-Control", "private, no-store")
	_, _ = w.Write(data)
}
