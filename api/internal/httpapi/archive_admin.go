package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
)

// Central-admin endpoints: the archive console. Senders never reach these (the
// decision was: only the central admin sees what was sent; a sender only gets the
// receipt of their own upload).
func (s *Server) archiveAdminRoutes(r chi.Router) {
	r.Get("/stats", s.adminOnly(s.archiveStats))
	r.Get("/items", s.adminOnly(s.archiveList))
	r.Get("/items/{id}", s.adminOnly(s.archiveDetail))
	r.Post("/items/{id}/verify", s.adminOnly(s.archiveVerify))
	r.Get("/items/{id}/download", s.adminOnly(s.archiveDownload))
	r.Post("/items/{id}/ticket", s.adminOnly(s.archiveTicket))
	r.Get("/offices", s.adminOnly(s.archiveOffices))
	r.Post("/offices", s.adminOnly(s.archiveCreateOffice))
	r.Get("/members", s.adminOnly(s.archiveMembers))
	r.Put("/members/{account_id}", s.adminOnly(s.archiveAssignMember))
}

func (s *Server) adminOnly(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !identityFrom(r).isAdmin() {
			writeError(w, http.StatusForbidden, "hanya admin pusat")
			return
		}
		h(w, r)
	}
}

func (s *Server) logAccess(ctx context.Context, r *http.Request, itemID, action string) {
	_, _ = s.DB.Exec(ctx, `INSERT INTO archive_access (item_id, admin_id, action, client_ip) VALUES ($1,$2,$3,$4)`,
		itemID, identityFrom(r).ID, action, clientIP(r))
}

// ---------------------------------------------------------------- list / detail

func (s *Server) archiveList(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	where := []string{"true"}
	var args []interface{}
	add := func(cond string, v interface{}) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", "$"+strconv.Itoa(len(args))))
	}
	if v := q.Get("org"); v != "" {
		add("a.organization_id = ?", v)
	}
	if v := q.Get("sender"); v != "" {
		add("a.sender_id = ?", v)
	}
	if v := strings.TrimSpace(q.Get("q")); v != "" {
		like := "%" + strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(v) + "%"
		args = append(args, like, strings.ToLower(v))
		li, ex := len(args)-1, len(args)
		where = append(where, fmt.Sprintf("(a.file_name ILIKE $%d OR u.display_name ILIKE $%d OR a.description ILIKE $%d OR a.sha256 ILIKE $%d OR a.receipt_id = $%d)", li, li, li, li, ex))
	}
	if v := q.Get("from"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			add("a.received_at >= ?", t)
		}
	}
	if v := q.Get("to"); v != "" {
		if t, err := time.Parse("2006-01-02", v); err == nil {
			add("a.received_at < ?", t.AddDate(0, 0, 1))
		}
	}
	limit, _ := strconv.Atoi(q.Get("limit"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	offset, _ := strconv.Atoi(q.Get("offset"))
	if offset < 0 {
		offset = 0
	}
	cond := strings.Join(where, " AND ")

	ctx := r.Context()
	var total int64
	if err := s.DB.QueryRow(ctx, `SELECT count(*) FROM archive_item a JOIN user_identity u ON u.id = a.sender_id WHERE `+cond, args...).Scan(&total); err != nil {
		s.Logger.Error("archive list count", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	rows, err := s.DB.Query(ctx, `
		SELECT a.id, a.receipt_id, a.transaction_id, a.organization_id, o.name, a.sender_id, u.display_name, COALESCE(u.email,''),
		       a.file_name, a.media_type, a.size_bytes, a.sha256, a.description, a.received_at,
		       (SELECT count(*) FROM outbox_event x WHERE x.aggregate_id = a.transaction_id AND x.status IN ('pending','failed')),
		       (SELECT count(*) FROM outbox_event x WHERE x.aggregate_id = a.transaction_id AND x.status = 'dead_letter'),
		       (SELECT count(*) FROM transaction_event e WHERE e.transaction_id = a.transaction_id AND e.fabric_tx_id IS NOT NULL)
		FROM archive_item a
		JOIN organization o ON o.id = a.organization_id
		JOIN user_identity u ON u.id = a.sender_id
		WHERE `+cond+` ORDER BY a.received_at DESC LIMIT `+strconv.Itoa(limit)+` OFFSET `+strconv.Itoa(offset), args...)
	if err != nil {
		s.Logger.Error("archive list", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	items := []map[string]interface{}{}
	for rows.Next() {
		var id, rid, tid, oid, oname, sid, sname, semail, fname, media, sha, desc string
		var size int64
		var at time.Time
		var queued, dead, committed int
		if err := rows.Scan(&id, &rid, &tid, &oid, &oname, &sid, &sname, &semail, &fname, &media, &size, &sha, &desc, &at, &queued, &dead, &committed); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		items = append(items, map[string]interface{}{
			"id": id, "receipt_id": rid, "transaction_id": tid, "organization_id": oid, "organization_name": oname,
			"sender_id": sid, "sender_name": sname, "sender_email": semail, "file_name": fname, "media_type": media,
			"size_bytes": size, "sha256": sha, "description": desc, "received_at": at,
			"ledger": ledgerState(s.Office.FabricEnabled, queued, dead, committed),
		})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": items, "total": total, "limit": limit, "offset": offset})
}

func (s *Server) archiveDetail(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	var (
		rid, tid, oid, oname, sid, sname, semail, fname, media, sha256h, sha512h, desc, ip, ua, mhash string
		size                                                                                          int64
		at                                                                                            time.Time
		manifest, receipt                                                                             json.RawMessage
	)
	err := s.DB.QueryRow(ctx, `
		SELECT a.receipt_id, a.transaction_id, a.organization_id, o.name, a.sender_id, u.display_name, COALESCE(u.email,''),
		       a.file_name, a.media_type, a.size_bytes, a.sha256, a.sha512, a.description, a.client_ip, a.user_agent,
		       a.manifest_hash, a.received_at, a.manifest, a.receipt
		FROM archive_item a JOIN organization o ON o.id = a.organization_id JOIN user_identity u ON u.id = a.sender_id
		WHERE a.id = $1`, id).
		Scan(&rid, &tid, &oid, &oname, &sid, &sname, &semail, &fname, &media, &size, &sha256h, &sha512h, &desc, &ip, &ua, &mhash, &at, &manifest, &receipt)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "kiriman tidak ditemukan")
		return
	}
	if err != nil {
		s.Logger.Error("archive detail", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	evRows, err := s.DB.Query(ctx, `
		SELECT e.event_sequence, e.event_type, COALESCE(u.display_name, e.actor_id, ''), e.created_at_server, e.payload_hash,
		       COALESCE(e.previous_event_hash,''), e.fabric_tx_id, e.fabric_block_number
		FROM transaction_event e LEFT JOIN user_identity u ON u.id = e.actor_id
		WHERE e.transaction_id = $1 ORDER BY e.event_sequence`, tid)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer evRows.Close()
	events := []map[string]interface{}{}
	committed := 0
	for evRows.Next() {
		var seq int
		var typ, actor, hash, prev string
		var at2 time.Time
		var fab *string
		var blk *int64
		if err := evRows.Scan(&seq, &typ, &actor, &at2, &hash, &prev, &fab, &blk); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		ev := map[string]interface{}{"sequence": seq, "type": typ, "actor_name": actor, "at": at2, "payload_hash": hash,
			"previous_event_hash": prev, "recorded_on_ledger": fab != nil}
		if fab != nil {
			committed++
			ev["fabric_tx_id"], ev["fabric_block_number"] = *fab, blk
		}
		events = append(events, ev)
	}
	evRows.Close()
	s.logAccess(ctx, r, id, "view")
	var mf, rc interface{}
	_ = json.Unmarshal(manifest, &mf)
	_ = json.Unmarshal(receipt, &rc)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"id": id, "receipt_id": rid, "transaction_id": tid, "organization_id": oid, "organization_name": oname,
		"sender_id": sid, "sender_name": sname, "sender_email": semail, "file_name": fname, "media_type": media,
		"size_bytes": size, "sha256": sha256h, "sha512": sha512h, "description": desc, "client_ip": ip, "user_agent": ua,
		"manifest_hash": mhash, "received_at": at, "manifest": mf, "receipt": rc, "events": events,
		"ledger": s.ledgerFor(ctx, tid),
	})
}

func (s *Server) archiveVerify(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	res, err := s.verifyItem(r.Context(), id, r.URL.Query().Get("deep") == "1")
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "kiriman tidak ditemukan")
		return
	}
	if err != nil {
		s.Logger.Error("archive verify", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	s.logAccess(r.Context(), r, id, "verify")
	writeJSON(w, http.StatusOK, res)
}

// archiveDownload streams the stored bytes exactly as received. The file is
// untrusted content: it is always an attachment, never sniffed or rendered.
func (s *Server) archiveDownload(w http.ResponseWriter, r *http.Request) {
	s.streamItem(w, r, chi.URLParam(r, "id"), identityFrom(r).ID)
}

func (s *Server) streamItem(w http.ResponseWriter, r *http.Request, id, adminID string) {
	var key, name string
	var size int64
	err := s.DB.QueryRow(r.Context(), `SELECT storage_key, file_name, size_bytes FROM archive_item WHERE id = $1`, id).Scan(&key, &name, &size)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "kiriman tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	rc, err := s.Objects.GetStream(r.Context(), key)
	if err != nil {
		s.Logger.Error("archive download", "error", err)
		writeError(w, http.StatusInternalServerError, "berkas tidak dapat dibaca dari penyimpanan")
		return
	}
	defer rc.Close()
	_, _ = s.DB.Exec(r.Context(), `INSERT INTO archive_access (item_id, admin_id, action, client_ip) VALUES ($1,$2,'download',$3)`, id, adminID, clientIP(r))
	h := w.Header()
	h.Set("Content-Type", "application/octet-stream")
	h.Set("Content-Disposition", `attachment; filename="`+asciiName(name)+`"; filename*=UTF-8''`+percentEncode(name))
	h.Set("Content-Length", strconv.FormatInt(size, 10))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Content-Security-Policy", "sandbox; default-src 'none'")
	h.Set("Cache-Control", "private, no-store")
	_, _ = io.Copy(w, rc)
}

// archiveTicket issues a one-time link (valid two minutes) for a native browser
// download of one item.
func (s *Server) archiveTicket(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var one bool
	if err := s.DB.QueryRow(r.Context(), `SELECT true FROM archive_item WHERE id = $1`, id).Scan(&one); err != nil {
		writeError(w, http.StatusNotFound, "kiriman tidak ditemukan")
		return
	}
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	token := hex.EncodeToString(raw)
	sum := sha256.Sum256([]byte(token))
	if _, err := s.DB.Exec(r.Context(), `INSERT INTO archive_ticket (token_hash, item_id, admin_id, expires_at) VALUES ($1,$2,$3, now() + interval '2 minutes')`,
		hex.EncodeToString(sum[:]), id, identityFrom(r).ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"url": "/api/v1/public/dl/" + token, "expires_in": 120})
}

// publicDownload redeems a ticket exactly once.
func (s *Server) publicDownload(w http.ResponseWriter, r *http.Request) {
	sum := sha256.Sum256([]byte(chi.URLParam(r, "token")))
	var itemID, adminID string
	err := s.DB.QueryRow(r.Context(), `
		UPDATE archive_ticket SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now() RETURNING item_id, admin_id`, hex.EncodeToString(sum[:])).Scan(&itemID, &adminID)
	if err != nil {
		writeError(w, http.StatusNotFound, "tautan unduhan tidak berlaku (kedaluwarsa atau sudah dipakai)")
		return
	}
	s.streamItem(w, r, itemID, adminID)
}

func asciiName(n string) string {
	return strings.Map(func(r rune) rune {
		if r < 32 || r > 126 || r == '"' || r == '\\' {
			return '_'
		}
		return r
	}, n)
}

func percentEncode(s string) string {
	const hexd = "0123456789ABCDEF"
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.IndexByte("-._~", c) >= 0 {
			b.WriteByte(c)
		} else {
			b.WriteByte('%')
			b.WriteByte(hexd[c>>4])
			b.WriteByte(hexd[c&15])
		}
	}
	return b.String()
}

// ---------------------------------------------------------------- stats / offices / members

func (s *Server) archiveStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var total, bytes, today int64
	_ = s.DB.QueryRow(ctx, `SELECT count(*), COALESCE(sum(size_bytes),0), count(*) FILTER (WHERE received_at > now() - interval '24 hours') FROM archive_item`).Scan(&total, &bytes, &today)
	writeJSON(w, http.StatusOK, map[string]interface{}{"items": total, "bytes": bytes, "last_24h": today})
}

func (s *Server) archiveOffices(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(r.Context(), `
		SELECT o.id, o.name,
		       (SELECT count(*) FROM office_member m WHERE m.organization_id = o.id),
		       (SELECT count(*) FROM archive_item a WHERE a.organization_id = o.id),
		       (SELECT COALESCE(sum(size_bytes),0) FROM archive_item a WHERE a.organization_id = o.id)
		FROM organization o WHERE o.id NOT IN ($1, 'org-a') ORDER BY o.name`, systemOrgID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	out := []map[string]interface{}{}
	for rows.Next() {
		var id, name string
		var members, items, bytes int64
		if err := rows.Scan(&id, &name, &members, &items, &bytes); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		out = append(out, map[string]interface{}{"id": id, "name": name, "members": members, "items": items, "bytes": bytes})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"offices": out})
}

var slugRe = regexp.MustCompile(`[^a-z0-9]+`)

func (s *Server) archiveCreateOffice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}
	name := strings.TrimSpace(in.Name)
	if n := utf8.RuneCountInString(name); n < 2 || n > 120 {
		writeError(w, http.StatusBadRequest, "nama kantor 2–120 karakter")
		return
	}
	id := strings.Trim(slugRe.ReplaceAllString(strings.ToLower(name), "-"), "-")
	if id == "" || id == systemOrgID || id == "org-a" {
		writeError(w, http.StatusBadRequest, "nama kantor tidak valid")
		return
	}
	if len(id) > 60 {
		id = id[:60]
	}
	tag, err := s.DB.Exec(r.Context(), `INSERT INTO organization (id, name, msp_id) VALUES ($1,$2,'Org1MSP') ON CONFLICT (id) DO NOTHING`, id, name)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if tag.RowsAffected() == 0 {
		writeError(w, http.StatusConflict, "kantor dengan nama itu sudah ada")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": id, "name": name})
}

func (s *Server) archiveMembers(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(r.Context(), `
		SELECT u.id, COALESCE(u.email,''), u.display_name, COALESCE(m.organization_id,''), COALESCE(o.name,'')
		FROM user_identity u
		LEFT JOIN office_member m ON m.account_id = u.id
		LEFT JOIN organization o ON o.id = m.organization_id
		WHERE u.id NOT IN ('requester-1','approver-1','approver-2','warehouse-1','auditor-1', $1)
		ORDER BY u.display_name`, systemArchiveID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer rows.Close()
	out := []map[string]string{}
	for rows.Next() {
		var id, email, name, oid, oname string
		if err := rows.Scan(&id, &email, &name, &oid, &oname); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		out = append(out, map[string]string{"account_id": id, "email": email, "name": name, "organization_id": oid, "organization_name": oname})
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"members": out})
}

// archiveAssignMember puts an account in an office ("" removes it). The account
// may not have opened the app yet, so its identity row is provisioned here.
func (s *Server) archiveAssignMember(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	var in struct {
		OrganizationID string `json:"organization_id"`
		Email          string `json:"email"`
		Name           string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}
	account := chi.URLParam(r, "account_id")
	if account == "" || len(account) > 100 || account == systemArchiveID {
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
	org := in.OrganizationID
	if org == "" {
		if _, err := tx.Exec(ctx, `DELETE FROM office_member WHERE account_id = $1`, account); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		if err := tx.Commit(ctx); err != nil {
			writeError(w, http.StatusInternalServerError, "internal error")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"account_id": account, "organization_id": ""})
		return
	}
	var exists bool
	if err := tx.QueryRow(ctx, `SELECT true FROM organization WHERE id = $1 AND id <> $2`, org, systemOrgID).Scan(&exists); err != nil {
		writeError(w, http.StatusBadRequest, "kantor tidak ditemukan")
		return
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO user_identity (id, organization_id, display_name, role, email) VALUES ($1,$2,$3,'requester',NULLIF($4,''))
		ON CONFLICT (id) DO UPDATE SET organization_id = EXCLUDED.organization_id`, account, org, name, in.Email); err != nil {
		s.Logger.Error("archive: assign identity", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO office_member (account_id, organization_id, assigned_by) VALUES ($1,$2,$3)
		ON CONFLICT (account_id) DO UPDATE SET organization_id = EXCLUDED.organization_id, assigned_by = EXCLUDED.assigned_by, assigned_at = now()`,
		account, org, me.ID); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if err := tx.Commit(ctx); err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"account_id": account, "organization_id": org})
}

// ---------------------------------------------------------------- public receipt

// proxyOnly guards routes that are public to the world but must only be reached
// through the TTD server (so it can rate-limit and terminate TLS in one place).
func (s *Server) proxyOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if s.Office == nil || subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Office-Secret")), []byte(s.Office.ProxySecret)) != 1 {
			writeError(w, http.StatusUnauthorized, "unauthorized")
			return
		}
		next(w, r)
	}
}

// publicReceipt lets anyone holding a receipt id check that it is genuine. It
// shows what the receipt itself says (hashes, time, office, who signed) and the
// live verification result — never the file, the sender's e-mail, IP or notes.
func (s *Server) publicReceipt(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	var itemID, tid string
	var oname, sname, fname, sha256h, sha512h, mhash string
	var size int64
	var at time.Time
	err := s.DB.QueryRow(ctx, `
		SELECT a.id, a.transaction_id, o.name, u.display_name, a.file_name, a.size_bytes, a.sha256, a.sha512, a.manifest_hash, a.received_at
		FROM archive_item a JOIN organization o ON o.id = a.organization_id JOIN user_identity u ON u.id = a.sender_id
		WHERE a.receipt_id = $1`, chi.URLParam(r, "receipt_id")).Scan(&itemID, &tid, &oname, &sname, &fname, &size, &sha256h, &sha512h, &mhash, &at)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "bukti tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	ver, err := s.verifyItem(ctx, itemID, false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	var serverName string
	if s.Archive != nil {
		serverName = s.Archive.ServerName
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"receipt_id": chi.URLParam(r, "receipt_id"), "server_name": serverName, "organization_name": oname, "sender_name": sname,
		"file_name": fname, "size_bytes": size, "sha256": sha256h, "sha512": sha512h, "manifest_hash": mhash,
		"received_at": at, "verification": ver, "ledger": s.ledgerFor(ctx, tid),
	})
}
