package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base32"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"

	"ledger/crypto"
)

// The archive app (docs/adr/0004-archive-server-side-signing.md).
//
// A sender uploads any file, of any size, in resumable chunks. When the upload
// completes the SERVER, automatically:
//
//  1. hashes the bytes (SHA-256 + SHA-512) and requires the browser's SHA-256 to
//     agree (end-to-end integrity of the transfer);
//  2. stores the file in object storage and reads it back to prove what was stored;
//  3. builds a manifest (who, which office, what file, hashes, when, from where) and
//     signs it with the SENDER's hybrid key (Ed25519 + ML-DSA-65) — the keys are held
//     server-side, so this is "the server, having authenticated the sender, signs for
//     them", not a signature only the sender could make;
//  4. records three hash-chained events (UPLOAD_RECEIVED signed by the sender,
//     INTEGRITY_VERIFIED and ARCHIVED signed by the system identity) through the
//     usual outbox to the Fabric ledger;
//  5. issues a receipt, itself signed by the server.
const (
	archiveWorkflow = "arsip-kiriman"
	archiveSchema   = "archive.v1"
	systemArchiveID = "system-archive"
	systemOrgID     = "pusat"

	archiveChunkSize    = 8 << 20  // what the browser is told to send per request
	archiveMaxChunk     = 64 << 20 // hard cap per PATCH
	archiveDefaultMax   = 20 << 30 // default per-file ceiling (ARCHIVE_MAX_BYTES)
	archiveMaxOpenUpl   = 5        // open (unfinished) uploads per sender
	archiveSessionTTL   = 48 * time.Hour
	archiveDiskReserved = 256 << 20
)

// ArchiveConfig enables the archive routes.
type ArchiveConfig struct {
	TempDir    string // scratch space for in-progress uploads
	MaxBytes   int64  // per-file ceiling; 0 = 20 GiB
	ServerName string // shown to users so they can confirm the server they are sending to
}

func (c *ArchiveConfig) maxBytes() int64 {
	if c.MaxBytes > 0 {
		return c.MaxBytes
	}
	return archiveDefaultMax
}

// uploadRT is the in-memory side of one upload: a lock (chunks of one upload are
// serialized) and the running hashes of the bytes received so far.
type uploadRT struct {
	mu   sync.Mutex
	n    int64
	h256 hash.Hash
	h512 hash.Hash
}

type archiveRuntime struct {
	mu      sync.Mutex
	uploads map[string]*uploadRT
}

func (s *Server) uploadRT(id string) *uploadRT {
	s.arch.mu.Lock()
	defer s.arch.mu.Unlock()
	if s.arch.uploads == nil {
		s.arch.uploads = map[string]*uploadRT{}
	}
	rt := s.arch.uploads[id]
	if rt == nil {
		rt = &uploadRT{}
		s.arch.uploads[id] = rt
	}
	return rt
}

func (s *Server) dropUploadRT(id string) {
	s.arch.mu.Lock()
	delete(s.arch.uploads, id)
	s.arch.mu.Unlock()
}

// InitArchive makes sure the system office ("Pusat") and the system identity that
// countersigns every archived item exist. Idempotent; call once at startup.
func (s *Server) InitArchive(ctx context.Context) error {
	if s.Archive == nil {
		return nil
	}
	if err := os.MkdirAll(s.Archive.TempDir, 0o700); err != nil {
		return fmt.Errorf("archive: temp dir: %w", err)
	}
	if _, err := s.DB.Exec(ctx, `INSERT INTO organization (id, name, msp_id) VALUES ($1, 'Pusat', 'Org1MSP') ON CONFLICT (id) DO NOTHING`, systemOrgID); err != nil {
		return err
	}
	if _, err := s.DB.Exec(ctx, `
		INSERT INTO user_identity (id, organization_id, display_name, role) VALUES ($1, $2, 'Sistem Arsip', 'app_admin')
		ON CONFLICT (id) DO NOTHING`, systemArchiveID, systemOrgID); err != nil {
		return err
	}
	_, err := s.Keystore.SigningIdentity(ctx, systemArchiveID) // creates + mirrors its keys
	return err
}

// RunArchiveJanitor drops abandoned uploads (and their scratch files) until ctx ends.
func (s *Server) RunArchiveJanitor(ctx context.Context, every time.Duration) {
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			rows, err := s.DB.Query(ctx, `
				UPDATE archive_upload SET status = 'aborted'
				WHERE status = 'open' AND updated_at < now() - $1::interval RETURNING id, temp_path`,
				fmt.Sprintf("%d seconds", int(archiveSessionTTL.Seconds())))
			if err != nil {
				s.Logger.Warn("archive janitor", "error", err)
				continue
			}
			for rows.Next() {
				var id, p string
				if rows.Scan(&id, &p) == nil {
					_ = os.Remove(p)
					s.dropUploadRT(id)
				}
			}
			rows.Close()
		}
	}
}

func (s *Server) archiveRoutes(r chi.Router) {
	r.Get("/config", s.archiveConfig)
	r.Post("/uploads", s.archiveCreateUpload)
	r.Get("/uploads/{id}", s.archiveUploadStatus)
	r.Patch("/uploads/{id}", s.archiveUploadChunk)
	r.Post("/uploads/{id}/complete", s.archiveComplete)
	r.Delete("/uploads/{id}", s.archiveAbort)
	r.Get("/receipts/{receipt_id}", s.archiveReceipt)
	s.archiveAdminRoutes(r)
}

func newReceiptID() string {
	b := make([]byte, 16) // 128 bits: unguessable, the id is the capability to view a receipt
	_, _ = rand.Read(b)
	return "rcp_" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b))
}

func clientIP(r *http.Request) string {
	// Only trusted because officeAuth already required the proxy secret: the TTD
	// server resets X-Forwarded-For to the real peer address before forwarding.
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func shortText(s string, max int) string {
	if utf8.RuneCountInString(s) <= max {
		return s
	}
	return string([]rune(s)[:max])
}

// ---------------------------------------------------------------- config

func (s *Server) archiveConfig(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"server_name": s.Archive.ServerName, "chunk_size": archiveChunkSize, "max_bytes": s.Archive.maxBytes(),
		"fabric_enabled": s.Office.FabricEnabled,
		"me": map[string]interface{}{
			"id": me.ID, "name": me.Name, "email": me.Email, "is_admin": me.isAdmin(),
			"organization_id": me.OrgID, "organization_name": me.OrgName,
		},
	})
}

// ---------------------------------------------------------------- upload session

type uploadRow struct {
	ID, SenderID, OrgID, FileName, MediaType, Description, TempPath, ClientIP, UserAgent, Status string
	Size, Received                                                                               int64
}

func (s *Server) loadUpload(ctx context.Context, id, sender string) (uploadRow, error) {
	var u uploadRow
	err := s.DB.QueryRow(ctx, `
		SELECT id, sender_id, organization_id, file_name, media_type, description, temp_path, client_ip, user_agent,
		       status, size_bytes, received_bytes
		FROM archive_upload WHERE id = $1 AND sender_id = $2`, id, sender).
		Scan(&u.ID, &u.SenderID, &u.OrgID, &u.FileName, &u.MediaType, &u.Description, &u.TempPath, &u.ClientIP, &u.UserAgent,
			&u.Status, &u.Size, &u.Received)
	return u, err
}

func cleanArchiveName(n string) string {
	n = strings.ReplaceAll(n, "\\", "/")
	if i := strings.LastIndex(n, "/"); i >= 0 {
		n = n[i+1:]
	}
	n = strings.Map(func(r rune) rune {
		if r < 32 || r == 127 || r == '"' {
			return '_'
		}
		return r
	}, n)
	n = strings.TrimSpace(n)
	if utf8.RuneCountInString(n) > 200 {
		rs := []rune(n)
		n = string(rs[len(rs)-200:])
	}
	if n == "" || n == "." || n == ".." {
		n = "berkas"
	}
	return n
}

func (s *Server) archiveCreateUpload(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	if me.OrgID == "" {
		writeError(w, http.StatusForbidden, "akun Anda belum ditetapkan ke sebuah kantor. Hubungi admin pusat.")
		return
	}
	var in struct {
		FileName    string `json:"file_name"`
		Size        int64  `json:"size"`
		MediaType   string `json:"media_type"`
		Description string `json:"description"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&in); err != nil {
		writeError(w, http.StatusBadRequest, "JSON tidak valid")
		return
	}
	if in.Size < 0 {
		writeError(w, http.StatusBadRequest, "ukuran tidak valid")
		return
	}
	if in.Size > s.Archive.maxBytes() {
		writeError(w, http.StatusRequestEntityTooLarge, "berkas melebihi batas server ("+strconv.FormatInt(s.Archive.maxBytes(), 10)+" byte)")
		return
	}
	if utf8.RuneCountInString(in.Description) > 2000 {
		writeError(w, http.StatusBadRequest, "keterangan maksimal 2000 karakter")
		return
	}
	if free, ok := freeDiskBytes(s.Archive.TempDir); ok && uint64(in.Size)+archiveDiskReserved > free {
		writeError(w, http.StatusInsufficientStorage, "ruang penyimpanan server tidak cukup untuk berkas ini")
		return
	}
	ctx := r.Context()
	var open int
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM archive_upload WHERE sender_id = $1 AND status = 'open'`, me.ID).Scan(&open)
	if open >= archiveMaxOpenUpl {
		writeError(w, http.StatusTooManyRequests, "terlalu banyak unggahan yang belum selesai; selesaikan atau batalkan dulu")
		return
	}

	id := "upl_" + uuid.NewString()
	tmp := filepath.Join(s.Archive.TempDir, id+".part")
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		s.Logger.Error("archive: temp file", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	f.Close()
	media := strings.TrimSpace(in.MediaType)
	if media == "" || len(media) > 200 {
		media = "application/octet-stream"
	}
	if _, err := s.DB.Exec(ctx, `
		INSERT INTO archive_upload (id, sender_id, organization_id, file_name, media_type, size_bytes, description, temp_path, client_ip, user_agent)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		id, me.ID, me.OrgID, cleanArchiveName(in.FileName), media, in.Size, strings.TrimSpace(in.Description), tmp,
		clientIP(r), shortText(r.UserAgent(), 300)); err != nil {
		_ = os.Remove(tmp)
		s.Logger.Error("archive: create upload", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]interface{}{
		"upload_id": id, "offset": 0, "size": in.Size, "chunk_size": archiveChunkSize,
	})
}

func (s *Server) archiveUploadStatus(w http.ResponseWriter, r *http.Request) {
	u, err := s.loadUpload(r.Context(), chi.URLParam(r, "id"), identityFrom(r).ID)
	if errors.Is(err, pgx.ErrNoRows) {
		writeError(w, http.StatusNotFound, "unggahan tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{
		"upload_id": u.ID, "offset": u.Received, "size": u.Size, "status": u.Status, "file_name": u.FileName,
	})
}

// ensureHashes leaves rt holding the hashes of exactly the first `received`
// bytes of the temp file: reusing the running state when it is in step,
// recomputing from disk otherwise (after a restart, or a failed chunk).
func ensureHashes(rt *uploadRT, path string, received int64) error {
	if rt.h256 != nil && rt.n == received {
		return nil
	}
	rt.h256, rt.h512, rt.n = sha256.New(), sha512.New(), 0
	if received == 0 {
		return nil
	}
	f, err := os.Open(path)
	if err != nil {
		rt.h256, rt.h512 = nil, nil
		return err
	}
	defer f.Close()
	n, err := io.Copy(io.MultiWriter(rt.h256, rt.h512), io.LimitReader(f, received))
	if err != nil || n != received {
		rt.h256, rt.h512 = nil, nil
		return fmt.Errorf("rehash: %d/%d bytes: %v", n, received, err)
	}
	rt.n = received
	return nil
}

// archiveUploadChunk appends one chunk at Upload-Offset. The offset must equal
// what the server already has, so a retry after a dropped connection cannot
// corrupt the file: the client asks GET for the offset and continues from there.
func (s *Server) archiveUploadChunk(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	rt := s.uploadRT(id)
	rt.mu.Lock()
	defer rt.mu.Unlock()

	u, err := s.loadUpload(ctx, id, me.ID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && u.Status != "open") {
		writeError(w, http.StatusNotFound, "unggahan tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	offset, err := strconv.ParseInt(r.Header.Get("Upload-Offset"), 10, 64)
	if err != nil || offset < 0 {
		writeError(w, http.StatusBadRequest, "header Upload-Offset wajib")
		return
	}
	if offset != u.Received {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "offset tidak sama dengan yang diterima server", "offset": u.Received})
		return
	}
	remaining := u.Size - offset
	if err := ensureHashes(rt, u.TempPath, u.Received); err != nil {
		s.Logger.Error("archive: hash state", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	f, err := os.OpenFile(u.TempPath, os.O_WRONLY, 0o600)
	if err != nil {
		s.Logger.Error("archive: open temp", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	defer f.Close()

	body := http.MaxBytesReader(w, r.Body, archiveMaxChunk)
	w512, w256 := rt.h512, rt.h256
	n, cerr := io.Copy(io.MultiWriter(io.NewOffsetWriter(f, offset), w256, w512), io.LimitReader(body, remaining+1))
	rollback := func() { _ = f.Truncate(offset); rt.h256, rt.h512, rt.n = nil, nil, 0 }
	switch {
	case cerr != nil:
		rollback()
		writeError(w, http.StatusBadRequest, "pengiriman potongan terputus; lanjutkan dari offset server")
		return
	case n > remaining:
		rollback()
		writeError(w, http.StatusBadRequest, "data melebihi ukuran yang dideklarasikan")
		return
	}
	rt.n = offset + n
	if _, err := s.DB.Exec(ctx, `UPDATE archive_upload SET received_bytes = $2, updated_at = now() WHERE id = $1`, id, offset+n); err != nil {
		rollback()
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, map[string]interface{}{"offset": offset + n, "size": u.Size})
}

func (s *Server) archiveAbort(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	id := chi.URLParam(r, "id")
	u, err := s.loadUpload(r.Context(), id, me.ID)
	if err != nil || u.Status != "open" {
		writeError(w, http.StatusNotFound, "unggahan tidak ditemukan")
		return
	}
	rt := s.uploadRT(id)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	_, _ = s.DB.Exec(r.Context(), `UPDATE archive_upload SET status = 'aborted', updated_at = now() WHERE id = $1`, id)
	_ = os.Remove(u.TempPath)
	s.dropUploadRT(id)
	writeJSON(w, http.StatusOK, map[string]string{"status": "aborted"})
}

// ---------------------------------------------------------------- complete

func hexSum(h hash.Hash) string { return hex.EncodeToString(h.Sum(nil)) }

func (s *Server) archiveComplete(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	ctx := r.Context()
	id := chi.URLParam(r, "id")
	var in struct {
		ClientSHA256 string `json:"client_sha256"`
	}
	_ = json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&in)

	rt := s.uploadRT(id)
	rt.mu.Lock()
	defer rt.mu.Unlock()

	u, err := s.loadUpload(ctx, id, me.ID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && u.Status != "open") {
		writeError(w, http.StatusNotFound, "unggahan tidak ditemukan atau sudah selesai")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if u.Received != u.Size {
		writeJSON(w, http.StatusConflict, map[string]interface{}{"error": "berkas belum diterima lengkap", "offset": u.Received, "size": u.Size})
		return
	}
	if err := ensureHashes(rt, u.TempPath, u.Received); err != nil {
		s.Logger.Error("archive: final hash", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	sum256, sum512 := hexSum(rt.h256), hexSum(rt.h512)
	client := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(in.ClientSHA256), "sha256:"))
	if client == "" {
		writeError(w, http.StatusBadRequest, "client_sha256 wajib: hash SHA-256 berkas yang dihitung browser")
		return
	}
	if client != sum256 {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]interface{}{
			"error":         "hash berkas di server berbeda dari yang dihitung browser; unggahan rusak di jalan, ulangi",
			"server_sha256": sum256, "client_sha256": client,
		})
		return
	}

	item, err := s.archiveFinalize(ctx, me, u, sum256, sum512, r)
	if err != nil {
		s.Logger.Error("archive: finalize", "upload", id, "error", err)
		writeError(w, http.StatusInternalServerError, "gagal mengarsipkan berkas; tidak ada yang dicatat, silakan ulangi")
		return
	}
	_, _ = s.DB.Exec(ctx, `UPDATE archive_upload SET status = 'completed', updated_at = now() WHERE id = $1`, id)
	_ = os.Remove(u.TempPath)
	s.dropUploadRT(id)
	writeJSON(w, http.StatusCreated, s.receiptResponse(ctx, item))
}

type archivedItem struct {
	ItemID, ReceiptID, TransactionID string
	Receipt                          json.RawMessage
}

// archiveFinalize stores the file, proves what was stored, and records the
// signed transaction. Either everything is recorded or nothing is: the object
// is removed again if the database step fails.
func (s *Server) archiveFinalize(ctx context.Context, me officeIdentity, u uploadRow, sum256, sum512 string, r *http.Request) (archivedItem, error) {
	now := time.Now().UTC()
	itemID := "arc_" + uuid.NewString()
	txnID := "txn_" + uuid.NewString()
	receiptID := newReceiptID()
	key := fmt.Sprintf("archive/%s/%s/%s", u.OrgID, now.Format("2006/01"), itemID)

	f, err := os.Open(u.TempPath)
	if err != nil {
		return archivedItem{}, err
	}
	defer f.Close()
	if err := s.Objects.PutStream(ctx, key, f, u.Size, "application/octet-stream"); err != nil {
		return archivedItem{}, fmt.Errorf("store object: %w", err)
	}
	ok := false
	defer func() {
		if !ok {
			_ = s.Objects.Delete(context.WithoutCancel(ctx), key)
		}
	}()

	// Read it back: INTEGRITY_VERIFIED must be a fact about the STORED bytes.
	rc, err := s.Objects.GetStream(ctx, key)
	if err != nil {
		return archivedItem{}, fmt.Errorf("read back: %w", err)
	}
	h256, h512 := sha256.New(), sha512.New()
	n, err := io.Copy(io.MultiWriter(h256, h512), rc)
	rc.Close()
	if err != nil || n != u.Size || hexSum(h256) != sum256 || hexSum(h512) != sum512 {
		return archivedItem{}, fmt.Errorf("stored object does not match the received bytes (n=%d err=%v)", n, err)
	}

	var orgName string
	_ = s.DB.QueryRow(ctx, `SELECT name FROM organization WHERE id = $1`, u.OrgID).Scan(&orgName)
	manifest := map[string]interface{}{
		"schema": "archive-manifest/1", "receipt_id": receiptID, "item_id": itemID, "transaction_id": txnID,
		"server_name":     s.Archive.ServerName,
		"organization_id": u.OrgID, "organization_name": orgName,
		"sender_id": me.ID, "sender_name": me.Name, "sender_email": me.Email,
		"file_name": u.FileName, "media_type": u.MediaType, "size_bytes": u.Size,
		"sha256": sum256, "sha512": sum512, "description": u.Description,
		"client_ip": u.ClientIP, "user_agent": u.UserAgent,
		"received_at": now.Format(time.RFC3339Nano),
	}

	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return archivedItem{}, err
	}
	defer tx.Rollback(ctx)

	meta, _ := json.Marshal(map[string]interface{}{"title": u.FileName, "category": "arsip", "amount": u.Size, "description": u.Description})
	if _, err := tx.Exec(ctx, `
		INSERT INTO transaction (id, organization_id, workflow_type, schema_version, created_by, status, office_meta)
		VALUES ($1,$2,$3,$4,$5,'DRAFT',$6)`, txnID, u.OrgID, archiveWorkflow, archiveSchema, me.ID, meta); err != nil {
		return archivedItem{}, err
	}
	createArgs, _ := json.Marshal([]string{txnID, u.OrgID, archiveWorkflow, archiveSchema, me.ID})
	if err := enqueueOutbox(ctx, tx, "transaction", txnID, "transaction", "CreateTransaction", createArgs); err != nil {
		return archivedItem{}, err
	}

	// 1. the sender's signature over the manifest
	e1, err := s.appendTransactionEvent(ctx, tx, eventInput{
		TransactionID: txnID, EventType: "UPLOAD_RECEIVED", SignerIdentity: me.ID, Payload: manifest,
	}, true)
	if err != nil {
		return archivedItem{}, err
	}
	// 2. the server proves it stored exactly those bytes
	if _, err := s.appendTransactionEvent(ctx, tx, eventInput{
		TransactionID: txnID, EventType: "INTEGRITY_VERIFIED", SignerIdentity: systemArchiveID, NewStatus: "VERIFIED",
		Payload: map[string]interface{}{
			"receipt_id": receiptID, "sha256": sum256, "sha512": sum512, "size_bytes": u.Size,
			"method": "read-back-from-object-store", "at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, true); err != nil {
		return archivedItem{}, err
	}
	// 3. archived; the receipt is issued
	if _, err := s.appendTransactionEvent(ctx, tx, eventInput{
		TransactionID: txnID, EventType: "ARCHIVED", SignerIdentity: systemArchiveID, NewStatus: "ENDORSED",
		Payload: map[string]interface{}{
			"receipt_id": receiptID, "manifest_hash": e1.PayloadHash, "at": time.Now().UTC().Format(time.RFC3339Nano),
		},
	}, true); err != nil {
		return archivedItem{}, err
	}

	receipt, err := s.buildReceipt(ctx, tx, txnID, receiptID, manifest, e1.PayloadHash)
	if err != nil {
		return archivedItem{}, err
	}
	manifestJSON, _ := json.Marshal(manifest)
	if _, err := tx.Exec(ctx, `
		INSERT INTO archive_item (id, receipt_id, transaction_id, organization_id, sender_id, file_name, media_type, size_bytes,
		                          sha256, sha512, description, storage_key, client_ip, user_agent, manifest, manifest_hash, receipt, received_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17,$18)`,
		itemID, receiptID, txnID, u.OrgID, me.ID, u.FileName, u.MediaType, u.Size, sum256, sum512, u.Description, key,
		u.ClientIP, u.UserAgent, manifestJSON, e1.PayloadHash, receipt, now); err != nil {
		return archivedItem{}, err
	}
	if err := tx.Commit(ctx); err != nil {
		return archivedItem{}, err
	}
	ok = true
	return archivedItem{ItemID: itemID, ReceiptID: receiptID, TransactionID: txnID, Receipt: receipt}, nil
}

// ---------------------------------------------------------------- receipt

type sigJSON struct {
	Suite              string `json:"algorithm_suite"`
	ClassicalKeyID     string `json:"classical_key_id"`
	PQCKeyID           string `json:"pqc_key_id"`
	ClassicalSignature string `json:"classical_signature"`
	PQCSignature       string `json:"pqc_signature"`
	SigningContext     struct {
		Application     string `json:"application"`
		Environment     string `json:"environment"`
		TransactionType string `json:"transaction_type"`
		SchemaVersion   string `json:"schema_version"`
		TransactionID   string `json:"transaction_id"`
	} `json:"signing_context"`
}

func (s *Server) sigContext(txnType, txnID string) crypto.SigningContext {
	return crypto.SigningContext{Application: s.Application, Environment: s.Environment,
		TransactionType: txnType, SchemaVersion: archiveSchema, TransactionID: txnID}
}

func toSigJSON(sig *crypto.HybridSignature, c crypto.SigningContext) sigJSON {
	j := sigJSON{Suite: string(sig.AlgorithmSuite), ClassicalKeyID: sig.ClassicalKeyID, PQCKeyID: sig.PQCKeyID,
		ClassicalSignature: base64.StdEncoding.EncodeToString(sig.ClassicalSignature),
		PQCSignature:       base64.StdEncoding.EncodeToString(sig.PQCSignature)}
	j.SigningContext.Application, j.SigningContext.Environment = c.Application, c.Environment
	j.SigningContext.TransactionType, j.SigningContext.SchemaVersion, j.SigningContext.TransactionID =
		c.TransactionType, c.SchemaVersion, c.TransactionID
	return j
}

// buildReceipt assembles the receipt body (manifest, the sender's signature, the
// chained event hashes) and signs it with the system identity. The result is
// {"body": ..., "server_signature": ...}.
func (s *Server) buildReceipt(ctx context.Context, tx pgx.Tx, txnID, receiptID string, manifest map[string]interface{}, manifestHash string) ([]byte, error) {
	rows, err := tx.Query(ctx, `
		SELECT event_sequence, event_type, payload_hash, COALESCE(previous_event_hash,''), algorithm_suite,
		       classical_key_id, pqc_key_id, classical_signature, pqc_signature
		FROM transaction_event WHERE transaction_id = $1 ORDER BY event_sequence`, txnID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []map[string]interface{}
	var senderSig *sigJSON
	for rows.Next() {
		var seq int
		var typ, ph, prev, suite, ck, pk string
		var cs, ps []byte
		if err := rows.Scan(&seq, &typ, &ph, &prev, &suite, &ck, &pk, &cs, &ps); err != nil {
			return nil, err
		}
		events = append(events, map[string]interface{}{"sequence": seq, "type": typ, "payload_hash": ph, "previous_event_hash": prev})
		if seq == 1 {
			j := toSigJSON(&crypto.HybridSignature{AlgorithmSuite: crypto.AlgorithmSuite(suite), ClassicalKeyID: ck, PQCKeyID: pk,
				ClassicalSignature: cs, PQCSignature: ps}, s.sigContext("UPLOAD_RECEIVED", txnID))
			senderSig = &j
		}
	}
	rows.Close()
	if senderSig == nil {
		return nil, errors.New("missing first event")
	}
	body := map[string]interface{}{
		"format": "archive-receipt/1", "receipt_id": receiptID, "issued_at": time.Now().UTC().Format(time.RFC3339Nano),
		"transaction_id": txnID, "manifest": manifest, "manifest_hash": manifestHash,
		"sender_signature": senderSig, "events": events,
	}
	// Round-trip through JSON so what is signed is exactly what is stored/served.
	rawBody, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	var canonBody map[string]interface{}
	if err := json.Unmarshal(rawBody, &canonBody); err != nil {
		return nil, err
	}
	identity, err := s.Keystore.SigningIdentity(ctx, systemArchiveID)
	if err != nil {
		return nil, err
	}
	c := s.sigContext("ARCHIVE_RECEIPT", txnID)
	sig, _, err := crypto.SignHybrid(identity, c, canonBody)
	if err != nil {
		return nil, err
	}
	return json.Marshal(map[string]interface{}{"body": canonBody, "server_signature": toSigJSON(sig, c)})
}

// receiptResponse is what the sender gets back: the signed receipt, where to
// verify it, and how far the ledger has got.
func (s *Server) receiptResponse(ctx context.Context, it archivedItem) map[string]interface{} {
	var rcpt map[string]interface{}
	_ = json.Unmarshal(it.Receipt, &rcpt)
	return map[string]interface{}{
		"receipt": rcpt, "receipt_id": it.ReceiptID, "item_id": it.ItemID,
		"verify_path": "/app/#r=" + it.ReceiptID, "ledger": s.ledgerFor(ctx, it.TransactionID),
	}
}

// ledgerFor summarises the ledger recording state of one transaction.
func (s *Server) ledgerFor(ctx context.Context, txnID string) map[string]interface{} {
	var queued, dead, committed int
	_ = s.DB.QueryRow(ctx, `
		SELECT count(*) FILTER (WHERE status IN ('pending','failed')), count(*) FILTER (WHERE status = 'dead_letter')
		FROM outbox_event WHERE aggregate_id = $1`, txnID).Scan(&queued, &dead)
	_ = s.DB.QueryRow(ctx, `SELECT count(*) FROM transaction_event WHERE transaction_id = $1 AND fabric_tx_id IS NOT NULL`, txnID).Scan(&committed)
	return ledgerState(s.Office.FabricEnabled, queued, dead, committed)
}

// archiveReceipt returns a receipt to its sender (or an admin).
func (s *Server) archiveReceipt(w http.ResponseWriter, r *http.Request) {
	me := identityFrom(r)
	var it archivedItem
	var sender string
	err := s.DB.QueryRow(r.Context(), `SELECT id, receipt_id, transaction_id, receipt, sender_id FROM archive_item WHERE receipt_id = $1`,
		chi.URLParam(r, "receipt_id")).Scan(&it.ItemID, &it.ReceiptID, &it.TransactionID, &it.Receipt, &sender)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && sender != me.ID && !me.isAdmin()) {
		writeError(w, http.StatusNotFound, "bukti tidak ditemukan")
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	writeJSON(w, http.StatusOK, s.receiptResponse(r.Context(), it))
}
