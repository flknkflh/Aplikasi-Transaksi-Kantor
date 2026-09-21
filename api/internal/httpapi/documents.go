package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/google/uuid"
	"github.com/minio/minio-go/v7"
)

const maxDocumentSize = 32 << 20 // 32 MiB, generous for a spike

// UploadDocument stores a document off-chain in MinIO and records only its
// hash and storage reference in Postgres — the ledger event that references
// this document later embeds document_reference.id and its sha256_hash in
// its signed payload, so the hash (not the document) is what actually gets
// committed to the chain (PRD §6's on-chain/off-chain split).
func (s *Server) UploadDocument(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseMultipartForm(maxDocumentSize); err != nil {
		writeError(w, http.StatusBadRequest, "expected multipart/form-data with a 'file' field")
		return
	}
	file, header, err := r.FormFile("file")
	if err != nil {
		writeError(w, http.StatusBadRequest, "missing 'file' field")
		return
	}
	defer file.Close()

	uploadedBy := r.FormValue("uploaded_by")
	ownerType := r.FormValue("owner_type")
	ownerID := r.FormValue("owner_id")
	if uploadedBy == "" || ownerType == "" || ownerID == "" {
		writeError(w, http.StatusBadRequest, "uploaded_by, owner_type, and owner_id are required")
		return
	}
	if ownerType != "transaction_event" && ownerType != "custody_event" {
		writeError(w, http.StatusBadRequest, "owner_type must be 'transaction_event' or 'custody_event'")
		return
	}

	data, err := io.ReadAll(io.LimitReader(file, maxDocumentSize+1))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}
	if len(data) > maxDocumentSize {
		writeError(w, http.StatusBadRequest, "file too large")
		return
	}

	sum := sha256.Sum256(data)
	hash := "sha256:" + hex.EncodeToString(sum[:])

	ctx := r.Context()
	id := uuid.NewString()
	objectKey := fmt.Sprintf("%s/%s", ownerType, id)

	contentType := header.Header.Get("Content-Type")
	if contentType == "" {
		contentType = "application/octet-stream"
	}
	if _, err := s.MinIO.PutObject(ctx, s.Bucket, objectKey, bytes.NewReader(data), int64(len(data)), minio.PutObjectOptions{
		ContentType: contentType,
	}); err != nil {
		s.Logger.Error("upload document: minio put", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	if _, err := s.DB.Exec(ctx, `
		INSERT INTO document_reference (id, owner_type, owner_id, storage_bucket, storage_key, sha256_hash, content_type, uploaded_by)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)`,
		id, ownerType, ownerID, s.Bucket, objectKey, hash, contentType, uploadedBy,
	); err != nil {
		s.Logger.Error("upload document: insert", "error", err)
		writeError(w, http.StatusInternalServerError, "internal error")
		return
	}

	writeJSON(w, http.StatusCreated, map[string]string{
		"id":             id,
		"sha256_hash":    hash,
		"storage_bucket": s.Bucket,
		"storage_key":    objectKey,
	})
}
