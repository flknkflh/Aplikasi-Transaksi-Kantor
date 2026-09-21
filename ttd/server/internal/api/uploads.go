package api

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Resumable upload (docs/large-files.md). A signed PDF that is hundreds of MB
// does not survive one HTTP request on a flaky link, so the client can push it
// in chunks to a scratch file and then point /stamp or /document at the
// assembled upload with ?upload_id=. Sessions are in-memory (a server restart
// mid-upload means starting that upload over) and expire after 2h.

var (
	errUploadOffset = errors.New("offset mismatch")
	errUploadTooBig = errors.New("upload exceeds the limit")
	errNoUpload     = errors.New("upload session not found")
)

type uploadSession struct {
	id      string
	account string
	path    string
	size    int64
	updated time.Time
}

type uploadManager struct {
	mu  sync.Mutex
	dir string
	m   map[string]*uploadSession
}

func newUploadManager(dir string) *uploadManager {
	if dir == "" {
		dir = os.TempDir()
	}
	_ = os.MkdirAll(dir, 0o755)
	um := &uploadManager{dir: dir, m: map[string]*uploadSession{}}
	go um.reaper()
	return um
}

func (um *uploadManager) reaper() {
	for range time.Tick(15 * time.Minute) {
		um.mu.Lock()
		for id, s := range um.m {
			if time.Since(s.updated) > 2*time.Hour {
				_ = os.Remove(s.path)
				delete(um.m, id)
			}
		}
		um.mu.Unlock()
	}
}

func (um *uploadManager) create(account string) (*uploadSession, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	s := &uploadSession{id: "up_" + hex.EncodeToString(b), account: account, updated: time.Now()}
	s.path = filepath.Join(um.dir, s.id+".part")
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	_ = f.Close()
	um.mu.Lock()
	um.m[s.id] = s
	um.mu.Unlock()
	return s, nil
}

func (um *uploadManager) get(id, account string) *uploadSession {
	um.mu.Lock()
	defer um.mu.Unlock()
	if s := um.m[id]; s != nil && s.account == account {
		return s
	}
	return nil
}

// appendChunk writes r at offset (which must equal the current size) and
// returns the new size. It refuses to grow past max.
func (um *uploadManager) appendChunk(s *uploadSession, offset, max int64, r io.Reader) (int64, error) {
	um.mu.Lock()
	defer um.mu.Unlock()
	if offset != s.size {
		return s.size, errUploadOffset
	}
	f, err := os.OpenFile(s.path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return s.size, err
	}
	defer f.Close()
	n, err := io.Copy(f, io.LimitReader(r, max-s.size+1))
	s.size += n
	s.updated = time.Now()
	if err != nil {
		return s.size, err
	}
	if s.size > max {
		return s.size, errUploadTooBig
	}
	return s.size, nil
}

func (um *uploadManager) discard(s *uploadSession) {
	um.mu.Lock()
	delete(um.m, s.id)
	um.mu.Unlock()
	_ = os.Remove(s.path)
}

// ---- handlers ----

func (s *Server) hUploadCreate(w http.ResponseWriter, r *http.Request) {
	sess, err := s.uploads.create(claims(r).Sub)
	if err != nil {
		writeErr(w, http.StatusInternalServerError, "gagal memulai unggah")
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"upload_id": sess.id, "received": 0, "max_bytes": s.cfg.MaxUploadBytes,
	})
}

func (s *Server) hUploadChunk(w http.ResponseWriter, r *http.Request) {
	sess := s.uploads.get(r.PathValue("id"), claims(r).Sub)
	if sess == nil {
		writeErr(w, http.StatusNotFound, "sesi unggah tidak ditemukan")
		return
	}
	offset, _ := strconv.ParseInt(r.URL.Query().Get("offset"), 10, 64)
	got, err := s.uploads.appendChunk(sess, offset, s.cfg.MaxUploadBytes, r.Body)
	switch {
	case errors.Is(err, errUploadOffset):
		writeJSON(w, http.StatusConflict, map[string]any{"error": "offset tidak sesuai", "received": got})
	case errors.Is(err, errUploadTooBig):
		s.uploads.discard(sess)
		writeErr(w, http.StatusRequestEntityTooLarge, "unggahan melebihi batas")
	case err != nil:
		writeErr(w, http.StatusInternalServerError, "gagal menulis potongan")
	default:
		writeJSON(w, http.StatusOK, map[string]any{"received": got})
	}
}

func (s *Server) hUploadStatus(w http.ResponseWriter, r *http.Request) {
	sess := s.uploads.get(r.PathValue("id"), claims(r).Sub)
	if sess == nil {
		writeErr(w, http.StatusNotFound, "sesi unggah tidak ditemukan")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"received": sess.size})
}
