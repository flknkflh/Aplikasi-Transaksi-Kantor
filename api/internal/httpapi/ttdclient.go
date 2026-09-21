package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// TTDRecord is what the TTD server knows about one signature (its internal
// office endpoint). The ledger trusts it — not the browser — to say who signed
// what: the record is written by the TTD server after its own strict
// re-verification of the signed PDF.
type TTDRecord struct {
	PublicID           string `json:"public_id"`
	AccountID          string `json:"account_id"`
	OriginalSHA512     string `json:"original_sha512"`
	SignedSHA512       string `json:"signed_sha512"`
	VerificationStatus string `json:"verification_status"`
	VerificationURL    string `json:"verification_url"`
}

// TTDVerifier looks up a TTD signature and fetches its signed PDF.
type TTDVerifier interface {
	Record(ctx context.Context, publicID string) (TTDRecord, error)
	SignedPDF(ctx context.Context, publicID string) ([]byte, error)
}

// HTTPTTD talks to the TTD server over the internal network with the shared
// proxy secret.
type HTTPTTD struct {
	BaseURL string
	Secret  string
	Client  *http.Client
}

func (h HTTPTTD) client() *http.Client {
	if h.Client != nil {
		return h.Client
	}
	return &http.Client{Timeout: 30 * time.Second}
}

func (h HTTPTTD) get(ctx context.Context, path string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(h.BaseURL, "/")+path, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Office-Secret", h.Secret)
	resp, err := h.client().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("ttd server answered %d for %s", resp.StatusCode, path)
	}
	return io.ReadAll(io.LimitReader(resp.Body, limit+1))
}

func (h HTTPTTD) Record(ctx context.Context, publicID string) (TTDRecord, error) {
	b, err := h.get(ctx, "/internal/office/signatures/"+publicID, 1<<20)
	if err != nil {
		return TTDRecord{}, err
	}
	var r TTDRecord
	if err := json.Unmarshal(b, &r); err != nil {
		return TTDRecord{}, err
	}
	return r, nil
}

func (h HTTPTTD) SignedPDF(ctx context.Context, publicID string) ([]byte, error) {
	b, err := h.get(ctx, "/internal/office/signatures/"+publicID+"/document", maxDocumentSize)
	if err != nil {
		return nil, err
	}
	if len(b) > maxDocumentSize {
		return nil, fmt.Errorf("signed document too large")
	}
	return b, nil
}
