package store

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

// ObjectStore holds the signed PDF blobs. Keys are server-generated
// (Rencana V1 §19), never derived from a user file name. The *From / Open
// methods stream so a large document never has to be buffered whole.
type ObjectStore interface {
	PutObject(key string, data []byte) error
	GetObject(key string) ([]byte, error)
	PutObjectFrom(key string, r io.Reader, size int64) error
	OpenObject(key string) (io.ReadCloser, int64, error)
}

// --- DB-backed (objects table); the default when no S3 is configured ---

type dbObjects struct{ db *sql.DB }

func (o dbObjects) PutObject(key string, data []byte) error {
	_, err := o.db.Exec(
		`INSERT INTO objects(key,data) VALUES($1,$2)
		 ON CONFLICT(key) DO UPDATE SET data=EXCLUDED.data`, key, data)
	return err
}

func (o dbObjects) GetObject(key string) ([]byte, error) {
	var b []byte
	err := o.db.QueryRow(`SELECT data FROM objects WHERE key=$1`, key).Scan(&b)
	if err == sql.ErrNoRows {
		return nil, ErrNotFound
	}
	return b, err
}

func (o dbObjects) PutObjectFrom(key string, r io.Reader, _ int64) error {
	b, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	return o.PutObject(key, b)
}

func (o dbObjects) OpenObject(key string) (io.ReadCloser, int64, error) {
	b, err := o.GetObject(key)
	if err != nil {
		return nil, 0, err
	}
	return io.NopCloser(bytes.NewReader(b)), int64(len(b)), nil
}

// --- filesystem-backed (a mounted volume); for documents too big for a
// Postgres bytea value (its hard cap is 1 GiB) or to keep them off the DB ---

type fsObjects struct{ dir string }

// NewFSObjects stores each blob at <dir>/<key> (key path segments become
// directories). Used when PQC_OBJECT_DIR is set.
func NewFSObjects(dir string) (ObjectStore, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("store: object dir %q: %w", dir, err)
	}
	return fsObjects{dir: dir}, nil
}

func (o fsObjects) resolve(key string) (string, error) {
	// server-generated keys only, but stay defensive about traversal
	clean := filepath.Clean("/" + filepath.ToSlash(key))
	if clean == "/" || strings.Contains(clean, "..") {
		return "", fmt.Errorf("store: bad object key %q", key)
	}
	return filepath.Join(o.dir, filepath.FromSlash(clean)), nil
}

func (o fsObjects) PutObjectFrom(key string, r io.Reader, _ int64) error {
	p, err := o.resolve(key)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	tmp := p + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return os.Rename(tmp, p)
}

func (o fsObjects) PutObject(key string, data []byte) error {
	return o.PutObjectFrom(key, bytes.NewReader(data), int64(len(data)))
}

func (o fsObjects) OpenObject(key string) (io.ReadCloser, int64, error) {
	p, err := o.resolve(key)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(p)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, 0, ErrNotFound
		}
		return nil, 0, err
	}
	st, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, err
	}
	return f, st.Size(), nil
}

func (o fsObjects) GetObject(key string) ([]byte, error) {
	rc, _, err := o.OpenObject(key)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// --- MinIO / S3 ---

// S3Config configures an S3-compatible object store (MinIO in the lab, §22).
type S3Config struct {
	Endpoint  string // host:port, no scheme
	Region    string
	Bucket    string
	AccessKey string
	SecretKey string
	UseSSL    bool
}

type s3Objects struct {
	client *minio.Client
	bucket string
}

// NewS3Objects connects to the endpoint and ensures the bucket exists.
func NewS3Objects(cfg S3Config) (ObjectStore, error) {
	cl, err := minio.New(cfg.Endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(cfg.AccessKey, cfg.SecretKey, ""),
		Secure: cfg.UseSSL,
		Region: cfg.Region,
	})
	if err != nil {
		return nil, fmt.Errorf("store: minio client: %w", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ok, err := cl.BucketExists(ctx, cfg.Bucket)
	if err != nil {
		return nil, fmt.Errorf("store: minio reachability: %w", err)
	}
	if !ok {
		if err := cl.MakeBucket(ctx, cfg.Bucket, minio.MakeBucketOptions{Region: cfg.Region}); err != nil {
			return nil, fmt.Errorf("store: create bucket %q: %w", cfg.Bucket, err)
		}
	}
	return s3Objects{client: cl, bucket: cfg.Bucket}, nil
}

func (o s3Objects) PutObject(key string, data []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	_, err := o.client.PutObject(ctx, o.bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: "application/pdf"})
	return err
}

func (o s3Objects) GetObject(key string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	obj, err := o.client.GetObject(ctx, o.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer obj.Close()
	b, err := io.ReadAll(obj)
	if err != nil {
		return nil, ErrNotFound
	}
	return b, nil
}

func (o s3Objects) PutObjectFrom(key string, r io.Reader, size int64) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	if size <= 0 {
		size = -1 // unknown -> minio streams with a multipart buffer
	}
	_, err := o.client.PutObject(ctx, o.bucket, key, r, size,
		minio.PutObjectOptions{ContentType: "application/pdf"})
	return err
}

func (o s3Objects) OpenObject(key string) (io.ReadCloser, int64, error) {
	ctx := context.Background()
	obj, err := o.client.GetObject(ctx, o.bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, 0, err
	}
	st, err := obj.Stat()
	if err != nil {
		_ = obj.Close()
		return nil, 0, ErrNotFound
	}
	return obj, st.Size, nil
}
