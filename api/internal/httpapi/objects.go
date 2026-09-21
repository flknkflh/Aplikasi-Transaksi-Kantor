package httpapi

import (
	"bytes"
	"context"
	"io"

	"github.com/minio/minio-go/v7"
)

// ObjectStore is the small slice of object storage the office workflow needs.
// The MinIO client satisfies it in production; tests use an in-memory one.
type ObjectStore interface {
	Put(ctx context.Context, key string, data []byte, contentType string) error
	Get(ctx context.Context, key string) ([]byte, error)
	// PutStream stores size bytes from r without buffering them in memory (any size).
	PutStream(ctx context.Context, key string, r io.Reader, size int64, contentType string) error
	// GetStream returns the object for streaming; the caller closes it.
	GetStream(ctx context.Context, key string) (io.ReadCloser, error)
	Delete(ctx context.Context, key string) error
}

// MinIOObjects adapts a MinIO client + bucket to ObjectStore.
type MinIOObjects struct {
	Client *minio.Client
	Bucket string
}

func (m MinIOObjects) Put(ctx context.Context, key string, data []byte, contentType string) error {
	_, err := m.Client.PutObject(ctx, m.Bucket, key, bytes.NewReader(data), int64(len(data)),
		minio.PutObjectOptions{ContentType: contentType})
	return err
}

func (m MinIOObjects) Get(ctx context.Context, key string) ([]byte, error) {
	o, err := m.Client.GetObject(ctx, m.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	defer o.Close()
	return io.ReadAll(io.LimitReader(o, maxDocumentSize+1))
}

func (m MinIOObjects) PutStream(ctx context.Context, key string, r io.Reader, size int64, contentType string) error {
	_, err := m.Client.PutObject(ctx, m.Bucket, key, r, size, minio.PutObjectOptions{ContentType: contentType})
	return err
}

func (m MinIOObjects) GetStream(ctx context.Context, key string) (io.ReadCloser, error) {
	o, err := m.Client.GetObject(ctx, m.Bucket, key, minio.GetObjectOptions{})
	if err != nil {
		return nil, err
	}
	if _, err := o.Stat(); err != nil { // surface "not found" now, not on first read
		o.Close()
		return nil, err
	}
	return o, nil
}

func (m MinIOObjects) Delete(ctx context.Context, key string) error {
	return m.Client.RemoveObject(ctx, m.Bucket, key, minio.RemoveObjectOptions{})
}
