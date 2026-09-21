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
