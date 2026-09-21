// Package config loads runtime configuration from the environment, with
// defaults that point at this repo's local dev stack (infra/docker-compose.yml
// and the vendored Fabric test network from network/bootstrap.sh). None of
// these defaults are appropriate for anything beyond the Fase 1 spike — see
// docs/adr/0001-fase1-spike-scope.md.
package config

import (
	"os"
	"path/filepath"
	"strconv"
)

type Config struct {
	// HTTP server
	ListenAddr string

	// PostgreSQL
	DatabaseURL string

	// MinIO / S3-compatible object storage
	MinIOEndpoint  string
	MinIOAccessKey string
	MinIOSecretKey string
	MinIOUseSSL    bool
	MinIOBucket    string

	// Dev-only signing keystore (see docs/adr/0001 decision #4)
	KeystorePath string
	// KeystoreKEK encrypts the keystore file at rest (AES-256-GCM). Required wherever the
	// server holds keys that people are accountable for.
	KeystoreKEK string

	// Signing context (crypto.SigningContext)
	Application string
	Environment string

	// Fabric Gateway connection (Org1 User1 identity from the vendored
	// test-network, matching the fabric-gateway Go sample's layout)
	FabricMSPID        string
	FabricCertPath     string
	FabricKeyPath      string
	FabricTLSCertPath  string
	FabricPeerEndpoint string
	FabricGatewayPeer  string
	FabricChannelName  string

	// FabricEnabled=false runs without a Fabric connection: the outbox worker is
	// not started and events stay queued (visible in the UI) until it is enabled.
	FabricEnabled bool

	// Office app: enabled when OfficeProxySecret is set. TTDInternalURL is how
	// this service reaches the TTD server to verify approval signatures.
	OfficeProxySecret string

	// Archive app: scratch dir for resumable uploads, per-file ceiling (bytes, 0 = 20 GiB),
	// and the server name users see so they can confirm where they are sending.
	ArchiveTempDir  string
	ArchiveMaxBytes int64
	ServerName      string
	TTDInternalURL  string

	OutboxPollInterval string // parsed by main via time.ParseDuration
	OutboxMaxAttempts  int
}

func Load() Config {
	return Config{
		ListenAddr:  getEnv("LISTEN_ADDR", ":8080"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://ledger:ledger_dev_only@localhost:5432/ledger?sslmode=disable"),

		MinIOEndpoint:  getEnv("MINIO_ENDPOINT", "localhost:9000"),
		MinIOAccessKey: getEnv("MINIO_ACCESS_KEY", "ledger_admin"),
		MinIOSecretKey: getEnv("MINIO_SECRET_KEY", "ledger_dev_only"),
		MinIOUseSSL:    getEnv("MINIO_USE_SSL", "false") == "true",
		MinIOBucket:    getEnv("MINIO_BUCKET", "ledger-documents"),

		KeystorePath: getEnv("KEYSTORE_PATH", "./keystore/dev-keystore.json"),
		KeystoreKEK:  getEnv("KEYSTORE_KEK", ""),

		Application: getEnv("SIGNING_APPLICATION", "pqc-ledger"),
		Environment: getEnv("SIGNING_ENVIRONMENT", "dev"),

		FabricMSPID:        getEnv("FABRIC_MSP_ID", "Org1MSP"),
		FabricCertPath:     getEnv("FABRIC_CERT_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts"),
		FabricKeyPath:      getEnv("FABRIC_KEY_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore"),
		FabricTLSCertPath:  getEnv("FABRIC_TLS_CERT_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"),
		FabricPeerEndpoint: getEnv("FABRIC_PEER_ENDPOINT", "dns:///localhost:7051"),
		FabricGatewayPeer:  getEnv("FABRIC_GATEWAY_PEER", "peer0.org1.example.com"),
		FabricChannelName:  getEnv("FABRIC_CHANNEL_NAME", "ledgerchannel"),

		FabricEnabled:     getEnv("FABRIC_ENABLED", "true") != "false",
		OfficeProxySecret: getEnv("OFFICE_PROXY_SECRET", ""),
		ArchiveTempDir:    getEnv("ARCHIVE_TEMP_DIR", filepath.Join(os.TempDir(), "archive-uploads")),
		ArchiveMaxBytes:   int64(getEnvInt("ARCHIVE_MAX_BYTES", 0)),
		ServerName:        getEnv("SERVER_NAME", "Server Arsip"),
		TTDInternalURL:    getEnv("TTD_INTERNAL_URL", "http://localhost:8099"),

		OutboxPollInterval: getEnv("OUTBOX_POLL_INTERVAL", "2s"),
		OutboxMaxAttempts:  getEnvInt("OUTBOX_MAX_ATTEMPTS", 8),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

// getEnvInt reads a positive integer; anything else falls back.
func getEnvInt(key string, fallback int) int {
	if n, err := strconv.Atoi(os.Getenv(key)); err == nil && n > 0 {
		return n
	}
	return fallback
}
