// Package config loads the audit-service's runtime configuration. Same
// defaults convention as api/internal/config.
package config

import "os"

type Config struct {
	ListenAddr  string
	DatabaseURL string

	Application string
	Environment string

	FabricMSPID        string
	FabricCertPath     string
	FabricKeyPath      string
	FabricTLSCertPath  string
	FabricPeerEndpoint string
	FabricGatewayPeer  string
	FabricChannelName  string
}

func Load() Config {
	return Config{
		ListenAddr:  getEnv("LISTEN_ADDR", ":8081"),
		DatabaseURL: getEnv("DATABASE_URL", "postgres://ledger:ledger_dev_only@localhost:5432/ledger?sslmode=disable"),

		Application: getEnv("SIGNING_APPLICATION", "pqc-ledger"),
		Environment: getEnv("SIGNING_ENVIRONMENT", "dev"),

		// Audit-service uses its own identity within Org1 (User1 here, same
		// as api/, is fine for a spike with a single peer org; a real
		// deployment would give the audit domain its own MSP identity per
		// PRD §4's separation-of-duties principle).
		FabricMSPID:        getEnv("FABRIC_MSP_ID", "Org1MSP"),
		FabricCertPath:     getEnv("FABRIC_CERT_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts"),
		FabricKeyPath:      getEnv("FABRIC_KEY_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore"),
		FabricTLSCertPath:  getEnv("FABRIC_TLS_CERT_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"),
		FabricPeerEndpoint: getEnv("FABRIC_PEER_ENDPOINT", "dns:///localhost:7051"),
		FabricGatewayPeer:  getEnv("FABRIC_GATEWAY_PEER", "peer0.org1.example.com"),
		FabricChannelName:  getEnv("FABRIC_CHANNEL_NAME", "ledgerchannel"),
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
