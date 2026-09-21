// Package config loads the indexer's runtime configuration. Same defaults
// convention as api/internal/config — see that package's doc comment.
package config

import "os"

type Config struct {
	DatabaseURL string

	FabricMSPID        string
	FabricCertPath     string
	FabricKeyPath      string
	FabricTLSCertPath  string
	FabricPeerEndpoint string
	FabricGatewayPeer  string
	FabricChannelName  string

	// Chaincodes to listen to; the indexer runs one listener goroutine per
	// entry.
	ChaincodeNames []string
}

func Load() Config {
	return Config{
		DatabaseURL: getEnv("DATABASE_URL", "postgres://ledger:ledger_dev_only@localhost:5432/ledger?sslmode=disable"),

		FabricMSPID:        getEnv("FABRIC_MSP_ID", "Org1MSP"),
		FabricCertPath:     getEnv("FABRIC_CERT_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/signcerts"),
		FabricKeyPath:      getEnv("FABRIC_KEY_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/users/User1@org1.example.com/msp/keystore"),
		FabricTLSCertPath:  getEnv("FABRIC_TLS_CERT_PATH", "../network/vendor/fabric-samples/test-network/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"),
		FabricPeerEndpoint: getEnv("FABRIC_PEER_ENDPOINT", "dns:///localhost:7051"),
		FabricGatewayPeer:  getEnv("FABRIC_GATEWAY_PEER", "peer0.org1.example.com"),
		FabricChannelName:  getEnv("FABRIC_CHANNEL_NAME", "ledgerchannel"),

		ChaincodeNames: []string{"transaction", "asset"},
	}
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}
