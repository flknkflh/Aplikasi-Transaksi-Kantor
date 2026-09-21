// Package fabricclient wraps the read-only Fabric Gateway connection the
// indexer needs (chaincode event subscription only — no Submit). See
// api/internal/fabricclient for the write-side twin and the identity/TLS
// material explanation.
package fabricclient

import (
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"

	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/hyperledger/fabric-gateway/pkg/hash"
	"github.com/hyperledger/fabric-gateway/pkg/identity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"

	"ledger/indexer/internal/config"
)

type Client struct {
	conn    *grpc.ClientConn
	gateway *client.Gateway
	Network *client.Network
}

func Connect(cfg config.Config) (*Client, error) {
	conn, err := newGRPCConnection(cfg)
	if err != nil {
		return nil, err
	}

	id, err := newIdentity(cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}
	sign, err := newSign(cfg)
	if err != nil {
		conn.Close()
		return nil, err
	}

	gw, err := client.Connect(
		id,
		client.WithSign(sign),
		client.WithHash(hash.SHA256),
		client.WithClientConnection(conn),
	)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("fabricclient: connect gateway: %w", err)
	}

	return &Client{conn: conn, gateway: gw, Network: gw.GetNetwork(cfg.FabricChannelName)}, nil
}

func (c *Client) Close() {
	if c.gateway != nil {
		c.gateway.Close()
	}
	if c.conn != nil {
		c.conn.Close()
	}
}

func newGRPCConnection(cfg config.Config) (*grpc.ClientConn, error) {
	pem, err := os.ReadFile(cfg.FabricTLSCertPath)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: read TLS cert %s: %w", cfg.FabricTLSCertPath, err)
	}
	cert, err := identity.CertificateFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: parse TLS cert: %w", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(cert)
	creds := credentials.NewClientTLSFromCert(pool, cfg.FabricGatewayPeer)

	conn, err := grpc.NewClient(cfg.FabricPeerEndpoint, grpc.WithTransportCredentials(creds))
	if err != nil {
		return nil, fmt.Errorf("fabricclient: dial %s: %w", cfg.FabricPeerEndpoint, err)
	}
	return conn, nil
}

func newIdentity(cfg config.Config) (*identity.X509Identity, error) {
	pem, err := readFirstFile(cfg.FabricCertPath)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: read identity cert: %w", err)
	}
	cert, err := identity.CertificateFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: parse identity cert: %w", err)
	}
	id, err := identity.NewX509Identity(cfg.FabricMSPID, cert)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: build identity: %w", err)
	}
	return id, nil
}

func newSign(cfg config.Config) (identity.Sign, error) {
	pem, err := readFirstFile(cfg.FabricKeyPath)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: read private key: %w", err)
	}
	key, err := identity.PrivateKeyFromPEM(pem)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: parse private key: %w", err)
	}
	sign, err := identity.NewPrivateKeySign(key)
	if err != nil {
		return nil, fmt.Errorf("fabricclient: build signer: %w", err)
	}
	return sign, nil
}

func readFirstFile(dirPath string) ([]byte, error) {
	dir, err := os.Open(dirPath)
	if err != nil {
		return nil, err
	}
	defer dir.Close()

	names, err := dir.Readdirnames(1)
	if err != nil {
		return nil, err
	}
	return os.ReadFile(filepath.Join(dirPath, names[0]))
}
