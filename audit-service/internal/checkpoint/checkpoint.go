// Package checkpoint records periodic anchors of the ledger's current block
// height/hash into `audit_checkpoint` (PRD §6, §15), queried from the
// channel's system chaincode (qscc) rather than derived from Postgres, so
// the checkpoint is itself independently verifiable against the ledger.
package checkpoint

import (
	"context"
	"encoding/hex"
	"fmt"

	"github.com/google/uuid"
	"github.com/hyperledger/fabric-gateway/pkg/client"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/proto"

	"github.com/hyperledger/fabric-protos-go-apiv2/common"
)

// Create queries qscc's GetChainInfo for channelName and inserts a new
// audit_checkpoint row.
func Create(ctx context.Context, db *pgxpool.Pool, network *client.Network, channelName string) (blockNumber uint64, blockHash string, err error) {
	qscc := network.GetContract("qscc")
	result, err := qscc.EvaluateTransaction("GetChainInfo", channelName)
	if err != nil {
		return 0, "", fmt.Errorf("checkpoint: query qscc GetChainInfo: %w", err)
	}

	var info common.BlockchainInfo
	if err := proto.Unmarshal(result, &info); err != nil {
		return 0, "", fmt.Errorf("checkpoint: unmarshal BlockchainInfo: %w", err)
	}

	blockNumber = info.GetHeight() - 1 // height is "next block number"; the latest committed block is height-1
	blockHash = hex.EncodeToString(info.GetCurrentBlockHash())

	if _, err := db.Exec(ctx, `
		INSERT INTO audit_checkpoint (id, block_number, block_hash, tx_count, note)
		VALUES ($1, $2, $3, 0, 'qscc GetChainInfo')`,
		uuid.NewString(), int64(blockNumber), blockHash,
	); err != nil {
		return 0, "", fmt.Errorf("checkpoint: insert audit_checkpoint: %w", err)
	}

	return blockNumber, blockHash, nil
}
