// Command asset is the Fabric chaincode entrypoint for the asset custody
// contract described in docs/Hybrid_PQC_Permissioned_Blockchain_PRD.md §5.2.
package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"

	"ledger/chaincode/asset/chaincode"
)

func main() {
	contract := new(chaincode.AssetContract)
	cc, err := contractapi.NewChaincode(contract)
	if err != nil {
		log.Panicf("error creating asset chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("error starting asset chaincode: %v", err)
	}
}
