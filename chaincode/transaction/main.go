// Command transaction is the Fabric chaincode entrypoint for the
// transaction/approval contract described in
// docs/Hybrid_PQC_Permissioned_Blockchain_PRD.md §5.1 and §7.
package main

import (
	"log"

	"github.com/hyperledger/fabric-contract-api-go/v2/contractapi"

	"ledger/chaincode/transaction/chaincode"
)

func main() {
	contract := new(chaincode.TransactionContract)
	cc, err := contractapi.NewChaincode(contract)
	if err != nil {
		log.Panicf("error creating transaction chaincode: %v", err)
	}
	if err := cc.Start(); err != nil {
		log.Panicf("error starting transaction chaincode: %v", err)
	}
}
