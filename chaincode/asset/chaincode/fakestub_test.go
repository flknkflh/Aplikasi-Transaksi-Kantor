package chaincode

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/hyperledger/fabric-chaincode-go/v2/shim"
	"github.com/hyperledger/fabric-protos-go-apiv2/ledger/queryresult"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// fakeStub is a minimal hand-rolled ChaincodeStubInterface for unit testing
// this contract, implementing only the methods the contract actually calls.
// See chaincode/transaction/chaincode/fakestub_test.go for the twin
// implementation and rationale.
type fakeEvent struct {
	Name    string
	Payload []byte
}

type fakeStub struct {
	shim.ChaincodeStubInterface
	state  map[string][]byte
	events []fakeEvent
}

func newFakeStub() *fakeStub {
	return &fakeStub{state: map[string][]byte{}}
}

func (f *fakeStub) SetEvent(name string, payload []byte) error {
	f.events = append(f.events, fakeEvent{Name: name, Payload: payload})
	return nil
}

func (f *fakeStub) GetState(key string) ([]byte, error) {
	return f.state[key], nil
}

func (f *fakeStub) PutState(key string, value []byte) error {
	f.state[key] = value
	return nil
}

func (f *fakeStub) DelState(key string) error {
	delete(f.state, key)
	return nil
}

const compositeKeyDelimiter = "\x00"

func buildCompositeKey(objectType string, attributes []string) string {
	var b strings.Builder
	b.WriteString(compositeKeyDelimiter)
	b.WriteString(objectType)
	b.WriteString(compositeKeyDelimiter)
	for _, a := range attributes {
		b.WriteString(a)
		b.WriteString(compositeKeyDelimiter)
	}
	return b.String()
}

func (f *fakeStub) CreateCompositeKey(objectType string, attributes []string) (string, error) {
	return buildCompositeKey(objectType, attributes), nil
}

func (f *fakeStub) SplitCompositeKey(compositeKey string) (string, []string, error) {
	trimmed := strings.Trim(compositeKey, compositeKeyDelimiter)
	parts := strings.Split(trimmed, compositeKeyDelimiter)
	if len(parts) == 0 {
		return "", nil, fmt.Errorf("invalid composite key %q", compositeKey)
	}
	return parts[0], parts[1:], nil
}

func (f *fakeStub) GetStateByPartialCompositeKey(objectType string, attributes []string) (shim.StateQueryIteratorInterface, error) {
	prefix := buildCompositeKey(objectType, attributes)
	keys := make([]string, 0)
	for k := range f.state {
		if strings.HasPrefix(k, prefix) {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)

	kvs := make([]*queryresult.KV, 0, len(keys))
	for _, k := range keys {
		kvs = append(kvs, &queryresult.KV{Key: k, Value: f.state[k]})
	}
	return &fakeIterator{items: kvs}, nil
}

func (f *fakeStub) GetTxTimestamp() (*timestamppb.Timestamp, error) {
	return timestamppb.New(time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)), nil
}

func (f *fakeStub) GetTxID() string {
	return "fake-tx-id"
}

type fakeIterator struct {
	items []*queryresult.KV
	pos   int
}

func (it *fakeIterator) HasNext() bool {
	return it.pos < len(it.items)
}

func (it *fakeIterator) Close() error {
	return nil
}

func (it *fakeIterator) Next() (*queryresult.KV, error) {
	if !it.HasNext() {
		return nil, fmt.Errorf("no more items")
	}
	item := it.items[it.pos]
	it.pos++
	return item, nil
}
