module ledger/api

go 1.27

require (
	github.com/go-chi/chi/v5 v5.3.2
	github.com/google/uuid v1.6.0
	github.com/hyperledger/fabric-gateway v1.12.1
	github.com/jackc/pgx/v5 v5.11.0
	github.com/minio/minio-go/v7 v7.3.0
	google.golang.org/grpc v1.83.2
	ledger/crypto v0.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/hyperledger/fabric-protos-go-apiv2 v0.3.7 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/klauspost/compress v1.19.2 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/klauspost/crc32 v1.3.0 // indirect
	github.com/miekg/pkcs11 v1.1.2 // indirect
	github.com/minio/crc64nvme v1.1.1 // indirect
	github.com/minio/md5-simd v1.1.2 // indirect
	github.com/philhofer/fwd v1.2.0 // indirect
	github.com/rs/xid v1.6.0 // indirect
	github.com/tinylib/msgp v1.6.4 // indirect
	github.com/zeebo/xxh3 v1.1.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sync v0.23.0 // indirect
	golang.org/x/sys v0.48.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260526163538-3dc84a4a5aaa // indirect
	google.golang.org/protobuf v1.36.12 // indirect
	gopkg.in/ini.v1 v1.67.3 // indirect
)

// Needed alongside go.work's `use` directive: without it, `go mod tidy`'s
// deep test-dependency graph walk (e.g. through grpc's internal test
// packages) tries to resolve "ledger/crypto" from a real module proxy
// instead of applying the workspace-local override, and fails since it
// isn't a real, published module path.
replace ledger/crypto => ../crypto
