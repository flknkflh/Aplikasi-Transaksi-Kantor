# Builds and runs the API service. Pure Go (no cgo): ML-DSA-65 comes from the
# Go standard library's crypto/mldsa (Go 1.27+), so there is no C library to
# build or ship.
FROM golang:1.27-bookworm AS build

# GOWORK=off: api/go.mod's own `replace ledger/crypto => ../crypto` is
# enough to resolve the local crypto module; go.work also lists the
# chaincode modules, which this build context deliberately doesn't include
# (chaincode has no dependency on api/ or ledger/crypto — see
# docs/adr/0001-fase1-spike-scope.md decision #1), so workspace mode would
# fail here looking for directories that were never copied in.
ENV GOWORK=off
ENV CGO_ENABLED=0
WORKDIR /workspace
COPY crypto ./crypto
COPY api ./api
RUN cd api && go build -trimpath -ldflags="-s -w" -o /out/api .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/api /api
ENTRYPOINT ["/api"]
