# No liboqs/cgo needed — the indexer never signs or verifies anything (see
# the package doc in indexer/main.go). It also has no local sibling-module
# dependency (unlike api/ and audit-service/, it doesn't import ledger/crypto),
# so unlike their Dockerfiles this one builds indexer/ standalone without
# go.work — unset GOWORK explicitly so the workspace file two levels up in
# the build context (if any) is never picked up by accident.
FROM golang:1.27-bookworm AS build
ENV GOWORK=off
WORKDIR /workspace
COPY indexer ./indexer
RUN cd indexer && CGO_ENABLED=0 go build -o /out/indexer .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/indexer /indexer
ENTRYPOINT ["/indexer"]
