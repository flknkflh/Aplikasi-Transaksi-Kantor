# Pure Go (no cgo): ML-DSA-65 verification uses the Go standard library's
# crypto/mldsa (Go 1.27+). See api/Dockerfile for why GOWORK=off.
FROM golang:1.27-bookworm AS build
ENV GOWORK=off
ENV CGO_ENABLED=0
WORKDIR /workspace
COPY crypto ./crypto
COPY audit-service ./audit-service
RUN cd audit-service && go build -trimpath -ldflags="-s -w" -o /out/audit-service .

FROM gcr.io/distroless/static-debian12
COPY --from=build /out/audit-service /audit-service
ENTRYPOINT ["/audit-service"]
