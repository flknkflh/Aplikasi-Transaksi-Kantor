# Multi-stage build for the receiver API (Rencana V1 §22, §27).
# Build context is the repository root: server/go.mod has `replace
# example.internal/pqc-pdf-sign/core => ../core`, so both trees must be present.

FROM golang:1.27 AS build
WORKDIR /src
COPY core/ ./core/
COPY server/ ./server/
WORKDIR /src/server
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/api /api
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/api"]
CMD ["--addr", ":8080"]
