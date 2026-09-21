# Local prototype image: the receiver API + the CA operator binary in one
# small container. The CA is created on first boot into a persistent volume,
# so data survives `docker compose up --build` and `docker compose down`
# (only `down -v` wipes it). Build context is the repo root.

FROM golang:1.27 AS build
WORKDIR /src
COPY core/ ./core/
COPY server/ ./server/
COPY tools/ ./tools/
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    cd server && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api && \
    cd /src/tools/ca-admin && CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/ca-admin .

FROM alpine:3.20
# tzdata: the stamp caption prints the server date in Asia/Jakarta.
RUN apk add --no-cache ca-certificates curl tzdata
COPY --from=build /out/api /usr/local/bin/api
COPY --from=build /out/ca-admin /usr/local/bin/ca-admin
COPY deploy/local/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
EXPOSE 8099
ENTRYPOINT ["/entrypoint.sh"]
