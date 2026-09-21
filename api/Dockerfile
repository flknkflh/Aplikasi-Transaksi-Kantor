# Builds and runs the API service. Needs liboqs at both build time (cgo,
# ML-DSA-65 via ledger/crypto) and runtime (the resulting binary dynamically
# links libcrypto/liboqs). The liboqs build steps mirror
# infra/Dockerfile.godev exactly — duplicated here (rather than FROM'd from
# it) so `docker compose build` can build this service from a clean checkout
# without depending on a separately pre-built local image tag.
FROM golang:1.27-bookworm AS build

ARG LIBOQS_VERSION=0.16.0

RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build libssl-dev git pkg-config ca-certificates \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --branch "${LIBOQS_VERSION}" --depth=1 https://github.com/open-quantum-safe/liboqs /tmp/liboqs \
    && cmake -S /tmp/liboqs -B /tmp/liboqs/build -GNinja -DBUILD_SHARED_LIBS=ON -DCMAKE_BUILD_TYPE=Release \
    && cmake --build /tmp/liboqs/build --parallel \
    && cmake --build /tmp/liboqs/build --target install \
    && rm -rf /tmp/liboqs \
    && ldconfig

RUN printf '%s\n' \
        'LIBOQS_INCLUDE_DIR=/usr/local/include' \
        'LIBOQS_LIB_DIR=/usr/local/lib' \
        '' \
        'Name: liboqs-go' \
        'Description: Go bindings for liboqs' \
        "Version: ${LIBOQS_VERSION}" \
        'Cflags: -I${LIBOQS_INCLUDE_DIR}' \
        'Libs: -L${LIBOQS_LIB_DIR} -loqs' \
        > /usr/local/lib/pkgconfig/liboqs-go.pc

ENV LD_LIBRARY_PATH=/usr/local/lib
ENV PKG_CONFIG_PATH=/usr/local/lib/pkgconfig
ENV CGO_ENABLED=1

# GOWORK=off: api/go.mod's own `replace ledger/crypto => ../crypto` is
# enough to resolve the local crypto module; go.work also lists the
# chaincode modules, which this build context deliberately doesn't include
# (chaincode has no dependency on api/ or ledger/crypto — see
# docs/adr/0001-fase1-spike-scope.md decision #1), so workspace mode would
# fail here looking for directories that were never copied in.
ENV GOWORK=off
WORKDIR /workspace
COPY crypto ./crypto
COPY api ./api
RUN cd api && go build -o /out/api .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib
COPY --from=build /out/api /usr/local/bin/api
ENTRYPOINT ["/usr/local/bin/api"]
