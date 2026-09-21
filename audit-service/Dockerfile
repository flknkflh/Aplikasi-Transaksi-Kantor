# See api/Dockerfile for why the liboqs build steps are duplicated here
# rather than shared via FROM.
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

# GOWORK=off: see api/Dockerfile for why this is enough (audit-service's own
# go.mod replace directive resolves ../crypto without needing the workspace
# file or the chaincode modules it also lists).
ENV GOWORK=off
WORKDIR /workspace
COPY crypto ./crypto
COPY audit-service ./audit-service
RUN cd audit-service && go build -o /out/audit-service .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=build /usr/local/lib/liboqs.so* /usr/local/lib/
RUN ldconfig
ENV LD_LIBRARY_PATH=/usr/local/lib
COPY --from=build /out/audit-service /usr/local/bin/audit-service
ENTRYPOINT ["/usr/local/bin/audit-service"]
