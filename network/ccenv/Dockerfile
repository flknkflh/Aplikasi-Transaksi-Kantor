# Fabric 2.5.16's chaincode build image ships Go 1.26.4, but this repo's
# chaincode (and its dependencies, e.g. fabric-contract-api-go v2.2.3) require
# Go >= 1.26.7 / the go.mod says 1.27. The stock image would have to download a
# newer toolchain from the network on every chaincode build (slow, and it fails
# behind a restrictive VPN/proxy). This derives an image with Go 1.27 baked in
# and bootstrap.sh tags it over the local hyperledger/fabric-ccenv tags so the
# peer's builder picks it up. Only the local tags change; the base image layers
# are untouched.
ARG FABRIC_VERSION=2.5.16
FROM golang:1.27-bookworm AS go
FROM ghcr.io/hyperledger/fabric-ccenv:${FABRIC_VERSION}
# Replace, do not overlay: a merged 1.26+1.27 GOROOT keeps stale std files and breaks the build.
USER root
RUN rm -rf /usr/local/go
COPY --from=go /usr/local/go /usr/local/go
# the stock image runs the build as this user
USER chaincode
