## ── UpstreamAuthority plugin ─────────────────────────────────────────

ARG GO_IMAGE=golang:1.25-alpine
ARG ALPINE_IMAGE=alpine:3.22
# Kept in step with the spire-plugin-sdk version in go.mod.
ARG SPIRE_SERVER_IMAGE=ghcr.io/spiffe/spire-server:1.15.3

# Runs on the native build platform and cross-compiles, avoiding QEMU emulation.
FROM --platform=$BUILDPLATFORM ${GO_IMAGE} AS build

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

# Only the source trees are copied so local test credentials (test/*.p12,
# test/*.pem) can never end up in a build layer.
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY pkg/ ./pkg/

ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
go build -mod=readonly -o /out/spire-upstreamauthority-cagw ./cmd/spire-upstreamauthority-cagw

FROM ${ALPINE_IMAGE} AS prep

COPY --from=build /out/spire-upstreamauthority-cagw  /opt/spire/bin/spire-upstreamauthority-cagw
COPY test/spire-server-upstreamauthority.conf          /opt/spire/conf/server/server.conf

RUN CHECKSUM=$(sha256sum /opt/spire/bin/spire-upstreamauthority-cagw | awk '{print $1}') && \
  sed -i "/plugin_cmd/a\\    plugin_checksum = \"${CHECKSUM}\"" /opt/spire/conf/server/server.conf

FROM ${SPIRE_SERVER_IMAGE} AS upstreamauthority

COPY --from=prep /opt/spire/bin/spire-upstreamauthority-cagw   /opt/spire/bin/spire-upstreamauthority-cagw
COPY --from=prep /opt/spire/conf/server/server.conf              /opt/spire/conf/server/server.conf
