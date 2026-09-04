# Plugin binary
BINARY   := spire-upstreamauthority-cagw
CMD_PATH := ./cmd/spire-upstreamauthority-cagw

# Architecture for the cross-compiled linux binary and the Docker image.
# Deliberately not named GOARCH: make inherits exported environment variables,
# so an unrelated GOARCH in the shell would silently retarget the build.
TARGET_ARCH ?= amd64

# Overrides the SPIRE server base image for the runnable Docker target. Leave
# empty to use the version pinned in the Dockerfile, which is authoritative.
SPIRE_SERVER_IMAGE ?=

# Pinned developer tooling. CI installs the same version via `make tools`, so
# this is the single place the linter version is defined.
GOLANGCI_LINT_VERSION ?= v2.12.2

# Resolved by path rather than PATH, so `make lint` always runs the version
# `make tools` installed. Override to use a linter from elsewhere.
GOLANGCI_LINT ?= $(shell go env GOPATH)/bin/golangci-lint

.PHONY: all build build-linux docker preflight run test test-integration lint tidy clean ci tools fmt-check tidy-check vulncheck

all: build

# --- Build targets ---

build:
	go build -mod=readonly -o bin/$(BINARY) $(CMD_PATH)

# Cross-compile a static linux binary for the container image.
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=$(TARGET_ARCH) \
		go build -mod=readonly -a -o bin/$(BINARY) $(CMD_PATH)

# --- Docker image target ---

# The image compiles the plugin itself, so a clean checkout is enough.
docker:
	docker build --no-cache --platform linux/$(TARGET_ARCH) \
		$(if $(SPIRE_SERVER_IMAGE),--build-arg SPIRE_SERVER_IMAGE=$(SPIRE_SERVER_IMAGE),) \
		-t custom-spire-server:upstreamauthority-plugin .

# --- Docker run target ---

# Host path to the PKCS#12 client credential bind-mounted into the container at
# the path referenced by `p12_file` in
# test/spire-server-upstreamauthority.conf. Shared with `make test-integration`.
CAGW_P12_FILE ?= $(CURDIR)/test/cagw-client.p12

# Host path to the CAGW server CA certificate (PEM) bind-mounted into the
# container at the path referenced by `server_ca_cert` in
# test/spire-server-upstreamauthority.conf. This must be the issuer of the cert
# CAGW *presents* on its TLS port, NOT the client-auth truststore CA.
# Capture it with:
#   openssl s_client -connect cagw.example.com:443 </dev/null 2>/dev/null | openssl x509 > test/cagw-server-ca.pem
#
# Set CAGW_SERVER_CA=system to skip the pinned-cert mount entirely and verify
# CAGW against the host system root store instead (use this when CAGW presents a
# publicly-trusted certificate).
CAGW_SERVER_CA ?= $(CURDIR)/test/cagw-server-ca.pem

# Derive the CA mount + config mode from CAGW_SERVER_CA. When "system", no PEM is
# mounted and server_ca_cert is set to "system" (OS trust store); otherwise the
# PEM is bind-mounted and preflight validates it.
ifeq ($(CAGW_SERVER_CA),system)
CA_MOUNT           :=
CAGW_SERVER_CA_MODE := system
PREFLIGHT_FILES    := $(CAGW_P12_FILE)
else
CA_MOUNT           := --mount type=bind,source=$(CAGW_SERVER_CA),target=/opt/spire/conf/cagw-server-ca.pem,readonly
CAGW_SERVER_CA_MODE :=
PREFLIGHT_FILES    := $(CAGW_P12_FILE) $(CAGW_SERVER_CA)
endif

# Password unlocking the PKCS#12 client credential. Passed into the container as
# an environment variable and expanded into `p12_password` in
# test/spire-server-upstreamauthority.conf at runtime via SPIRE's `-expandEnv`
# flag, keeping the secret out of the committed config and the built image.
CAGW_P12_PASSWORD ?=

# preflight validates the bind-mount sources BEFORE the (slow) docker build so
# we fail fast with a helpful message. Docker's `-v` flag silently creates a
# directory when the source path is missing, which then gets mounted over the
# expected file and breaks the plugin ("is a directory"); this guard plus the
# `--mount` form in `run` prevent that entirely.
preflight:
	@fail=0; \
	for f in $(PREFLIGHT_FILES); do \
		if [ ! -e "$$f" ]; then \
			echo "ERROR: bind-mount source does not exist: $$f"; fail=1; \
		elif [ -d "$$f" ]; then \
			echo "ERROR: bind-mount source is a directory, expected a file: $$f"; \
			echo "       (remove it with 'rmdir $$f' then recreate the file)"; fail=1; \
		fi; \
	done; \
	if [ "$(CAGW_SERVER_CA)" != "system" ] && { [ ! -e "$(CAGW_SERVER_CA)" ] || [ -d "$(CAGW_SERVER_CA)" ]; }; then \
		echo "       Capture the CAGW server CA with:"; \
		echo "         openssl s_client -connect cagw.example.com:443 </dev/null 2>/dev/null | openssl x509 > test/cagw-server-ca.pem"; \
		echo "       (or set CAGW_SERVER_CA=system to use the host system root store)"; \
	fi; \
	if [ -z "$(CAGW_P12_PASSWORD)" ]; then \
		echo "WARNING: CAGW_P12_PASSWORD is empty; the PKCS#12 file will not unlock."; \
	fi; \
	if [ "$$fail" != "0" ]; then exit 1; fi

# `--mount type=bind` (unlike `-v`) refuses to start when the source path does
# not exist, instead of silently creating a directory for it. CAGW_SERVER_CA_MODE
# is expanded into `server_ca_cert` in the config: empty => the mounted PEM
# default path; "system" => the host system root store.
run: preflight docker
	docker run --rm -ti -p 8081:8081 \
		-e CAGW_P12_PASSWORD=$(CAGW_P12_PASSWORD) \
		-e CAGW_SERVER_CA_MODE=$(CAGW_SERVER_CA_MODE) \
		--mount type=bind,source=$(CAGW_P12_FILE),target=/opt/spire/conf/cagw-client.p12,readonly \
		$(CA_MOUNT) \
		custom-spire-server:upstreamauthority-plugin -expandEnv

# --- Test / Lint / Tidy / Clean ---

test:
	go test ./...

# Runs the live integration test (TestIntegration_MintX509CA) against a real
# CAGW. Values are supplied via environment variables (see the README for the
# full list) — nothing is hardcoded here. For convenience, if a git-ignored env
# file exists it is sourced first; copy test/integration.env.example to that
# path and fill in your values. Override the path with INTEGRATION_ENV=...
INTEGRATION_ENV ?= test/integration.env

test-integration:
	@if [ -f "$(INTEGRATION_ENV)" ]; then \
		echo "Loading integration env from $(INTEGRATION_ENV)"; \
		set -a; . "$(INTEGRATION_ENV)"; set +a; \
	fi; \
	: "$${CAGW_URL:?required — export it or add it to $(INTEGRATION_ENV) (see README)}"; \
	: "$${CAGW_CA_ID:?required — export it or add it to $(INTEGRATION_ENV)}"; \
	: "$${CAGW_PROFILE:?required — export it or add it to $(INTEGRATION_ENV)}"; \
	: "$${CAGW_P12_FILE:?required — export it or add it to $(INTEGRATION_ENV)}"; \
	: "$${CAGW_P12_PASSWORD:?required — export it or add it to $(INTEGRATION_ENV)}"; \
	go test -v -count=1 -run 'TestIntegration_MintX509CA' ./pkg/upstreamauthority/

lint:
	@have=$$($(GOLANGCI_LINT) version --short 2>/dev/null); \
	if [ "$$have" != "$(GOLANGCI_LINT_VERSION:v%=%)" ]; then \
		echo "ERROR: golangci-lint $(GOLANGCI_LINT_VERSION) required, found '$${have:-none}'"; \
		echo "       run 'make tools' to install it"; \
		exit 1; \
	fi
	$(GOLANGCI_LINT) run ./...

tidy:
	go mod tidy

clean:
	rm -rf bin/

# --- Developer tooling and pre-push checks ---

# Installs the pinned linter into $(go env GOPATH)/bin. Fetched through the
# module proxy so the download is covered by the Go checksum database.
tools:
	go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_LINT_VERSION)

fmt-check:
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then \
		echo "ERROR: the following files are not gofmt-formatted:"; \
		echo "$$unformatted"; \
		exit 1; \
	fi

tidy-check:
	go mod tidy -diff

vulncheck:
	go run golang.org/x/vuln/cmd/govulncheck@latest ./...

# Runs exactly what CI runs. Use this before pushing.
ci: build fmt-check tidy-check test lint vulncheck
	@echo "All CI checks passed."
