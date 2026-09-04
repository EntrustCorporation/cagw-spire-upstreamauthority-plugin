# CAGW SPIRE UpstreamAuthority Plugin

A [SPIRE](https://spiffe.io/spire/) server external `UpstreamAuthority` plugin
that signs SPIRE's intermediate CA certificates using an Entrust CA Gateway
(CAGW) certificate authority.

| Plugin | Binary | Description |
|--------|--------|-------------|
| **UpstreamAuthority** | `spire-upstreamauthority-cagw` | Signs SPIRE CA certificates using a CAGW CA |

## Supported SPIRE versions

Built against `spire-plugin-sdk` v1.15.3 and tested against SPIRE server 1.15.3.
Other 1.15.x releases are expected to work; earlier lines are not tested.

The SDK version in [go.mod](./go.mod) and the SPIRE server image pinned in the
[Dockerfile](./Dockerfile) are kept on the same release line.

## Supported platforms

`linux/amd64` and `linux/arm64`. The plugin is a static binary built with
`CGO_ENABLED=0`, and the SPIRE server base image is published for both.

`make build` builds for the host platform. `make build-linux` and `make docker`
target `linux/amd64` by default; select the other with `TARGET_ARCH`:

```bash
make docker TARGET_ARCH=arm64
```

## Build

```bash
# Build the plugin binary (host platform)
make build
```

The binary is placed in `bin/`.

## Test with SPIRE

1. Update the config in [test/spire-server-upstreamauthority.conf](./test/spire-server-upstreamauthority.conf) as needed. See the [Configuration](#configuration) section for the available `plugin_data` fields.

2. Build the linux binary, build the Docker image, and run the container:

    ```bash
    make run
    ```

   The `run` target bind-mounts the PKCS#12 client credential and CAGW server CA
   certificate into the container and expands the `CAGW_P12_PASSWORD` environment
   variable into the plugin config via SPIRE's `-expandEnv` flag. Override the
   defaults as needed:

    ```bash
    make run \
      CAGW_P12_FILE=/path/to/cagw-client.p12 \
      CAGW_SERVER_CA=/path/to/cagw-server-ca.pem \
      CAGW_P12_PASSWORD=your-p12-password
    ```

   > **Obtaining the CAGW server TLS certificate.** `CAGW_SERVER_CA` must contain
   > the certificate CAGW presents on its TLS port, *not* the client-auth truststore CA.
   > Capture it straight from the live endpoint with `openssl` — adjust the
   > host/port to match your `cagw_url`:
   >
   > ```bash
   > openssl s_client -connect cagw.example.com:443 </dev/null 2>/dev/null \
   >   | openssl x509 > test/cagw-server-ca.pem
   > ```
   >
   > This file is git-ignored. If the host path is missing when you run the
   > container, the `run` target fails fast rather than letting Docker create a
   > directory in its place.
   >
   > **Publicly-trusted CAGW.** If CAGW presents a publicly- (or otherwise
   > system-) trusted certificate, skip the capture and the mount entirely with
   > `make run CAGW_SERVER_CA=system` — the plugin then verifies CAGW against the
   > host system root store.

## Configuration

`plugin_data` fields:

| Field | Description |
|-------|-------------|
| `cagw_url` | CA Gateway base URL, including the base path (e.g. `https://cagw.example.com/cagw`) |
| `ca_id` | Full CA Gateway certificate authority ID used for enrollment, in the form `<partition_id>~<ca_id>` |
| `profile_id` | Certificate profile to use for signing the issued CA certificates |
| `p12_file` | Path to the PKCS#12 file with the CAGW client certificate and key (mutual TLS). Defaults to `/opt/spire/conf/cagw-client.p12` since this is where the PKCS#12 file will be bind-mounted by the docker run command when the plugin is run in the docker container |
| `p12_password` | Password that unlocks the PKCS#12 file. Reference an environment variable rather than writing the password into the config file — see below |
| `server_ca_cert` | _(optional)_ How to verify the CAGW server's TLS certificate. Either a **path** to a PEM file used as the sole trusted root, or the literal value `"system"` to verify against the host system root store (use this when CAGW presents a publicly-trusted certificate). When unset, defaults to `/opt/spire/conf/cagw-server-ca.pem` where the file will be bind-mounted by the docker run command when the plugin is run in the docker container |
| `ca_client_id` | _(optional)_ Value sent in the `ca-client-id` header on every CAGW request. Omit unless your CAGW deployment requires it |
| `request_timeout` | _(optional)_ Bounds each CAGW request end-to-end — connection, TLS handshake and response read — as a Go duration string such as `"45s"` or `"2m"`. Defaults to `30s`. Raise it if your CA is slow to sign, for example when backed by an HSM under load |

Example (pinned CA file):

```hcl
UpstreamAuthority "cagw" {
    plugin_cmd = "/opt/spire/bin/spire-upstreamauthority-cagw"
    plugin_data {
        cagw_url       = "https://cagw.example.com/cagw"
        ca_id          = "my-partition~spire-ca-id"
        profile_id     = "basic-ca-subord"
        p12_file       = "/opt/spire/conf/cagw-client.p12"
        p12_password   = "${CAGW_P12_PASSWORD}"
        server_ca_cert = "/opt/spire/conf/cagw-server-ca.pem"
    }
}
```

> **Keep the PKCS#12 password out of the config file.** `${CAGW_P12_PASSWORD}`
> above is expanded from the environment at startup by SPIRE's `-expandEnv`
> flag, so the secret is supplied at runtime rather than stored alongside the
> configuration. A literal password works but should be avoided.

For a CAGW that presents a **publicly-trusted** certificate, set
`server_ca_cert = "system"` and omit the CA PEM entirely:

```hcl
        server_ca_cert = "system"   # verify against the host system root store
```

### Verifying the plugin binary (optional)

This project is distributed as source. Build the plugin yourself with
`make build` rather than obtaining a binary from elsewhere.

`plugin_checksum` is an optional SPIRE setting. When set, SPIRE compares the
SHA-256 of the plugin binary against it and refuses to load the plugin if they
differ. When it is not set, SPIRE loads the binary without checking it.

**You do not need to set it in the usual cases:**

- **Running with `make run`.** The Docker image computes the checksum and inserts
  it into the config for you.
- **Building and running on the same machine.** The binary is the one you just
  built, so there is nothing in between to guard against.

Set it when the binary is deployed somewhere other than where it was built, so
that corruption or tampering in transit is detected. Compute it with:

```bash
sha256sum bin/spire-upstreamauthority-cagw   # macOS: shasum -a 256
```

then pin it alongside `plugin_cmd`:

```hcl
UpstreamAuthority "cagw" {
    plugin_cmd      = "/opt/spire/bin/spire-upstreamauthority-cagw"
    plugin_checksum = "<sha256 of the binary>"
    plugin_data {
        # ...
    }
}
```

## What to observe

| What SPIRE logs | What it means |
|---|---|
| `plugin loaded` | Plugin subprocess started |
| `Minting X509 CA` | `MintX509CAAndSubscribe` was called |
| `Successfully rotated X.509 CA` | CAGW signed the CSR and SPIRE accepted the chain |
| `UpstreamAuthority plugin does not support JWT-SVIDs` | Expected — see [Limitations](#limitations) |
| Error with `upstreamauthority(cagw):` prefix | The gRPC status returned by the plugin |

Verify the resulting CA chain:

```bash
spire-server bundle show -format pem
spire-server localauthority x509 show
```
The above can be run inside the docker container with a docker exec command, for example:
```bash
docker exec -it <container id> /opt/spire/bin/spire-server localauthority x509 show
```

## Limitations

**JWT-SVIDs are not supported.** The plugin does not publish JWT signing keys
upstream, so SPIRE logs a warning at startup — `UpstreamAuthority plugin does not
support JWT-SVIDs`. This is expected and does not indicate a misconfiguration.
X.509 SVIDs are unaffected, but workloads relying on JWT-SVIDs to communicate
outside the trust domain may be affected.

**Upstream root changes are picked up at the next SPIRE CA rotation**, not
immediately. The plugin sends a single response and closes the stream rather than
subscribing to upstream root updates, which the SPIRE plugin SDK permits. SPIRE
reopens the stream at its next X.509 CA rotation, and the new roots are read
then.

## Test

Run the whole suite (unit + mock-backed tests):

```bash
make test
# equivalent:
go test ./...
```

Run just the plugin package, verbose:

```bash
go test -v ./pkg/upstreamauthority/
```

### Pre-push checks

`make ci` runs exactly what CI runs — build, formatting, module tidiness, tests,
lint, and a vulnerability scan:

```bash
make tools   # once: installs the pinned golangci-lint
make ci
```

The tests are organised in three layers:

| Layer | File | What it covers |
|-------|------|----------------|
| Protocol / config | `pkg/upstreamauthority/plugin_test.go` | Plugin loads and serves over gRPC; not-configured, unimplemented JWT, missing fields, invalid HCL |
| Pure logic | `pkg/upstreamauthority/plugin_internal_test.go` | `buildChain` / `isSelfSigned` — leaf/intermediate/root splitting, de-duplication, error cases |
| RPC behaviour | `pkg/upstreamauthority/mint_test.go` | Full `MintX509CAAndSubscribe` flow against a mock CAGW (`httptest` TLS server) — happy path plus enrollment/CA error branches |

### Integration test (live CAGW)

An optional integration test against a real CAGW instance is included in
`pkg/upstreamauthority/plugin_test.go` (`TestIntegration_MintX509CA`). It is
**skipped** unless all required environment variables are set:

| Env var | Required | Description |
|---------|----------|-------------|
| `CAGW_URL` | yes | CAGW base URL including the base path, e.g. `https://cagw.example.com/cagw` |
| `CAGW_CA_ID` | yes | Full CA ID, `<partition_id>~<ca_id>` |
| `CAGW_PROFILE` | yes | Certificate profile to sign with |
| `CAGW_P12_FILE` | yes | Path to the PKCS#12 client credential (mutual TLS) |
| `CAGW_P12_PASSWORD` | yes | Password unlocking the PKCS#12 file |
| `CAGW_SERVER_CA` | no | How to verify CAGW's TLS certificate: a PEM path, or `system` for the host root store. **Defaults to `system` when unset** |

Example — the test runs on the host rather than inside a container, so
`CAGW_URL` must be reachable from the host (use `127.0.0.1` for a CAGW
running locally):

```bash
CAGW_URL="https://127.0.0.1/cagw" \
CAGW_CA_ID="my-partition~spire-ca-id" \
CAGW_PROFILE="basic-ca-subord" \
CAGW_P12_FILE="/path/to/cagw-client.p12" \
CAGW_P12_PASSWORD="your-p12-password" \
CAGW_SERVER_CA="$PWD/test/cagw-server-ca.pem" \
go test -v -run 'TestIntegration_MintX509CA' ./pkg/upstreamauthority/
```

Or use the `make test-integration` target, which reads the same variables from
the environment (nothing is hardcoded). For convenience it also sources a
git-ignored env file if present — copy the template and fill it in:

```bash
cp test/integration.env.example test/integration.env   # git-ignored
$EDITOR test/integration.env                            # fill in your values
make test-integration
```

Point it at a different file with
`make test-integration INTEGRATION_ENV=/path/to/other.env`.

Notes:
- `CAGW_SERVER_CA` defaults to `system` (host system root store) when
  unset, so the test works out-of-the-box against a publicly-trusted CAGW. For a
  **self-signed** CAGW set it to a
  PEM containing the certificate CAGW presents on its TLS port. Capture it with:
  ```bash
  openssl s_client -connect cagw.example.com:443 </dev/null 2>/dev/null | openssl x509 > test/cagw-server-ca.pem
  ```
- If any required variable is missing, the test reports
  `skipping integration test: env var for ... not set` and passes without running.

## License

This plugin is licensed under the [Apache License 2.0](./LICENSE). See
[NOTICE](./NOTICE) for the accompanying attribution notice.

## Dependencies & Licenses

This project distributes source only. The Go modules it depends on are fetched
at build time via [`go.mod`](./go.mod) and [`go.sum`](./go.sum), are not
redistributed by this repository, and are used unmodified.

[`go.mod`](./go.mod) is the authoritative dependency list: direct dependencies
appear in the `require` block, transitive ones as `// indirect` entries. To
produce a current license report for a specific build, use
[`go-licenses`](https://github.com/google/go-licenses):

```bash
go install github.com/google/go-licenses@latest
go-licenses report ./...
```

See [NOTICE](./NOTICE) for the attribution notice accompanying the
[Apache License 2.0](./LICENSE).

