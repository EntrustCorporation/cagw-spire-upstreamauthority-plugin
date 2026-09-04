/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

package upstreamauthority_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	"github.com/spiffe/spire-plugin-sdk/plugintest"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"software.sslmate.com/src/go-pkcs12"

	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/pkg/upstreamauthority"
)

const testP12Password = "test-password"

// requireGRPCStatus asserts that err is a gRPC status error carrying the
// expected code and a message containing msgSubstr. This mirrors how SPIRE
// server inspects UpstreamAuthority errors (by status code) rather than
// matching the full error string, which is brittle.
func requireGRPCStatus(t *testing.T, err error, code codes.Code, msgSubstr string) {
	t.Helper()
	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok, "error is not a gRPC status: %v", err)
	assert.Equal(t, code, st.Code(), "unexpected gRPC status code")
	assert.Contains(t, st.Message(), msgSubstr)
}

// writeTestP12 generates a throwaway self-signed certificate and writes it to a
// temporary PKCS#12 file, returning its path. It is used to satisfy the plugin's
// mutual-TLS client setup during Configure without needing a real credential.
func writeTestP12(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spire-plugin-test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pfx, err := pkcs12.Modern.Encode(key, cert, nil, testP12Password)
	require.NoError(t, err)

	p12Path := filepath.Join(t.TempDir(), "client.p12")
	require.NoError(t, os.WriteFile(p12Path, pfx, 0o600))
	return p12Path
}

// writeTestServerCA generates a throwaway self-signed certificate and writes it
// as a PEM file, returning its path. It is used to satisfy the plugin's
// server_ca_cert trust setup during Configure without depending on the
// container-provided default file.
func writeTestServerCA(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "spire-plugin-test-server-ca"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	caPath := filepath.Join(t.TempDir(), "server-ca.pem")
	require.NoError(t, os.WriteFile(caPath, pemBytes, 0o600))
	return caPath
}

// validHCLConfig returns a minimal valid plugin_data block pointing at a freshly
// generated throwaway PKCS#12 client credential and server CA. The CAGW URL is
// intentionally unreachable; only the protocol/config layer is exercised here.
func validHCLConfig(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf(`
cagw_url       = "https://cagw.example.internal/cagw"
ca_id          = "test-partition~test-ca"
profile_id     = "spire-subca"
p12_file       = %q
p12_password   = %q
server_ca_cert = %q
`, writeTestP12(t), testP12Password, writeTestServerCA(t))
}

func newServedPlugin(t *testing.T) (upstreamauthorityv1.UpstreamAuthorityPluginClient, configv1.ConfigServiceClient) {
	t.Helper()
	plugin := new(upstreamauthority.Plugin)
	uaClient := new(upstreamauthorityv1.UpstreamAuthorityPluginClient)
	configClient := new(configv1.ConfigServiceClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: upstreamauthorityv1.UpstreamAuthorityPluginServer(plugin),
		PluginClient: uaClient,
		ServiceServers: []pluginsdk.ServiceServer{
			configv1.ConfigServiceServer(plugin),
		},
		ServiceClients: []pluginsdk.ServiceClient{
			configClient,
		},
	})
	return *uaClient, *configClient
}

func TestPlugin_NotConfigured(t *testing.T) {
	plugin := new(upstreamauthority.Plugin)
	uaClient := new(upstreamauthorityv1.UpstreamAuthorityPluginClient)

	plugintest.ServeInBackground(t, plugintest.Config{
		PluginServer: upstreamauthorityv1.UpstreamAuthorityPluginServer(plugin),
		PluginClient: uaClient,
	})

	stream, err := uaClient.MintX509CAAndSubscribe(context.Background(), &upstreamauthorityv1.MintX509CARequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	requireGRPCStatus(t, err, codes.FailedPrecondition, "plugin not configured")
}

func TestPlugin_PublishJWTKeyAndSubscribe_Unimplemented(t *testing.T) {
	uaClient, configClient := newServedPlugin(t)

	ctx := context.Background()
	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  validHCLConfig(t),
	})
	require.NoError(t, err)
	require.True(t, uaClient.IsInitialized())

	stream, err := uaClient.PublishJWTKeyAndSubscribe(ctx, &upstreamauthorityv1.PublishJWTKeyRequest{})
	require.NoError(t, err)
	_, err = stream.Recv()
	requireGRPCStatus(t, err, codes.Unimplemented, "JWT key publishing is not supported")
}

func TestPlugin_Configure_MissingFields(t *testing.T) {
	_, configClient := newServedPlugin(t)
	ctx := context.Background()

	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  `cagw_url = "https://cagw.example.internal/cagw"`,
	})
	requireGRPCStatus(t, err, codes.InvalidArgument, "missing required fields")
}

func TestPlugin_Configure_InvalidHCL(t *testing.T) {
	_, configClient := newServedPlugin(t)
	ctx := context.Background()

	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  `{{{not valid hcl`,
	})
	requireGRPCStatus(t, err, codes.InvalidArgument, "failed to decode configuration")
}

// An unparseable or non-positive request_timeout must be rejected at configure
// time rather than silently falling back to the default, which would leave the
// operator believing a timeout they set is in effect.
func TestPlugin_Configure_InvalidRequestTimeout(t *testing.T) {
	for _, value := range []string{"soon", "0s", "-5s"} {
		t.Run(value, func(t *testing.T) {
			_, configClient := newServedPlugin(t)

			_, err := configClient.Configure(context.Background(), &configv1.ConfigureRequest{
				CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
				HclConfiguration: `
					cagw_url        = "https://cagw.example.com/cagw"
					ca_id           = "my-partition~spire-ca-id"
					profile_id      = "basic-ca-subord"
					p12_file        = "/nonexistent.p12"
					p12_password    = "secret"
					request_timeout = "` + value + `"
				`,
			})
			requireGRPCStatus(t, err, codes.InvalidArgument, "request_timeout")
		})
	}
}

// TestPlugin_Configure_SystemTrustStore verifies that server_ca_cert = "system"
// configures successfully without any CA PEM file on disk — the plugin verifies
// the CAGW server certificate against the host system root store instead of a
// pinned file.
func TestPlugin_Configure_SystemTrustStore(t *testing.T) {
	uaClient, configClient := newServedPlugin(t)
	ctx := context.Background()

	hcl := fmt.Sprintf(`
cagw_url       = "https://cagw.example.internal/cagw"
ca_id          = "test-partition~test-ca"
profile_id     = "spire-subca"
p12_file       = %q
p12_password   = %q
server_ca_cert = "system"
`, writeTestP12(t), testP12Password)

	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  hcl,
	})
	require.NoError(t, err)
	require.True(t, uaClient.IsInitialized())
}

// Integration test — skipped unless env vars are set.
// Run with:
//
//	CAGW_URL=... CAGW_CA_ID=... CAGW_PROFILE=... \
//	CAGW_P12_FILE=... CAGW_P12_PASSWORD=... \
//	[CAGW_SERVER_CA=...] [CAGW_CA_CLIENT_ID=...] \
//	go test ./pkg/upstreamauthority/ -run TestIntegration_MintX509CA -v
func TestIntegration_MintX509CA(t *testing.T) {
	env := map[string]string{
		"cagw_url":     os.Getenv("CAGW_URL"),
		"ca_id":        os.Getenv("CAGW_CA_ID"),
		"profile_id":   os.Getenv("CAGW_PROFILE"),
		"p12_file":     os.Getenv("CAGW_P12_FILE"),
		"p12_password": os.Getenv("CAGW_P12_PASSWORD"),
	}
	for k, v := range env {
		if v == "" {
			t.Skipf("skipping integration test: env var for %q not set", k)
		}
	}

	// server_ca_cert defaults to "system" (host system root store) when
	// CAGW_SERVER_CA is unset, so the test works out-of-the-box against a
	// publicly-trusted CAGW. Set it to a PEM path for a self-signed CAGW.
	serverCACert := os.Getenv("CAGW_SERVER_CA")
	if serverCACert == "" {
		serverCACert = "system"
	}

	hclConfig := fmt.Sprintf(`
        cagw_url       = %q
        ca_id          = %q
        profile_id     = %q
        p12_file       = %q
        p12_password   = %q
        server_ca_cert = %q
        ca_client_id   = %q
    `, env["cagw_url"], env["ca_id"], env["profile_id"],
		env["p12_file"], env["p12_password"],
		serverCACert, os.Getenv("CAGW_CA_CLIENT_ID"))

	uaClient, configClient := newServedPlugin(t)
	ctx := context.Background()

	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  hclConfig,
	})
	require.NoError(t, err)

	// Generate a throwaway EC key + CSR — same key type SPIRE itself uses.
	// SPIRE's upstream CSR always carries an identity (a subject and/or the
	// trust-domain SPIFFE URI SAN); CAGW's CA profiles reject a request with no
	// subject name at all ("No SubjectName provided in Request or CSR"), so the
	// CSR here mirrors what SPIRE sends.
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "SPIRE Server CA"},
		URIs:    []*url.URL{{Scheme: "spiffe", Host: "example.org"}},
	}, key)
	require.NoError(t, err)

	stream, err := uaClient.MintX509CAAndSubscribe(ctx, &upstreamauthorityv1.MintX509CARequest{
		Csr: csrDER,
	})
	require.NoError(t, err)

	resp, err := stream.Recv()
	require.NoError(t, err)

	assert.NotEmpty(t, resp.X509CaChain, "expected at least the signed CA cert")
	assert.NotEmpty(t, resp.UpstreamX509Roots, "expected at least one upstream root")

	// Parse and sanity-check the first cert in the chain (the one SPIRE will use as its CA).
	cert, err := x509.ParseCertificate(resp.X509CaChain[0].Asn1)
	require.NoError(t, err)
	assert.True(t, cert.IsCA, "signed cert should have IsCA=true")
	t.Logf("signed CA subject: %s", cert.Subject)
	t.Logf("chain length: %d, roots: %d", len(resp.X509CaChain), len(resp.UpstreamX509Roots))
}
