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
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// b64 returns the standard Base64 encoding of DER bytes, matching the encoding
// CAGW uses for certificate data on the wire.
func b64(der []byte) string {
	return base64.StdEncoding.EncodeToString(der)
}

// makeCA generates a self-signed CA certificate (a root).
func makeCA(t *testing.T, cn string) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()
	return makeChildCA(t, cn, nil, nil)
}

// makeChildCA generates a CA certificate signed by parent. When parent is nil
// the certificate is self-signed (a root).
func makeChildCA(t *testing.T, cn string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, []byte, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}

	signer, signerKey := tmpl, key // self-signed by default
	if parent != nil {
		signer, signerKey = parent, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert, der, key
}

// writeServerCAFromTS writes the TLS certificate presented by ts to a temporary
// PEM file so the plugin's mTLS client can be configured to trust it via
// server_ca_cert.
func writeServerCAFromTS(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	path := filepath.Join(t.TempDir(), "cagw-server-ca.pem")
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

// mockCAGW starts a TLS test server that mimics the two CAGW endpoints the
// plugin uses. enrollHandler serves the enrollment POST; caHandler serves the
// certificate-authority GET. Either may be nil to fall back to a 200 with an
// empty JSON object.
func mockCAGW(t *testing.T, enrollHandler, caHandler http.HandlerFunc) *httptest.Server {
	t.Helper()
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/enrollments"):
			if enrollHandler != nil {
				enrollHandler(w, r)
				return
			}
		case r.Method == http.MethodGet:
			if caHandler != nil {
				caHandler(w, r)
				return
			}
		}
		_, _ = w.Write([]byte(`{}`))
	}))
	t.Cleanup(ts.Close)
	return ts
}

// hclConfigForServer builds a valid plugin_data block pointing at the mock CAGW
// server, trusting its TLS certificate and presenting a throwaway client
// credential.
func hclConfigForServer(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	return fmt.Sprintf(`
cagw_url       = %q
ca_id          = "test-partition~test-ca"
profile_id     = "spire-subca"
p12_file       = %q
p12_password   = %q
server_ca_cert = %q
`, ts.URL, writeTestP12(t), testP12Password, writeServerCAFromTS(t, ts))
}

// newCSR returns a DER-encoded PKCS#10 CSR suitable for MintX509CARequest.
func newCSR(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "spire-server"},
	}, key)
	require.NoError(t, err)
	return csrDER
}

// configureAndMint configures the served plugin against the mock server and
// invokes MintX509CAAndSubscribe, returning the first stream response (or the
// receive error).
func configureAndMint(t *testing.T, ts *httptest.Server) (*upstreamauthorityv1.MintX509CAResponse, error) {
	t.Helper()
	uaClient, configClient := newServedPlugin(t)
	ctx := context.Background()

	_, err := configClient.Configure(ctx, &configv1.ConfigureRequest{
		CoreConfiguration: &configv1.CoreConfiguration{TrustDomain: "example.org"},
		HclConfiguration:  hclConfigForServer(t, ts),
	})
	require.NoError(t, err)

	stream, err := uaClient.MintX509CAAndSubscribe(ctx, &upstreamauthorityv1.MintX509CARequest{
		Csr: newCSR(t),
	})
	require.NoError(t, err)
	return stream.Recv()
}

func TestMintX509CA_Success(t *testing.T) {
	// Upstream PKI: root -> intermediate (the issuing CA) -> leaf (issued to SPIRE).
	root, rootDER, rootKey := makeCA(t, "test-root")
	inter, interDER, interKey := makeChildCA(t, "test-intermediate", root, rootKey)
	_, leafDER, _ := makeChildCA(t, "spire-ca", inter, interKey)

	enroll := func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enrollment": map[string]any{
				"status": "ISSUED",
				"body":   b64(leafDER),
			},
		})
	}
	getCA := func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ca": map[string]any{
				"certificate": map[string]any{"certificateData": b64(interDER)},
				"chain":       []map[string]any{{"certificateData": b64(rootDER)}},
			},
		})
	}

	resp, err := configureAndMint(t, mockCAGW(t, enroll, getCA))
	require.NoError(t, err)

	// x509CaChain = [leaf, intermediate]; upstreamX509Roots = [root].
	require.Len(t, resp.X509CaChain, 2)
	assert.Equal(t, leafDER, resp.X509CaChain[0].Asn1, "minted leaf must be first")
	assert.Equal(t, interDER, resp.X509CaChain[1].Asn1, "intermediate must follow the leaf")
	require.Len(t, resp.UpstreamX509Roots, 1)
	assert.Equal(t, rootDER, resp.UpstreamX509Roots[0].Asn1)
}

func TestMintX509CA_EnrollHTTPError(t *testing.T) {
	enroll := func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, `{"error":"boom"}`, http.StatusInternalServerError)
	}

	_, err := configureAndMint(t, mockCAGW(t, enroll, nil))
	requireGRPCStatus(t, err, codes.Internal, "failed to enroll certificate with CAGW")
}

// The gRPC status reaches SPIRE's logs and its API clients, so it must carry
// CAGW's code and top-level message but none of the nested detail, which can
// describe backend internals.
func TestMintX509CA_EnrollErrorDetailNotLeaked(t *testing.T) {
	const secret = "InternalBackendDetail"

	enroll := func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"error": map[string]any{
				"code":                 "cagw-4018",
				"message":              "CA with specified name not found",
				"additionalProperties": map[string]any{"exceptionClass": secret},
				"details":              []map[string]any{{"message": secret}},
			},
		})
	}

	_, err := configureAndMint(t, mockCAGW(t, enroll, nil))
	require.Error(t, err)

	msg := status.Convert(err).Message()
	assert.NotContains(t, msg, secret, "nested CAGW detail must not reach the gRPC status")
	assert.Contains(t, msg, "cagw-4018", "CAGW error code should be retained for diagnosis")
	assert.Contains(t, msg, "CA with specified name not found")
}

func TestMintX509CA_EmptyEnrollmentBody(t *testing.T) {
	enroll := func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enrollment": map[string]any{"status": "PENDING"},
		})
	}

	_, err := configureAndMint(t, mockCAGW(t, enroll, nil))
	requireGRPCStatus(t, err, codes.Internal, "did not return an issued certificate")
}

func TestMintX509CA_NoUpstreamRoot(t *testing.T) {
	// The issuing CA is only an intermediate; CAGW returns no self-signed root,
	// so the plugin cannot determine the upstream root.
	root, _, rootKey := makeCA(t, "test-root")
	inter, interDER, interKey := makeChildCA(t, "test-intermediate", root, rootKey)
	_, leafDER, _ := makeChildCA(t, "spire-ca", inter, interKey)

	enroll := func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"enrollment": map[string]any{"status": "ISSUED", "body": b64(leafDER)},
		})
	}
	getCA := func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ca": map[string]any{
				"certificate": map[string]any{"certificateData": b64(interDER)},
			},
		})
	}

	_, err := configureAndMint(t, mockCAGW(t, enroll, getCA))
	requireGRPCStatus(t, err, codes.Internal, "could not determine upstream root")
}
