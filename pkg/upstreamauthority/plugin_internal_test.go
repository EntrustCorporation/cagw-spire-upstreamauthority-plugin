/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

package upstreamauthority

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"

	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/internal/cagw"
)

// testCert is a generated certificate together with its DER encoding and the
// key that signed it, used to build parent/child relationships in the tests.
type testCert struct {
	der  []byte
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// makeCert creates a certificate from tmpl signed by parent. When parent is nil
// the certificate is self-signed (a root). isCA controls the BasicConstraints
// and KeyUsage so that CheckSignatureFrom (used by isSelfSigned) succeeds for
// CA certificates.
func makeCert(t *testing.T, cn string, parent *testCert, isCA bool) testCert {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature
	}

	signer := tmpl     // self-signed by default
	signerKey := key   // ...with its own key
	if parent != nil { // otherwise signed by the parent
		signer = parent.cert
		signerKey = parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return testCert{der: der, cert: cert, key: key}
}

// cagwCert wraps DER bytes as a CAGW certificate resource (Base64 DER).
func cagwCert(der []byte) cagw.Certificate {
	return cagw.Certificate{CertificateData: base64.StdEncoding.EncodeToString(der)}
}

// derSet collects the raw ASN.1 of a slice of plugintypes certificates for
// order-independent comparison.
func derSet(t *testing.T, in []*plugintypes.X509Certificate) map[string]struct{} {
	t.Helper()
	out := make(map[string]struct{}, len(in))
	for _, c := range in {
		out[string(c.Asn1)] = struct{}{}
	}
	return out
}

func TestBuildChain_LeafAndRoot(t *testing.T) {
	root := makeCert(t, "root", nil, true)
	leaf := makeCert(t, "leaf", &root, false)

	chain, roots, err := buildChain(leaf.der, []cagw.Certificate{cagwCert(root.der)})
	require.NoError(t, err)

	require.Len(t, chain, 1, "chain should hold only the minted leaf")
	assert.Equal(t, leaf.der, chain[0].Asn1)
	require.Len(t, roots, 1)
	assert.Equal(t, root.der, roots[0].Asn1)
}

func TestBuildChain_WithIntermediate(t *testing.T) {
	root := makeCert(t, "root", nil, true)
	inter := makeCert(t, "intermediate", &root, true)
	leaf := makeCert(t, "leaf", &inter, false)

	chain, roots, err := buildChain(leaf.der, []cagw.Certificate{
		cagwCert(inter.der),
		cagwCert(root.der),
	})
	require.NoError(t, err)

	// chain = [leaf, intermediate] (order-independent for the CA certs)
	require.Len(t, chain, 2)
	assert.Equal(t, leaf.der, chain[0].Asn1, "leaf must be first in the chain")
	chainSet := derSet(t, chain)
	assert.Contains(t, chainSet, string(inter.der))

	require.Len(t, roots, 1)
	assert.Equal(t, root.der, roots[0].Asn1)
}

func TestBuildChain_DeduplicatesCACerts(t *testing.T) {
	root := makeCert(t, "root", nil, true)
	inter := makeCert(t, "intermediate", &root, true)
	leaf := makeCert(t, "leaf", &inter, false)

	chain, roots, err := buildChain(leaf.der, []cagw.Certificate{
		cagwCert(root.der),
		cagwCert(root.der), // duplicate root
		cagwCert(inter.der),
		cagwCert(inter.der), // duplicate intermediate
	})
	require.NoError(t, err)

	assert.Len(t, roots, 1, "duplicate roots must be collapsed")
	assert.Len(t, chain, 2, "leaf + single intermediate")
}

func TestBuildChain_SkipsEmptyCertificateData(t *testing.T) {
	root := makeCert(t, "root", nil, true)
	leaf := makeCert(t, "leaf", &root, false)

	chain, roots, err := buildChain(leaf.der, []cagw.Certificate{
		{CertificateData: ""}, // must be ignored, not an error
		cagwCert(root.der),
	})
	require.NoError(t, err)
	assert.Len(t, chain, 1)
	assert.Len(t, roots, 1)
}

func TestBuildChain_NoRootReturnsError(t *testing.T) {
	root := makeCert(t, "root", nil, true)
	inter := makeCert(t, "intermediate", &root, true)
	leaf := makeCert(t, "leaf", &inter, false)

	// Only the (non-self-signed) intermediate is supplied — no root present.
	_, _, err := buildChain(leaf.der, []cagw.Certificate{cagwCert(inter.der)})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "could not determine upstream root")
}

func TestBuildChain_InvalidBase64ReturnsError(t *testing.T) {
	root := makeCert(t, "root", nil, true)
	leaf := makeCert(t, "leaf", &root, false)

	_, _, err := buildChain(leaf.der, []cagw.Certificate{{CertificateData: "!!!not-base64!!!"}})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "failed to decode CA certificate")
}

func TestIsSelfSigned(t *testing.T) {
	root := makeCert(t, "root", nil, true)
	inter := makeCert(t, "intermediate", &root, true)
	leaf := makeCert(t, "leaf", &inter, false)

	selfSigned, err := isSelfSigned(root.cert)
	require.NoError(t, err)
	assert.True(t, selfSigned, "root is self-signed")

	selfSigned, err = isSelfSigned(inter.cert)
	require.NoError(t, err)
	assert.False(t, selfSigned, "intermediate is signed by root")

	selfSigned, err = isSelfSigned(leaf.cert)
	require.NoError(t, err)
	assert.False(t, selfSigned, "leaf is signed by intermediate")
}

// A cross-signed certificate shares its subject and issuer names but is signed
// by a different key. Signature verification fails, yet it is an intermediate
// rather than a root, so this must not be reported as an error: treating every
// verification failure as fatal would reject a valid chain.
func TestIsSelfSigned_CrossSignedIsIntermediate(t *testing.T) {
	issuer := makeCert(t, "shared-name", nil, true)
	crossSigned := makeCert(t, "shared-name", &issuer, true)

	require.Equal(t, crossSigned.cert.RawSubject, crossSigned.cert.RawIssuer,
		"test requires subject and issuer names to match")

	selfSigned, err := isSelfSigned(crossSigned.cert)
	require.NoError(t, err, "a mismatched signature is not an error")
	assert.False(t, selfSigned, "cross-signed certificate is an intermediate")
}

// An algorithm the toolchain cannot verify means "cannot tell", not "not a
// root". Silently classifying it as an intermediate previously surfaced as the
// misleading "CAGW returned no self-signed CA certificate".
func TestIsSelfSigned_UnverifiableAlgorithmIsAnError(t *testing.T) {
	root := makeCert(t, "root", nil, true)

	unverifiable := *root.cert
	unverifiable.SignatureAlgorithm = x509.MD5WithRSA

	_, err := isSelfSigned(&unverifiable)
	require.Error(t, err, "an unverifiable signature algorithm must be surfaced")

	var insecure x509.InsecureAlgorithmError
	assert.True(t,
		errors.Is(err, x509.ErrUnsupportedAlgorithm) || errors.As(err, &insecure),
		"must fail because the algorithm cannot be verified, not for some other reason: %v", err)
}
