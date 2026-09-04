/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

package cagwtls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"software.sslmate.com/src/go-pkcs12"
)

const testP12Password = "test-password"

// writeP12 generates a self-signed certificate and writes it, with its key, as a
// PKCS#12 file. Fixtures are generated rather than committed because .gitignore
// excludes test/*.p12, so a checked-in fixture would be absent on a clean
// checkout and the test would pass locally but fail in CI.
func writeP12(t *testing.T, dir, password string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-client"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	pfx, err := pkcs12.Modern.Encode(key, cert, nil, password)
	require.NoError(t, err)

	path := filepath.Join(dir, "client.p12")
	require.NoError(t, os.WriteFile(path, pfx, 0o600))
	return path
}

// writeCAPEM writes a self-signed CA certificate in PEM form.
func writeCAPEM(t *testing.T, dir string) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	path := filepath.Join(dir, "ca.pem")
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	require.NoError(t, os.WriteFile(path, pemBytes, 0o600))
	return path
}

func tlsConfigOf(t *testing.T, client *http.Client) *tls.Config {
	t.Helper()

	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok, "expected an *http.Transport")
	return transport.TLSClientConfig
}

func TestNewHTTPClient_PinnedCA(t *testing.T) {
	dir := t.TempDir()

	client, err := NewHTTPClient(writeP12(t, dir, testP12Password), testP12Password, writeCAPEM(t, dir), 0)
	require.NoError(t, err)

	cfg := tlsConfigOf(t, client)
	assert.Len(t, cfg.Certificates, 1, "client credential must be presented for mutual TLS")
	assert.NotNil(t, cfg.RootCAs, "pinned CA must be the sole trusted root")
	assert.Equal(t, uint16(tls.VersionTLS12), cfg.MinVersion)
}

// An empty serverCAFile means "verify against the host system root store", which
// is represented by leaving RootCAs nil rather than by an empty pool. An empty
// pool would trust nothing and fail every connection.
func TestNewHTTPClient_SystemTrustStore(t *testing.T) {
	dir := t.TempDir()

	client, err := NewHTTPClient(writeP12(t, dir, testP12Password), testP12Password, "", 0)
	require.NoError(t, err)

	assert.Nil(t, tlsConfigOf(t, client).RootCAs)
}

func TestNewHTTPClient_Timeout(t *testing.T) {
	dir := t.TempDir()
	p12 := writeP12(t, dir, testP12Password)

	tests := map[string]struct {
		given time.Duration
		want  time.Duration
	}{
		"zero falls back to the default":     {0, defaultRequestTimeout},
		"negative falls back to the default": {-time.Second, defaultRequestTimeout},
		"positive is honored":                {45 * time.Second, 45 * time.Second},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			client, err := NewHTTPClient(p12, testP12Password, "", tc.given)
			require.NoError(t, err)
			assert.Equal(t, tc.want, client.Timeout)
		})
	}
}

func TestNewHTTPClient_Errors(t *testing.T) {
	tests := map[string]struct {
		setup   func(t *testing.T, dir string) (p12File, password, serverCAFile string)
		wantErr string
	}{
		"missing PKCS#12 file": {
			setup: func(_ *testing.T, dir string) (string, string, string) {
				return filepath.Join(dir, "absent.p12"), testP12Password, ""
			},
			wantErr: "failed to stat PKCS#12 file",
		},
		// A missing Docker bind-mount source is silently created as a directory,
		// so this path must report the cause rather than a decode failure.
		"PKCS#12 path is a directory": {
			setup: func(t *testing.T, dir string) (string, string, string) {
				path := filepath.Join(dir, "as-dir.p12")
				require.NoError(t, os.Mkdir(path, 0o750))
				return path, testP12Password, ""
			},
			wantErr: "is a directory, not a file",
		},
		"wrong PKCS#12 password": {
			setup: func(t *testing.T, dir string) (string, string, string) {
				return writeP12(t, dir, testP12Password), "not-the-password", ""
			},
			wantErr: "failed to decode PKCS#12 file",
		},
		"corrupt PKCS#12 contents": {
			setup: func(t *testing.T, dir string) (string, string, string) {
				path := filepath.Join(dir, "corrupt.p12")
				require.NoError(t, os.WriteFile(path, []byte("not a pkcs12 file"), 0o600))
				return path, testP12Password, ""
			},
			wantErr: "failed to decode PKCS#12 file",
		},
		"missing server CA file": {
			setup: func(t *testing.T, dir string) (string, string, string) {
				return writeP12(t, dir, testP12Password), testP12Password, filepath.Join(dir, "absent.pem")
			},
			wantErr: "failed to stat server CA file",
		},
		"server CA path is a directory": {
			setup: func(t *testing.T, dir string) (string, string, string) {
				path := filepath.Join(dir, "as-dir.pem")
				require.NoError(t, os.Mkdir(path, 0o750))
				return writeP12(t, dir, testP12Password), testP12Password, path
			},
			wantErr: "is a directory, not a file",
		},
		"server CA file contains no certificates": {
			setup: func(t *testing.T, dir string) (string, string, string) {
				path := filepath.Join(dir, "empty.pem")
				require.NoError(t, os.WriteFile(path, []byte("no PEM data here"), 0o600))
				return writeP12(t, dir, testP12Password), testP12Password, path
			},
			wantErr: "no certificates found in server CA file",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			p12File, password, serverCAFile := tc.setup(t, t.TempDir())

			_, err := NewHTTPClient(p12File, password, serverCAFile, 0)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErr)
		})
	}
}
