/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cagwtls builds a mutual-TLS http.Client for talking to the CA Gateway
// (CAGW) API using a PKCS#12 client credential.
package cagwtls

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"time"

	"software.sslmate.com/src/go-pkcs12"
)

// defaultRequestTimeout bounds each CAGW HTTP request end-to-end (connection,
// TLS handshake, and response read) so an unresponsive CAGW cannot hang the
// plugin indefinitely when the caller's context carries no deadline.
const defaultRequestTimeout = 30 * time.Second

// NewHTTPClient builds an *http.Client that presents the client certificate and
// private key contained in the PKCS#12 file at p12File (unlocked with
// p12Password) for mutual TLS against the CAGW endpoint.
//
// If serverCAFile is non-empty it is used as the sole trusted root for verifying
// the CAGW server certificate. If it is empty the host's system root store is
// used.
//
// timeout bounds each request end-to-end; defaultRequestTimeout is used when it
// is not positive.
func NewHTTPClient(p12File, p12Password, serverCAFile string, timeout time.Duration) (*http.Client, error) {
	if timeout <= 0 {
		timeout = defaultRequestTimeout
	}

	if err := ensureFile("PKCS#12", p12File); err != nil {
		return nil, err
	}

	p12Data, err := os.ReadFile(p12File)
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCS#12 file %q: %w", p12File, err)
	}

	privateKey, cert, _, err := pkcs12.DecodeChain(p12Data, p12Password)
	if err != nil {
		return nil, fmt.Errorf("failed to decode PKCS#12 file %q: %w", p12File, err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("failed to build client TLS key pair: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		MinVersion:   tls.VersionTLS12,
	}

	if serverCAFile != "" {
		if err := ensureFile("server CA", serverCAFile); err != nil {
			return nil, err
		}
		caPEM, err := os.ReadFile(serverCAFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read server CA file %q: %w", serverCAFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caPEM) {
			return nil, fmt.Errorf("no certificates found in server CA file %q", serverCAFile)
		}
		tlsConfig.RootCAs = pool
	}

	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = tlsConfig

	return &http.Client{Transport: transport, Timeout: timeout}, nil
}

// ensureFile verifies that path exists and is a regular file. It gives a clear,
// actionable error for the common container footgun where a missing Docker
// bind-mount source is silently auto-created as a directory (making the path
// resolve to a directory rather than the expected credential/PEM file).
func ensureFile(label, path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat %s file %q: %w", label, path, err)
	}
	if info.IsDir() {
		return fmt.Errorf("%s file %q is a directory, not a file "+
			"(a missing Docker bind-mount source is auto-created as a directory)", label, path)
	}
	return nil
}
