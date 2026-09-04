/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

package upstreamauthority

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/spiffe/spire-plugin-sdk/pluginsdk"
	upstreamauthorityv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/server/upstreamauthority/v1"
	plugintypes "github.com/spiffe/spire-plugin-sdk/proto/spire/plugin/types"
	configv1 "github.com/spiffe/spire-plugin-sdk/proto/spire/service/common/config/v1"

	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/internal/cagw"
	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/internal/cagwtls"
	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/internal/grpcerr"
	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/internal/hclconfig"
	"github.com/EntrustCorporation/cagw-spire-upstreamauthority-plugin/internal/logger"
)

// Compile-time interface assertions.
var (
	_ pluginsdk.NeedsLogger       = (*Plugin)(nil)
	_ pluginsdk.NeedsHostServices = (*Plugin)(nil)
)

// Default file paths applied when the corresponding configuration fields are
// left empty. They match the conventional locations bind-mounted into the
// plugin's container image.
const (
	defaultP12File      = "/opt/spire/conf/cagw-client.p12"
	defaultServerCACert = "/opt/spire/conf/cagw-server-ca.pem"

	// serverCASystemTrustStore is the sentinel value for server_ca_cert that
	// tells the plugin to verify the CAGW server certificate against the host's
	// system root store instead of a pinned PEM file. Use this when CAGW
	// presents a publicly (or otherwise system-) trusted certificate.
	serverCASystemTrustStore = "system"
)

// Config holds the HCL-decoded plugin configuration provided by SPIRE.
//
// Example plugin_data block in the SPIRE server config:
//
//	UpstreamAuthority "cagw" {
//	    plugin_data {
//	        cagw_url      = "https://cagw.example.com/cagw"
//	        ca_id         = "my-partition~spire-ca-id"
//	        profile_id    = "basic-ca-subord"
//	        p12_file      = "/opt/spire/conf/cagw-client.p12"
//	        p12_password  = "my-p12-password"
//	        server_ca_cert = "/opt/spire/conf/cagw-server-ca.pem"
//	        ca_client_id  = "my-client-id"
//	        request_timeout = "45s"
//	    }
//	}
type Config struct {
	// CAGWURL is the base URL of the CA Gateway API, including the base path
	// (e.g. "https://cagw.example.com/cagw").
	CAGWURL string `hcl:"cagw_url"`
	// CAID is the full CA Gateway certificate authority ID used for enrollment,
	// in the form "<partition_id>~<ca_id>".
	CAID string `hcl:"ca_id"`
	// ProfileID is the certificate profile to use for signing.
	ProfileID string `hcl:"profile_id"`
	// P12File is the path to the PKCS#12 file holding the CAGW client
	// certificate and private key used for mutual TLS. When empty it defaults
	// to defaultP12File.
	P12File string `hcl:"p12_file"`
	// P12Password unlocks the PKCS#12 file.
	P12Password string `hcl:"p12_password"`
	// ServerCACert selects how the CAGW server's TLS certificate is verified.
	// It is a path to a PEM file used as the sole trusted root, OR the special
	// value "system" to verify against the host's system root store (use this
	// when CAGW presents a publicly-trusted certificate). When empty it defaults
	// to defaultServerCACert.
	ServerCACert string `hcl:"server_ca_cert"`
	// CAClientID is an optional value sent in the "ca-client-id" header on
	// every CAGW request.
	CAClientID string `hcl:"ca_client_id"`
	// RequestTimeout bounds each CAGW request end-to-end, as a Go duration
	// string (e.g. "45s"). When empty a built-in default is used.
	RequestTimeout string `hcl:"request_timeout"`
}

// state holds the live configuration together with the CAGW API client.
// Both are replaced atomically on (re-)configure.
type state struct {
	config     *Config
	cagwClient *cagw.Client
}

// Plugin implements the UpstreamAuthority server plugin interface.
type Plugin struct {
	upstreamauthorityv1.UnimplementedUpstreamAuthorityServer
	configv1.UnimplementedConfigServer
	logger.Loggable

	mu sync.RWMutex
	st *state
}

// MintX509CAAndSubscribe implements the UpstreamAuthority MintX509CAAndSubscribe RPC.
//
// SPIRE calls this RPC when it needs a new X.509 CA certificate signed by the
// upstream PKI. The plugin submits the CSR to CA Gateway for the configured CA
// and profile, retrieves the issuing CA's certificate and chain (not all CAs
// supported by CAGW return the chain in the enrollment response), and splits the
// result into the SPIRE CA chain and the upstream root(s).
//
// This plugin does not implement upstream root-update tracking, so it sends a
// single response and closes the stream, which the SDK permits. SPIRE reopens
// the stream at the next X.509 CA rotation, so upstream root changes are picked
// up then rather than immediately.
func (p *Plugin) MintX509CAAndSubscribe(
	req *upstreamauthorityv1.MintX509CARequest,
	stream upstreamauthorityv1.UpstreamAuthority_MintX509CAAndSubscribeServer,
) error {
	st, err := p.getState()
	if err != nil {
		return err
	}

	ctx := stream.Context()

	// 1. Parse the DER-encoded CSR to extract the subject DN.
	csr, err := x509.ParseCertificateRequest(req.Csr)
	if err != nil {
		return grpcerr.InvalidArgument("failed to parse CSR: %v", err)
	}

	// 2. Build the CAGW enrollment request. CAGW expects the CSR as a
	//    Base64-encoded DER PKCS#10 request. IncludeCa requests the CA chain
	//    alongside the issued certificate.
	enrollReq := cagw.EnrollmentRequest{
		Csr:            base64.StdEncoding.EncodeToString(req.Csr),
		ProfileID:      st.config.ProfileID,
		RequiredFormat: &cagw.CertificateFormat{Format: "X509"},
		OptionalCertificateRequestDetails: &cagw.CertificateRequestDetails{
			SubjectDn:     csr.Subject.String(),
			UseSANFromCSR: true,
		},
	}
	if req.PreferredTtl > 0 {
		enrollReq.OptionalCertificateRequestDetails.ValidityPeriod = fmt.Sprintf("PT%dS", req.PreferredTtl)
	}

	p.Logger.Debug("Minting X509 CA via CAGW", "ca_id", st.config.CAID, "profile_id", st.config.ProfileID)

	// 3. Submit the enrollment request to CAGW.
	resp, err := st.cagwClient.Enroll(ctx, st.config.CAID, enrollReq)
	if err != nil {
		return p.cagwFailure("failed to enroll certificate with CAGW", err)
	}

	if resp.Enrollment == nil || resp.Enrollment.Body == "" {
		status := ""
		if resp.Enrollment != nil && resp.Enrollment.Status != nil {
			status = *resp.Enrollment.Status
		}
		return grpcerr.Internal("CAGW did not return an issued certificate (status %q)", status)
	}

	// 4. Decode the issued certificate (Base64 DER).
	leafDER, err := base64.StdEncoding.DecodeString(resp.Enrollment.Body)
	if err != nil {
		return grpcerr.Internal("failed to decode issued certificate: %v", err)
	}

	// 5. Retrieve the issuing CA certificate and its chain from CAGW. Not all
	//    CAs supported by CAGW return the chain in the enrollment response, so we
	//    query the CA resource directly. Any chain CAGW does return inline on the
	//    enrollment is folded in as well (de-duplicated downstream).
	caCerts, err := st.fetchCACerts(ctx)
	if err != nil {
		return p.cagwFailure("failed to retrieve CA certificate from CAGW", err)
	}
	caCerts = append(caCerts, resp.Enrollment.Chain...)

	// 6. Split those certificates into the SPIRE CA chain and the upstream root.
	chain, roots, err := buildChain(leafDER, caCerts)
	if err != nil {
		return err
	}

	// 7. Send one response and close the stream.
	return stream.Send(&upstreamauthorityv1.MintX509CAResponse{
		X509CaChain:       chain,
		UpstreamX509Roots: roots,
	})
}

// cagwFailure returns a gRPC status carrying only CAGW's status, error code and
// top-level message. The full response body is logged at debug level instead:
// CAGW error details can describe backend internals, and this status reaches
// SPIRE's logs and any SPIRE API client.
func (p *Plugin) cagwFailure(msg string, err error) error {
	var apiErr *cagw.APIError
	if errors.As(err, &apiErr) && apiErr.Body != "" && p.Logger != nil {
		p.Logger.Debug("CAGW error response", "status", apiErr.StatusCode, "body", apiErr.Body)
	}
	return grpcerr.Internal("%s: %v", msg, err)
}

// fetchCACerts retrieves the configured CA's own certificate and its chain from
// CAGW. The CA's certificate is the issuer of the minted leaf; the chain (when
// present) carries any higher intermediates and the self-signed root.
//
// The certificate data is only populated when explicitly requested via the
// dotted "$fields" query parameter (ca.certificate, ca.chain).
//
// Errors are returned unwrapped so the caller can apply cagwFailure.
func (st *state) fetchCACerts(ctx context.Context) ([]cagw.Certificate, error) {
	caResp, err := st.cagwClient.GetCA(ctx, st.config.CAID, "ca.certificate,ca.chain")
	if err != nil {
		return nil, err
	}
	if caResp.Ca == nil {
		return nil, fmt.Errorf("CAGW returned no CA detail for ca_id %q", st.config.CAID)
	}

	var certs []cagw.Certificate
	if caResp.Ca.Certificate != nil {
		certs = append(certs, *caResp.Ca.Certificate)
	}
	certs = append(certs, caResp.Ca.Chain...)
	return certs, nil
}

// buildChain assembles the SPIRE MintX509CAResponse certificate lists from the
// minted leaf certificate and the CA-level certificates (the issuing CA
// certificate plus its chain) returned by CAGW:
//   - x509CaChain:       [leaf, intermediate1, …]  (the minted certificate
//     followed by every non-self-signed CA certificate)
//   - upstreamX509Roots: [rootCA, …]               (every self-signed CA certificate)
//
// CA certificates are de-duplicated by their DER encoding. At least one
// self-signed (root) certificate must be present or an error is returned.
func buildChain(leafDER []byte, caCerts []cagw.Certificate) ([]*plugintypes.X509Certificate, []*plugintypes.X509Certificate, error) {
	x509CaChain := []*plugintypes.X509Certificate{{Asn1: leafDER}}
	var upstreamRoots []*plugintypes.X509Certificate

	seen := make(map[string]struct{})
	for _, c := range caCerts {
		if c.CertificateData == "" {
			continue
		}

		der, err := base64.StdEncoding.DecodeString(c.CertificateData)
		if err != nil {
			return nil, nil, grpcerr.Internal("failed to decode CA certificate: %v", err)
		}
		if _, dup := seen[string(der)]; dup {
			continue
		}
		seen[string(der)] = struct{}{}

		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, grpcerr.Internal("failed to parse CA certificate: %v", err)
		}

		selfSigned, err := isSelfSigned(cert)
		if err != nil {
			return nil, nil, grpcerr.Internal("cannot determine whether CA certificate %q is self-signed: %v", cert.Subject, err)
		}
		if selfSigned {
			upstreamRoots = append(upstreamRoots, &plugintypes.X509Certificate{Asn1: der})
		} else {
			x509CaChain = append(x509CaChain, &plugintypes.X509Certificate{Asn1: der})
		}
	}

	if len(upstreamRoots) == 0 {
		return nil, nil, grpcerr.Internal("could not determine upstream root: CAGW returned no self-signed CA certificate")
	}

	return x509CaChain, upstreamRoots, nil
}

// isSelfSigned reports whether cert is a self-signed (root) certificate.
//
// A non-nil error means the signature could not be checked at all, which the
// caller must surface: this result decides whether a certificate becomes a
// trust anchor, so "not self-signed" and "cannot tell" must not be conflated.
// A signature that simply does not match is reported as not self-signed without
// an error, since a cross-signed certificate legitimately shares its subject and
// issuer names while being signed by a different key.
func isSelfSigned(cert *x509.Certificate) (bool, error) {
	if !bytes.Equal(cert.RawIssuer, cert.RawSubject) {
		return false, nil
	}

	err := cert.CheckSignatureFrom(cert)
	if err == nil {
		return true, nil
	}

	var insecure x509.InsecureAlgorithmError
	if errors.Is(err, x509.ErrUnsupportedAlgorithm) || errors.As(err, &insecure) {
		return false, err
	}
	return false, nil
}

// PublishJWTKeyAndSubscribe returns Unimplemented; this plugin does not
// participate in upstream JWT key federation.
func (p *Plugin) PublishJWTKeyAndSubscribe(
	_ *upstreamauthorityv1.PublishJWTKeyRequest,
	_ upstreamauthorityv1.UpstreamAuthority_PublishJWTKeyAndSubscribeServer,
) error {
	return grpcerr.Unimplemented("JWT key publishing is not supported by this plugin")
}

// Configure implements the Config service Configure RPC.
// It is called by SPIRE on plugin load and on configuration reload.
func (p *Plugin) Configure(_ context.Context, req *configv1.ConfigureRequest) (*configv1.ConfigureResponse, error) {
	cfg, err := hclconfig.ParseHCL[Config](req.HclConfiguration)
	if err != nil {
		return nil, grpcerr.InvalidArgument("failed to decode configuration: %v", err)
	}

	applyDefaults(cfg)

	if err := validateConfig(cfg); err != nil {
		return nil, grpcerr.InvalidArgument("invalid configuration: %v", err)
	}

	// A server_ca_cert of "system" means: verify against the host system root
	// store. cagwtls treats an empty path the same way, so translate the
	// sentinel accordingly.
	serverCAFile := cfg.ServerCACert
	if serverCAFile == serverCASystemTrustStore {
		serverCAFile = ""
	}

	requestTimeout, err := parseRequestTimeout(cfg.RequestTimeout)
	if err != nil {
		return nil, grpcerr.InvalidArgument("invalid configuration: %v", err)
	}

	httpClient, err := cagwtls.NewHTTPClient(cfg.P12File, cfg.P12Password, serverCAFile, requestTimeout)
	if err != nil {
		return nil, grpcerr.InvalidArgument("failed to create CAGW mTLS client: %v", err)
	}

	var headers map[string]string
	if cfg.CAClientID != "" {
		headers = map[string]string{"ca-client-id": cfg.CAClientID}
	}

	p.mu.Lock()
	p.st = &state{config: cfg, cagwClient: cagw.NewClient(cfg.CAGWURL, httpClient, headers)}
	p.mu.Unlock()

	return &configv1.ConfigureResponse{}, nil
}

// BrokerHostServices is called by the framework to give the plugin access to
// SPIRE host services.  This plugin does not require any host services.
func (p *Plugin) BrokerHostServices(_ pluginsdk.ServiceBroker) error {
	return nil
}

// getState returns the current live state or an error if the plugin has not
// been configured yet.
func (p *Plugin) getState() (*state, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	if p.st == nil {
		return nil, grpcerr.NotConfigured()
	}
	return p.st, nil
}

// applyDefaults fills in default values for optional file-path fields that were
// left empty in the configuration. server_ca_cert is only defaulted to the
// conventional container path when unset; an explicit "system" value is left
// intact so the caller can opt into the host system trust store.
func applyDefaults(cfg *Config) {
	if cfg.P12File == "" {
		cfg.P12File = defaultP12File
	}
	if cfg.ServerCACert == "" {
		cfg.ServerCACert = defaultServerCACert
	}
}

// parseRequestTimeout converts the optional request_timeout setting. An empty
// value yields zero, which leaves the client's own default in place.
func parseRequestTimeout(s string) (time.Duration, error) {
	if s == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return 0, fmt.Errorf("request_timeout %q is not a valid duration: %w", s, err)
	}
	if d <= 0 {
		return 0, fmt.Errorf("request_timeout %q must be positive", s)
	}
	return d, nil
}

// validateConfig ensures all required configuration fields are present.
func validateConfig(cfg *Config) error {
	return hclconfig.ValidateRequired(
		hclconfig.FieldCheck{Name: "cagw_url", Value: cfg.CAGWURL},
		hclconfig.FieldCheck{Name: "ca_id", Value: cfg.CAID},
		hclconfig.FieldCheck{Name: "profile_id", Value: cfg.ProfileID},
		hclconfig.FieldCheck{Name: "p12_file", Value: cfg.P12File},
		hclconfig.FieldCheck{Name: "p12_password", Value: cfg.P12Password},
	)
}
