/*
 * Copyright (c) 2026 Entrust Corporation.
 * SPDX-License-Identifier: Apache-2.0
 */

// Package cagw provides a minimal client for the two CA Gateway (CAGW) REST
// endpoints used by this plugin: submitting an enrollment request and reading a
// certificate authority's own certificate and chain.
//
// It intentionally models only the request/response fields the plugin needs
// rather than the full CAGW API surface. The mutual-TLS transport is supplied
// by the caller via the *http.Client (see internal/cagwtls).
package cagw

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Client talks to a CA Gateway instance over an mTLS-configured HTTP client.
type Client struct {
	baseURL    string
	httpClient *http.Client
	headers    map[string]string
}

// NewClient returns a CAGW client rooted at baseURL (the API base path, e.g.
// "https://cagw.example.com/cagw", without a trailing slash). The supplied
// httpClient carries the mutual-TLS client credential and server trust. Any
// headers are added to every request (e.g. "ca-client-id").
func NewClient(baseURL string, httpClient *http.Client, headers map[string]string) *Client {
	return &Client{
		baseURL:    strings.TrimRight(baseURL, "/"),
		httpClient: httpClient,
		headers:    headers,
	}
}

// maxErrorMessageRunes bounds the CAGW message included in an error string.
const maxErrorMessageRunes = 256

// APIError is returned when CAGW responds with a non-2xx status.
//
// Error() yields only the HTTP status and CAGW's own error code and top-level
// message. Body holds the full response and is intended for debug logging only:
// CAGW error details can describe backend internals, and this error is surfaced
// to SPIRE as a gRPC status that reaches its logs and API clients.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
	Body       string
}

func (e *APIError) Error() string {
	switch {
	case e.Code != "" && e.Message != "":
		return fmt.Sprintf("CAGW returned status %d (%s): %s", e.StatusCode, e.Code, e.Message)
	case e.Message != "":
		return fmt.Sprintf("CAGW returned status %d: %s", e.StatusCode, e.Message)
	default:
		return fmt.Sprintf("CAGW returned status %d", e.StatusCode)
	}
}

// errorResponse models only the safe top-level fields of a CAGW error payload.
// The nested "details" and "additionalProperties" are deliberately not modeled.
type errorResponse struct {
	Error struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func newAPIError(statusCode int, body []byte) *APIError {
	apiErr := &APIError{
		StatusCode: statusCode,
		Body:       strings.TrimSpace(string(body)),
	}

	var parsed errorResponse
	if err := json.Unmarshal(body, &parsed); err == nil {
		apiErr.Code = parsed.Error.Code
		apiErr.Message = truncateRunes(parsed.Error.Message, maxErrorMessageRunes)
	}
	return apiErr
}

func truncateRunes(s string, maxRunes int) string {
	r := []rune(s)
	if len(r) <= maxRunes {
		return s
	}
	return string(r[:maxRunes]) + "..."
}

// CertificateFormat selects the encoding CAGW returns for the issued
// certificate.
type CertificateFormat struct {
	Format string `json:"format"`
}

// CertificateRequestDetails carries optional overrides for an enrollment.
type CertificateRequestDetails struct {
	SubjectDn      string `json:"subjectDn,omitempty"`
	UseSANFromCSR  bool   `json:"useSANFromCSR"`
	ValidityPeriod string `json:"validityPeriod,omitempty"`
}

// EnrollmentRequest is the body posted to the enrollments endpoint.
type EnrollmentRequest struct {
	Csr                               string                     `json:"csr,omitempty"`
	ProfileID                         string                     `json:"profileId"`
	RequiredFormat                    *CertificateFormat         `json:"requiredFormat"`
	OptionalCertificateRequestDetails *CertificateRequestDetails `json:"optionalCertificateRequestDetails,omitempty"`
}

// Certificate is a CAGW certificate resource. Only CertificateData (Base64 DER)
// is consumed by this plugin.
type Certificate struct {
	CertificateData string `json:"certificateData,omitempty"`
}

// Enrollment holds the result of a successful (or pending) enrollment.
type Enrollment struct {
	Status *string       `json:"status,omitempty"`
	Body   string        `json:"body,omitempty"`
	Chain  []Certificate `json:"chain,omitempty"`
}

// EnrollmentResponse is the response from the enrollments endpoint.
type EnrollmentResponse struct {
	Enrollment *Enrollment `json:"enrollment,omitempty"`
}

// CA describes a certificate authority, including its own certificate and chain
// when requested via the "$fields" query parameter.
type CA struct {
	Certificate *Certificate  `json:"certificate,omitempty"`
	Chain       []Certificate `json:"chain,omitempty"`
}

// CAResponse is the response from the certificate-authority endpoint.
type CAResponse struct {
	Ca *CA `json:"ca"`
}

// Enroll submits an enrollment request for caID and returns the CAGW response.
func (c *Client) Enroll(ctx context.Context, caID string, req EnrollmentRequest) (*EnrollmentResponse, error) {
	path := "/v1/certificate-authorities/" + url.PathEscape(caID) + "/enrollments"

	var out EnrollmentResponse
	if err := c.do(ctx, http.MethodPost, path, nil, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetCA retrieves the certificate authority caID. The fields argument populates
// the CAGW "$fields" query parameter (e.g. "ca.certificate,ca.chain") to
// request the CA certificate and chain, which are otherwise omitted.
func (c *Client) GetCA(ctx context.Context, caID, fields string) (*CAResponse, error) {
	path := "/v1/certificate-authorities/" + url.PathEscape(caID)

	var query url.Values
	if fields != "" {
		query = url.Values{"$fields": {fields}}
	}

	var out CAResponse
	if err := c.do(ctx, http.MethodGet, path, query, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// do performs a single JSON request/response cycle against the CAGW API.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, body, out any) error {
	target := c.baseURL + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var reqBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("failed to encode request body: %w", err)
		}
		reqBody = bytes.NewReader(encoded)
	}

	req, err := http.NewRequestWithContext(ctx, method, target, reqBody)
	if err != nil {
		return fmt.Errorf("failed to build request: %w", err)
	}

	req.Header.Set("Accept", "application/json")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range c.headers {
		req.Header.Set(k, v)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("request to %s failed: %w", path, err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode >= http.StatusMultipleChoices {
		return newAPIError(resp.StatusCode, respBody)
	}

	if out != nil {
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("failed to decode response: %w", err)
		}
	}
	return nil
}
