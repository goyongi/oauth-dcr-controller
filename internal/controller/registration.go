/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	oauthv1alpha1 "goyongi.com/oauth-dcr-controller/api/v1alpha1"
)

const (
	// maxResponseBytes caps how much of a registration response body is read,
	// guarding against a misbehaving or malicious endpoint.
	maxResponseBytes = 1 << 20 // 1 MiB

	// httpTimeout bounds each outbound call to the authorization server so a
	// slow or unresponsive endpoint cannot wedge the reconcile worker.
	httpTimeout = 30 * time.Second
)

// defaultHTTPClient is used when no client is injected. It carries a timeout as
// a backstop; per-call context deadlines are the primary bound.
var defaultHTTPClient = &http.Client{Timeout: httpTimeout}

// registrationResponse models the OAuth 2.0 Dynamic Client Registration
// response defined by RFC 7591 §3.2.1. All fields other than client_id are
// optional; public clients receive no client_secret.
type registrationResponse struct {
	ClientID                string `json:"client_id"`
	ClientSecret            string `json:"client_secret,omitempty"`
	ClientIDIssuedAt        int64  `json:"client_id_issued_at,omitempty"`
	ClientSecretExpiresAt   int64  `json:"client_secret_expires_at,omitempty"`
	RegistrationAccessToken string `json:"registration_access_token,omitempty"`
	RegistrationClientURI   string `json:"registration_client_uri,omitempty"`
}

// buildRegistrationRequest renders the client metadata into the JSON body of an
// RFC 7591 registration request, mapping each spec field to its wire name and
// omitting empties. extraMetadata members are appended without overriding the
// explicitly modeled fields.
func buildRegistrationRequest(m oauthv1alpha1.ClientMetadata) ([]byte, error) {
	body := map[string]any{}
	setSlice := func(k string, v []string) {
		if len(v) > 0 {
			body[k] = v
		}
	}
	setStr := func(k, v string) {
		if v != "" {
			body[k] = v
		}
	}

	setSlice("redirect_uris", m.RedirectURIs)
	setStr("token_endpoint_auth_method", m.TokenEndpointAuthMethod)
	setSlice("grant_types", m.GrantTypes)
	setSlice("response_types", m.ResponseTypes)
	setStr("client_name", m.ClientName)
	setStr("client_uri", m.ClientURI)
	setStr("logo_uri", m.LogoURI)
	setStr("scope", m.Scope)
	setSlice("contacts", m.Contacts)
	setStr("tos_uri", m.TosURI)
	setStr("policy_uri", m.PolicyURI)
	setStr("jwks_uri", m.JwksURI)
	setStr("software_id", m.SoftwareID)
	setStr("software_version", m.SoftwareVersion)

	for k, v := range m.ExtraMetadata {
		if _, exists := body[k]; !exists {
			body[k] = v
		}
	}

	return json.Marshal(body)
}

// register performs the RFC 7591 registration request and returns the raw
// response body together with the HTTP status code. A non-2xx status is not
// treated as a transport error here; the caller inspects the code.
func (r *DynamicClientRegistrationReconciler) register(
	ctx context.Context, endpoint, initialAccessToken string, body []byte,
) (respBody []byte, statusCode int, err error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, 0, fmt.Errorf("building registration request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if initialAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+initialAccessToken)
	}

	resp, err := r.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("calling registration endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err = io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if err != nil {
		return nil, resp.StatusCode, fmt.Errorf("reading registration response: %w", err)
	}
	return respBody, resp.StatusCode, nil
}

// deleteRegistration best-effort deletes an upstream client registration via
// RFC 7592 (DELETE on the registration_client_uri). A 404 or 405 is treated as
// success: the registration is already gone or the server does not implement
// RFC 7592. Only transport errors and other non-success statuses are returned.
//
// The HTTP status code is returned alongside the error (0 on transport failure)
// so the caller can distinguish a real delete (2xx) from a no-op tolerated
// status (404/405) — a 405 means the client likely still exists upstream.
func (r *DynamicClientRegistrationReconciler) deleteRegistration(
	ctx context.Context, registrationClientURI, registrationAccessToken string,
) (int, error) {
	ctx, cancel := context.WithTimeout(ctx, httpTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, registrationClientURI, nil)
	if err != nil {
		return 0, fmt.Errorf("building delete request: %w", err)
	}
	if registrationAccessToken != "" {
		req.Header.Set("Authorization", "Bearer "+registrationAccessToken)
	}

	resp, err := r.httpClient().Do(req)
	if err != nil {
		return 0, fmt.Errorf("calling registration management endpoint: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))

	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return resp.StatusCode, nil
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusMethodNotAllowed:
		// Already gone, or RFC 7592 unsupported. Treat as done.
		return resp.StatusCode, nil
	default:
		return resp.StatusCode, fmt.Errorf("registration management endpoint returned %d", resp.StatusCode)
	}
}

// httpClient returns the configured HTTP client, or a sane default. Exposing the
// client as a field keeps the reconciler testable.
func (r *DynamicClientRegistrationReconciler) httpClient() *http.Client {
	if r.HTTPClient != nil {
		return r.HTTPClient
	}
	return defaultHTTPClient
}
