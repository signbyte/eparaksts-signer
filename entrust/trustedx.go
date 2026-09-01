package entrust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TrustedX OAuth scopes.
const (
	scopeProfile   = "urn:safelayer:eidas:sign:identity:profile"
	scopeAA        = "urn:lvrtc:fpeil:aa"
	scopeUseServer = "urn:safelayer:eidas:sign:identity:use:server"
	scopeUseDevice = "urn:safelayer:eidas:sign:identity:use:device"
)

// TrustedX resource paths.
const (
	pathUsersMe = "/trustedx-resources/openid/v1/users/me"
	// sign_identities/{id} is on the esigp/v1 surface (the `self` link in
	// users/me), NOT openid/v1 — openid/v1 returns 404 NotFoundException.
	pathSignIdentity  = "/trustedx-resources/esigp/v1/sign_identities/"
	pathServerRaw     = "/trustedx-resources/esigp/v1/signatures/server/raw"
	pathServerRawBat  = "/trustedx-resources/esigp/v1/signatures/server/raw/batch"
	pathDeviceRaw     = "/trustedx-resources/esigp/v1/signatures/device/raw"
	pathSignaturesRes = "/trustedx-resources/esigp/v1/signatures/" // {id}/result, {id} (DELETE)
)

// ProfileAuthorizeParams builds redirect #1 (profile).
type ProfileAuthorizeParams struct {
	State     string
	ACRValues string
	UILocales string
}

// ProfileAuthorizeURL builds the redirect #1 URL: the user authenticates
// (eParaksts Mobile / eID) and grants the profile scope so the service can read
// sign_identities. acr selects the authenticator (flow:mobileid / flow:mobile-eid).
func (c *Client) ProfileAuthorizeURL(p ProfileAuthorizeParams) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURI)
	q.Set("state", p.State)
	q.Set("scope", scopeProfile+" "+scopeAA)
	if p.ACRValues != "" {
		q.Set("acr_values", p.ACRValues)
	}
	if p.UILocales != "" {
		q.Set("ui_locales", p.UILocales)
	}
	return c.authorizeEndpoint() + "?" + q.Encode()
}

// SignAuthorizeParams builds redirect #2 (sign-consent).
type SignAuthorizeParams struct {
	State                   string
	ACRValues               string
	UILocales               string
	SignIdentityID          string
	DigestsSummary          string // base64 (echoed from CalculateDigest), URL-encoded by Encode
	DigestsSummaryAlgorithm string // mirror CalculateDigest's `algorithm`
	UseDevice               bool   // eidScan → use:device; else use:server
}

// SignAuthorizeURL builds the redirect #2 URL carrying the signing identity and
// the digests_summary the user approves (Mobile passcode / eID NFC).
func (c *Client) SignAuthorizeURL(p SignAuthorizeParams) string {
	scope := scopeUseServer
	if p.UseDevice {
		scope = scopeUseDevice
	}
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.ClientID)
	q.Set("redirect_uri", c.cfg.RedirectURI)
	q.Set("state", p.State)
	q.Set("scope", scope)
	q.Set("sign_identity_id", p.SignIdentityID)
	q.Set("digests_summary", p.DigestsSummary)
	q.Set("digests_summary_algorithm", p.DigestsSummaryAlgorithm)
	if p.ACRValues != "" {
		q.Set("acr_values", p.ACRValues)
	}
	if p.UILocales != "" {
		q.Set("ui_locales", p.UILocales)
	}
	return c.authorizeEndpoint() + "?" + q.Encode()
}

// Exchange swaps an authorization code for a TrustedX access token (Basic client
// auth). Used for both the profile and signing legs.
func (c *Client) Exchange(ctx context.Context, code string) (string, error) {
	form := map[string]string{
		"grant_type":   "authorization_code",
		"code":         code,
		"redirect_uri": c.cfg.RedirectURI,
	}
	var tr tokenResponse
	if err := c.postForm(ctx, c.tokenEndpoint(), form, c.basicAuth(c.cfg.ClientID, c.cfg.ClientSecret), &tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("entrust: token exchange returned no access_token")
	}
	return tr.AccessToken, nil
}

// SignIdentity is one entry of users/me sign_identities[] (live shape, verified
// against the Entrust flows): `status` is an object {value}, `access` is an
// array of {user_id, permissions[]} entries.
type SignIdentity struct {
	ID          string         `json:"id"`
	Description string         `json:"description"`
	Status      IdentityStatus `json:"status"`
	Labels      []string       `json:"labels"`
	Access      []AccessEntry  `json:"access"`
}

// IdentityStatus is the {"value":"enabled"} status object.
type IdentityStatus struct {
	Value string `json:"value"`
}

// AccessEntry is one {user_id, permissions[]} grant of an identity's access[].
type AccessEntry struct {
	UserID      string   `json:"user_id"`
	Permissions []string `json:"permissions"`
}

// Enabled reports whether the identity status is "enabled".
func (s SignIdentity) Enabled() bool { return strings.EqualFold(s.Status.Value, statusEnabled) }

type usersMeResponse struct {
	SignIdentities []SignIdentity `json:"sign_identities"`
}

// UsersMe reads the authenticated person's signing identities (profile token).
func (c *Client) UsersMe(ctx context.Context, profileToken string) ([]SignIdentity, error) {
	var out usersMeResponse
	if err := c.getJSON(ctx, c.cfg.BaseURL+pathUsersMe, profileToken, &out); err != nil {
		return nil, err
	}
	return out.SignIdentities, nil
}

// identityDetailResponse is the GET sign_identities/{id} response. The
// certificate is nested under identity.details.certificate (verified trace).
type identityDetailResponse struct {
	Identity struct {
		Details struct {
			Certificate string `json:"certificate"` // base64-DER signing/auth cert
		} `json:"details"`
	} `json:"identity"`
}

// SignIdentityCert fetches the base64-DER certificate for a sign-identity id,
// retrying while the identity materializes (the trace notes "repeat until
// granted").
func (c *Client) SignIdentityCert(ctx context.Context, profileToken, id string) (string, error) {
	var lastErr error
	for attempt := 0; attempt < c.cfg.IdentityFetchRetries; attempt++ {
		var d identityDetailResponse
		err := c.getJSON(ctx, c.cfg.BaseURL+pathSignIdentity+url.PathEscape(id), profileToken, &d)
		if err == nil {
			if d.Identity.Details.Certificate != "" {
				return d.Identity.Details.Certificate, nil
			}
			lastErr = fmt.Errorf("entrust: sign_identity %q has no certificate", id)
		} else {
			lastErr = err
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(c.cfg.IdentityFetchDelay):
		}
	}
	return "", lastErr
}

// ServerRawRequest is one digest to sign in a server/raw batch.
type ServerRawRequest struct {
	DigestValue        string `json:"digest_value"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

type serverRawBatchRequest struct {
	SignIdentityID     string             `json:"sign_identity_id"`
	SignatureAlgorithm string             `json:"signature_algorithm"`
	Requests           []ServerRawRequest `json:"requests"`
}

type serverRawBatchResponse struct {
	Signatures []string `json:"signatures"`
}

// ServerRawBatch signs a batch of digests server-side (mobile / cloudEseal),
// returning the signatures in request order (base64).
func (c *Client) ServerRawBatch(ctx context.Context, signingToken, signIdentityID, signatureAlgorithm string, reqs []ServerRawRequest) ([]string, error) {
	body, err := json.Marshal(serverRawBatchRequest{
		SignIdentityID:     signIdentityID,
		SignatureAlgorithm: signatureAlgorithm,
		Requests:           reqs,
	})
	if err != nil {
		return nil, err
	}
	var out serverRawBatchResponse
	if err := c.postJSONBearer(ctx, c.cfg.BaseURL+pathServerRawBat, signingToken, body, &out); err != nil {
		return nil, err
	}
	return out.Signatures, nil
}

// deviceRawRequest is the device-push body (eidScan).
type deviceRawRequest struct {
	Input struct {
		DigestValue     string `json:"digest_value"`
		DigestAlgorithm string `json:"digest_algorithm"`
		DataInfo        struct {
			HTML string `json:"html"`
		} `json:"data_info"`
	} `json:"input"`
	SignIdentities []struct {
		ID string `json:"id"`
	} `json:"sign_identities"`
	Notify bool `json:"notify"`
}

type deviceRawResponse struct {
	Signature struct {
		ID string `json:"id"`
	} `json:"signature"`
}

// DeviceRaw pushes a single digest to the user's device (eidScan), returning the
// pending signature id to poll. message is the prompt shown on the device; code
// is the 4-digit verification code; deadlineMs is the epoch-ms expiry.
func (c *Client) DeviceRaw(ctx context.Context, signingToken, signIdentityID, digestValue, digestAlgorithm, code, message string, deadlineMs int64) (string, error) {
	dataInfo := map[string]any{
		"code":    code,
		"message": message,
		"params": map[string]any{
			"transaction_type": "signature",
			"force_pin":        true,
			"deadline":         deadlineMs,
		},
		"api_level": 1,
	}
	infoJSON, err := json.Marshal(dataInfo)
	if err != nil {
		return "", err
	}

	var req deviceRawRequest
	req.Input.DigestValue = digestValue
	req.Input.DigestAlgorithm = digestAlgorithm
	req.Input.DataInfo.HTML = "=" + base64.StdEncoding.EncodeToString(infoJSON)
	req.SignIdentities = []struct {
		ID string `json:"id"`
	}{{ID: signIdentityID}}
	req.Notify = true

	body, err := json.Marshal(req)
	if err != nil {
		return "", err
	}
	var out deviceRawResponse
	if err := c.postJSONBearer(ctx, c.cfg.BaseURL+pathDeviceRaw, signingToken, body, &out); err != nil {
		return "", err
	}
	if out.Signature.ID == "" {
		return "", fmt.Errorf("entrust: device/raw returned no signature id")
	}
	return out.Signature.ID, nil
}

// DeviceResult is the polled device-signature result.
type DeviceResult struct {
	Status string `json:"status"` // finished | failed | canceled | pending
	Value  string `json:"value"`  // base64 signature when finished
}

// PollDeviceResult fetches the device signature result once.
func (c *Client) PollDeviceResult(ctx context.Context, signingToken, signatureID string) (DeviceResult, error) {
	var out DeviceResult
	err := c.getJSON(ctx, c.cfg.BaseURL+pathSignaturesRes+url.PathEscape(signatureID)+"/result", signingToken, &out)
	return out, err
}

// DeleteSignature deletes a device signature (always, incl. failure/cancel).
func (c *Client) DeleteSignature(ctx context.Context, signingToken, signatureID string) error {
	req, err := newRequest(ctx, "DELETE", c.cfg.BaseURL+pathSignaturesRes+url.PathEscape(signatureID), signingToken)
	if err != nil {
		return err
	}
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("entrust: delete signature: %w", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("entrust: delete signature returned %d", resp.StatusCode)
	}
	return nil
}

// ACRForFlow returns the configured acr_values for a TrustedX flow variant.
func (c *Client) ACRForFlow(useDevice, cloudEseal bool) string {
	switch {
	case useDevice:
		return c.cfg.ACREIDScan
	case cloudEseal && c.cfg.ACRCloudEseal != "":
		return c.cfg.ACRCloudEseal
	default:
		return c.cfg.ACRMobile
	}
}

// hasLabel reports whether labels contains all of want (case-insensitive).
func hasLabel(labels []string, want ...string) bool {
	set := make(map[string]struct{}, len(labels))
	for _, l := range labels {
		set[strings.ToLower(l)] = struct{}{}
	}
	for _, w := range want {
		if _, ok := set[strings.ToLower(w)]; !ok {
			return false
		}
	}
	return true
}
