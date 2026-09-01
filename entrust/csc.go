package entrust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// CSC API v2 paths. The CSC layer is the NEW surface fronting `signHash`; it
// coexists with the TrustedX surface for years.
//
// Some behaviours are still blocked on the LVRTC platform update and are marked
// at the call sites: the restricted AS / account_token; asynchronousOperationMode
// → signPolling; the short-term-cert mechanism and its timing vs CalculateDigest;
// and the CSC-layer ECDSA encoding (DER vs raw r‖s). The methods below implement
// the known request/response shapes; the unresolved cases are handled when the
// platform update lands.
const (
	cscPathOAuthAuthorize = "/csc/v2/oauth2/authorize"
	cscPathOAuthToken     = "/csc/v2/oauth2/token"
	cscPathCredsList      = "/csc/v2/credentials/list"
	cscPathCredsInfo      = "/csc/v2/credentials/info"
	cscPathSignHash       = "/csc/v2/signatures/signHash"
)

// cscBase returns the CSC layer base URL, defaulting to the TrustedX base when
// the CSC URL is not separately configured (same platform).
func (c *Client) cscBase() string {
	if c.cfg.CSCBaseURL != "" {
		return c.cfg.CSCBaseURL
	}
	return c.cfg.BaseURL
}

// CSCEnabled reports whether the CSC layer is configured.
func (c *Client) CSCEnabled() bool {
	return strings.TrimSpace(c.cfg.CSCClientID) != ""
}

// CSCAuthorizeParams configures the csc oauth2code consent redirect.
type CSCAuthorizeParams struct {
	State string
	// CodeChallenge is the S256 PKCE challenge.
	CodeChallenge string
	// Scope is the requested scope (service / credential).
	Scope string
	// DocumentDigests is the base64-URL credential-authorization SAD binding the
	// per-document digests the user consents to sign (CSC `documentDigests`).
	DocumentDigests string
}

// CSCAuthorizeURL builds the csc oauth2code consent URL. NOTE (open item Cert):
// the exact PAR / credential-token sequencing depends on the Entrust short-term
// cert mechanism — wired here as a plain code+PKCE authorize with documentDigests.
func (c *Client) CSCAuthorizeURL(p CSCAuthorizeParams) string {
	q := url.Values{}
	q.Set("response_type", "code")
	q.Set("client_id", c.cfg.CSCClientID)
	q.Set("redirect_uri", c.cfg.RedirectURI)
	q.Set("state", p.State)
	q.Set("code_challenge", p.CodeChallenge)
	q.Set("code_challenge_method", "S256")
	if p.Scope != "" {
		q.Set("scope", p.Scope)
	}
	if p.DocumentDigests != "" {
		q.Set("documentDigests", p.DocumentDigests)
	}
	return c.cscBase() + cscPathOAuthAuthorize + "?" + q.Encode()
}

// CSCExchange swaps a csc authorization code for a credential-scoped token using
// PKCE (codeVerifier) and confidential-client Basic auth.
func (c *Client) CSCExchange(ctx context.Context, code, codeVerifier string) (string, error) {
	form := map[string]string{
		"grant_type":    "authorization_code",
		"code":          code,
		"redirect_uri":  c.cfg.RedirectURI,
		"code_verifier": codeVerifier,
		"client_id":     c.cfg.CSCClientID,
	}
	var tr tokenResponse
	if err := c.postForm(ctx, c.cscBase()+cscPathOAuthToken, form, c.basicAuth(c.cfg.CSCClientID, c.cfg.CSCClientSecret), &tr); err != nil {
		return "", err
	}
	if tr.AccessToken == "" {
		return "", fmt.Errorf("entrust: csc token exchange returned no access_token")
	}
	return tr.AccessToken, nil
}

// cscSignHashRequest is the CSC signHash body.
type cscSignHashRequest struct {
	CredentialID string   `json:"credentialID"`
	SAD          string   `json:"SAD,omitempty"` // signature activation data (open: account_token, item E)
	Hashes       []string `json:"hashes"`        // base64 digests, in request order ([CSC v2 §11.13])
	SignAlgo     string   `json:"signAlgo"`      // signature algorithm OID
}

type cscSignHashResponse struct {
	Signatures []string `json:"signatures"`
}

// SignHash signs a set of (base64) hashes with a CSC credential, returning the
// signatures in request order. NOTE (open item K): the CSC-layer ECDSA encoding
// (DER vs raw r‖s) is unconfirmed — the orchestrator normalizes the result to
// DER at the finalize boundary regardless (signing/ecdsa.go), so either is safe.
func (c *Client) SignHash(ctx context.Context, token, credentialID, sad, signAlgo string, hashes []string) ([]string, error) {
	body, err := json.Marshal(cscSignHashRequest{
		CredentialID: credentialID,
		SAD:          sad,
		Hashes:       hashes,
		SignAlgo:     signAlgo,
	})
	if err != nil {
		return nil, err
	}
	var out cscSignHashResponse
	if err := c.postJSONBearer(ctx, c.cscBase()+cscPathSignHash, token, body, &out); err != nil {
		return nil, err
	}
	return out.Signatures, nil
}

// CSCCredential is one entry of credentials/info (subset).
type CSCCredential struct {
	CredentialID string `json:"credentialID"`
	Cert         struct {
		Certificates []string `json:"certificates"` // base64-DER chain (leaf first)
	} `json:"cert"`
	Key struct {
		Algo []string `json:"algo"`
	} `json:"key"`
}

type cscCredsListResponse struct {
	CredentialIDs []string `json:"credentialIDs"`
}

// CredentialsList lists the credential ids available to the token holder.
func (c *Client) CredentialsList(ctx context.Context, token string) ([]string, error) {
	var out cscCredsListResponse
	if err := c.postJSONBearer(ctx, c.cscBase()+cscPathCredsList, token, []byte(`{}`), &out); err != nil {
		return nil, err
	}
	return out.CredentialIDs, nil
}

// CredentialInfo fetches a credential's certificate chain (the leaf cert feeds
// CalculateDigest as the signing cert).
func (c *Client) CredentialInfo(ctx context.Context, token, credentialID string) (CSCCredential, error) {
	body, err := json.Marshal(map[string]any{"credentialID": credentialID, "certificates": "chain", "certInfo": true})
	if err != nil {
		return CSCCredential{}, err
	}
	var out CSCCredential
	if err := c.postJSONBearer(ctx, c.cscBase()+cscPathCredsInfo, token, body, &out); err != nil {
		return CSCCredential{}, err
	}
	out.CredentialID = credentialID
	return out, nil
}
