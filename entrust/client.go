// Package entrust is the client for the eParaksts Integration Platform
// (Entrust / TrustedX / Safelayer) — ONE platform with TWO surfaces:
//
// - the existing TrustedX surface (eParaksts Mobile, eID-scan, cloud eSeal):
// OAuth two-redirect dance, users/me + sign_identities, server/raw + device/raw;
// - the new CSC API layer (csc flow): info / oauth2code / credentials / signHash.
//
// Plus the process-wide TrustedX introspect token (client-credentials, 600 s)
// that authenticates every SignAPI call. The TrustedX surface is verified against
// manual traces; some CSC-layer behaviours remain blocked on the platform update.
//
// All HTTP uses an otel-instrumented transport so the calls to the QTSP show as
// client spans (go-platform-kit observability; no-op when tracing is inert).
package entrust

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gmb-lib/go-platform-kit/observability"
	"go.uber.org/zap"
)

// IntrospectScope is the scope of the SignAPI Bearer token used to introspect
// the upstream authorization.
const IntrospectScope = "urn:safelayer:eidas:oauth:token:introspect"

// Config configures the platform client.
type Config struct {
	// TrustedX surface.
	BaseURL      string // https://eidas-demo.eparaksts.lv | prod
	ASPath       string // /trustedx-authserver/oauth/lvrtc-eipsign-as
	ClientID     string
	ClientSecret string
	RedirectURI  string // https://<signer>/api/v1/signatures/callback

	// ACR values per flow (eParaksts Mobile / eID-scan).
	ACRMobile     string
	ACREIDScan    string
	ACRCloudEseal string

	// CSC API layer (may share BaseURL; partly open).
	CSCBaseURL      string
	CSCClientID     string
	CSCClientSecret string

	// IdentityFetchRetries / IdentityFetchDelay bound the sign_identities/{id}
	// retry loop (identities may materialize asynchronously after first login).
	IdentityFetchRetries int
	IdentityFetchDelay   time.Duration

	// EarlyRefresh refreshes the introspect token this long before it expires.
	EarlyRefresh time.Duration
}

// Client talks to the eParaksts platform across both surfaces.
type Client struct {
	cfg   Config
	httpc *http.Client
	log   *zap.Logger

	mu              sync.Mutex
	introspectTok   string
	introspectExpAt time.Time
}

// New builds a platform client. log may be nil.
func New(cfg Config, log *zap.Logger) *Client {
	if log == nil {
		log = zap.NewNop()
	}
	if cfg.IdentityFetchRetries <= 0 {
		cfg.IdentityFetchRetries = 5
	}
	if cfg.IdentityFetchDelay <= 0 {
		cfg.IdentityFetchDelay = 2 * time.Second
	}
	if cfg.EarlyRefresh <= 0 {
		cfg.EarlyRefresh = 60 * time.Second
	}
	cfg.BaseURL = strings.TrimSuffix(cfg.BaseURL, "/")
	cfg.CSCBaseURL = strings.TrimSuffix(cfg.CSCBaseURL, "/")
	return &Client{
		cfg: cfg,
		// External authority (eParaksts/Entrust): transport otel-instrumented for
		// client spans; the correlation id is intentionally NOT propagated — a
		// foreign authority ignores it — so this stays a bespoke client, not the
		// context-bound one our own service-to-service calls use.
		httpc: observability.InstrumentHTTPClient(&http.Client{Timeout: 20 * time.Second}),
		log:   log,
	}
}

// tokenEndpoint is the TrustedX AS token endpoint.
func (c *Client) tokenEndpoint() string {
	return c.cfg.BaseURL + c.cfg.ASPath + "/token"
}

// authorizeEndpoint is the TrustedX AS authorize endpoint.
func (c *Client) authorizeEndpoint() string {
	return c.cfg.BaseURL + c.cfg.ASPath
}

// IntrospectToken returns a cached TrustedX introspect token, minting one via
// client-credentials when none is cached or the cached one is near expiry. Used
// as the SignAPI Bearer. Process-wide (not job-bound), refreshed early.
func (c *Client) IntrospectToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	if c.introspectTok != "" && time.Until(c.introspectExpAt) > c.cfg.EarlyRefresh {
		tok := c.introspectTok
		c.mu.Unlock()
		return tok, nil
	}
	c.mu.Unlock()

	tok, ttl, err := c.clientCredentials(ctx, IntrospectScope)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.introspectTok = tok
	c.introspectExpAt = time.Now().Add(ttl)
	c.mu.Unlock()
	return tok, nil
}

// clientCredentials performs a client-credentials grant for scope on the
// TrustedX AS, returning the access token and its TTL.
func (c *Client) clientCredentials(ctx context.Context, scope string) (string, time.Duration, error) {
	form := map[string]string{
		"grant_type": "client_credentials",
		"scope":      scope,
	}
	var tr tokenResponse
	if err := c.postForm(ctx, c.tokenEndpoint(), form, c.basicAuth(c.cfg.ClientID, c.cfg.ClientSecret), &tr); err != nil {
		return "", 0, err
	}
	return tr.AccessToken, time.Duration(tr.ExpiresIn) * time.Second, nil
}

// tokenResponse is the OAuth token-endpoint response.
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token,omitempty"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
	Scope        string `json:"scope,omitempty"`
}

func (c *Client) basicAuth(id, secret string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(id+":"+secret))
}

// outboundCtx strips cancellation from a request-scoped context while keeping
// its values (the trace span). The request context is a pooled object the
// framework recycles the instant the handler returns; because this client sets a
// timeout, net/http would otherwise derive a cancellable child from it and leave
// a cancellation-watcher goroutine reading that recycled object afterwards (a
// data race). The client's own timeout still bounds each call, and the trace
// span survives so the call still shows as a client span.
func outboundCtx(ctx context.Context) context.Context {
	return context.WithoutCancel(ctx)
}

// postForm posts an application/x-www-form-urlencoded body with the given
// Authorization header and unmarshals a JSON response into out (may be nil).
func (c *Client) postForm(ctx context.Context, endpoint string, form map[string]string, authz string, out any) error {
	values := url.Values{}
	for k, v := range form {
		values.Set(k, v)
	}

	req, err := http.NewRequestWithContext(outboundCtx(ctx), http.MethodPost, endpoint, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=UTF-8")
	req.Header.Set("Accept", "application/json")
	if authz != "" {
		req.Header.Set("Authorization", authz)
	}
	return c.doJSON(req, out)
}

// getJSON performs a Bearer-authenticated GET, unmarshalling into out.
func (c *Client) getJSON(ctx context.Context, url, bearer string, out any) error {
	req, err := http.NewRequestWithContext(outboundCtx(ctx), http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	return c.doJSON(req, out)
}

// postJSONBearer performs a Bearer-authenticated JSON POST.
func (c *Client) postJSONBearer(ctx context.Context, url, bearer string, body []byte, out any) error {
	req, err := http.NewRequestWithContext(outboundCtx(ctx), http.MethodPost, url, strings.NewReader(string(body)))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.doJSON(req, out)
}

// newRequest builds a Bearer-authenticated request with no body.
func newRequest(ctx context.Context, method, url, bearer string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(outboundCtx(ctx), method, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Accept", "application/json")
	return req, nil
}

func (c *Client) doJSON(req *http.Request, out any) error {
	resp, err := c.httpc.Do(req)
	if err != nil {
		return fmt.Errorf("entrust: %s %s: %w", req.Method, req.URL.Path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<22))
	if err != nil {
		return err
	}
	// Debug: log method/url/status only — NOT the body. Token-endpoint responses
	// (introspect, code exchange) contain access_token, and resource responses
	// (users/me, sign_identities) contain PII; neither belongs in the log.
	c.log.Debug("entrust http", zap.String("method", req.Method), zap.String("url", req.URL.String()), zap.Int("status", resp.StatusCode))
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("entrust: %s %s returned %d: %s", req.Method, req.URL.Path, resp.StatusCode, truncate(body))
	}
	if out != nil && len(body) > 0 {
		return json.Unmarshal(body, out)
	}
	return nil
}

func truncate(b []byte) string {
	const max = 512
	if len(b) > max {
		return string(b[:max])
	}
	return string(b)
}
