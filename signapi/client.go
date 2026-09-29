package signapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net"
	"net/http"
	"net/textproto"
	"strings"
	"time"

	"github.com/gmb-lib/go-platform-kit/observability"
	"go.uber.org/zap"
)

// TokenProvider returns the Bearer the SignAPI calls authenticate with — the
// TrustedX introspect token (client-credentials, 600 s, cached). Injected by the
// service so this package stays free of the auth flow.
type TokenProvider func(ctx context.Context) (string, error)

// Client is the typed SignAPI client. It uses an otel-instrumented transport so
// every spine call shows as a client span (no-op when tracing is inert).
type Client struct {
	base  string
	token TokenProvider
	httpc *http.Client
	// quick is the client for the first try of a quick call: it gives up when the
	// answer has not begun within the first-attempt wait, so the retry comes sooner.
	quick *http.Client
	// firstWait is how long that first try waits.
	firstWait time.Duration
	// patient is the client for a call that must be waited on: it waits callLimit
	// for the whole answer.
	patient   *http.Client
	callLimit time.Duration
	log       *zap.Logger
}

// attemptLimit is the most one try of any other SignAPI call may take.
const attemptLimit = 30 * time.Second

// DefaultFirstAttempt is how long the first try of a quick call waits for the
// answer to begin. A session start the provider cannot serve (its session store
// unreachable) answers an error only after about a minute, while the next start is
// served at once; a quick call cut short leaves nothing behind at the provider, so
// asking again sooner is safe.
const DefaultFirstAttempt = 10 * time.Second

// DefaultCallLimit is how long a patient call — CalculateDigest, finalize, the
// archive timestamp, validation — waits for its own answer. The provider serves each
// synchronously and keeps working on a request its caller has given up on, so a
// patient call is never asked twice while the first may still be running.
const DefaultCallLimit = 60 * time.Second

// Option configures a Client.
type Option func(*Client)

// WithFirstAttempt sets how long the first try of a quick call (session start and
// close, list, download) waits for the answer to begin before it is retried. A
// value of zero or less keeps the default.
func WithFirstAttempt(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.firstWait = d
		}
	}
}

// WithCallLimit sets how long a patient call (CalculateDigest, finalize, the
// archive timestamp, validation) waits for its answer. A value of zero or less
// keeps the default.
func WithCallLimit(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.callLimit = d
		}
	}
}

// New builds a SignAPI client for baseURL (e.g. https://eparaksts-dev.zzdats.lv).
// log may be nil; at debug level it logs each call's request/response (bodies are
// digests/sessionIds/containers — never tokens; the Bearer header is not logged).
func New(baseURL string, token TokenProvider, log *zap.Logger, opts ...Option) *Client {
	if log == nil {
		log = zap.NewNop()
	}
	c := &Client{
		base:  strings.TrimSuffix(baseURL, "/"),
		token: token,
		// External authority (eParaksts SignAPI): transport otel-instrumented for
		// client spans; the correlation id is intentionally NOT propagated — a
		// foreign authority ignores it — so this stays a bespoke client, not the
		// context-bound one our own service-to-service calls use.
		httpc:     observability.InstrumentHTTPClient(&http.Client{Timeout: attemptLimit}),
		firstWait: DefaultFirstAttempt,
		callLimit: DefaultCallLimit,
		log:       log,
	}
	for _, o := range opts {
		o(c)
	}
	c.quick = quickClient(c.firstWait)
	c.patient = observability.InstrumentHTTPClient(&http.Client{Timeout: c.callLimit})
	return c
}

// quickClient waits at most wait for the response headers, which bounds a request
// the provider has not begun to answer but never an upload or a download in flight.
func quickClient(wait time.Duration) *http.Client {
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.ResponseHeaderTimeout = wait
	return observability.InstrumentHTTPClient(&http.Client{Timeout: attemptLimit, Transport: t})
}

// StartSession creates a session and returns its id. One session = one signature
// (= one result container); GET → 201.
func (c *Client) StartSession(ctx context.Context, correlationID string) (string, error) {
	var out startResponse
	if err := c.doQuick(ctx, http.MethodGet, "/api-session/v1.0/start", correlationID, nil, "", &out); err != nil {
		return "", err
	}
	if out.Data.SessionID == "" {
		return "", fmt.Errorf("signapi: start session returned no sessionId")
	}
	return out.Data.SessionID, nil
}

// UploadFile uploads document bytes to a session (multipart field "file").
// Returns the uploaded document's own id (data.id — the ASiC-E container or the
// PDF, which is what validation runs on) plus the inner document ids for ASiC-E.
func (c *Client) UploadFile(ctx context.Context, correlationID, sessionID, fileName, mimeType string, data []byte) (UploadResult, error) {
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	hdr := textproto.MIMEHeader{}
	hdr.Set("Content-Disposition", fmt.Sprintf(`form-data; name="file"; filename=%q`, fileName))
	if mimeType != "" {
		hdr.Set("Content-Type", mimeType)
	}
	part, err := mw.CreatePart(hdr)
	if err != nil {
		return UploadResult{}, err
	}
	if _, err := part.Write(data); err != nil {
		return UploadResult{}, err
	}
	if err := mw.Close(); err != nil {
		return UploadResult{}, err
	}

	var out uploadResponse
	if err := c.do(ctx, http.MethodPut, "/api-storage/v1.0/"+sessionID+"/upload", correlationID, body.Bytes(), mw.FormDataContentType(), &out); err != nil {
		return UploadResult{}, err
	}
	res := UploadResult{DocumentID: out.Data.ID, FileName: out.Data.Name}
	for _, d := range out.Data.IncludedDocuments {
		res.IncludedDocuments = append(res.IncludedDocuments, d.ID)
	}
	return res, nil
}

// AddDocumentDigest uploads hashes only (confidential documents). signatureIndex
// is the signature slot (0 for a fresh session).
func (c *Client) AddDocumentDigest(ctx context.Context, correlationID, sessionID string, files []HashFile, signatureIndex int) error {
	req := addDocumentDigestRequest{Files: files, SignatureIndex: signatureIndex}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/api-storage/v1.0/"+sessionID+"/addDocumentDigest", correlationID, b, "application/json", nil)
}

// CalculateDigest computes the data-to-be-signed for the request's sessions. A
// patient call: it prepares the session's signing result at the provider, so a
// second one while the first may still run would prepare it twice.
func (c *Client) CalculateDigest(ctx context.Context, correlationID string, req CalculateDigestRequest) ([]DigestResult, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out calculateDigestResponse
	if err := c.doPatient(ctx, http.MethodPost, "/api-sign/v1.0/CalculateDigest", correlationID, b, "application/json", &out); err != nil {
		return nil, err
	}
	// Flatten: broadcast the shared summary/algorithm onto each session's result
	// so the orchestrator can map per document (all opaque — SCAL2).
	results := make([]DigestResult, 0, len(out.Data.SessionDigests))
	for _, sd := range out.Data.SessionDigests {
		results = append(results, DigestResult{
			SessionID:          sd.SessionID,
			Digest:             sd.Digest,
			DigestsSummary:     out.Data.DigestsSummary,
			Algorithm:          out.Data.Algorithm,
			SignatureAlgorithm: out.Data.SignatureAlgorithm,
		})
	}
	return results, nil
}

// FinalizeSigning applies the signature value(s) and produces the B-LT
// container(s). All-or-nothing (Q G): a 4xx fails the whole request.
//
// finalize is treated as at-most-once: it is NOT retried on a transient/ambiguous
// outcome (the caller re-checks state via List instead), to avoid double-signing.
// It waits the patient-call limit for its answer.
func (c *Client) FinalizeSigning(ctx context.Context, correlationID string, req FinalizeRequest) error {
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return c.doOnce(ctx, http.MethodPost, "/api-sign/v1.0/finalizeSigning", correlationID, b, "application/json", nil)
}

// Validate returns the SignAPI validation report for an already-signed document
// (GET /api-validation/v2.0/{sessionId}/{documentId}/validate). The v2 report nests
// the signing party under signerExt and reports the signing/revocation times and
// the container's included files — the fields the portal's validation answer needs;
// the v1 report omitted them. It returns the upstream status code together with the
// response body UNCHANGED so the caller can relay exactly what SignAPI produced (the
// report is opaque to this service, and the "file is not signed" 4xx error body is
// passed through too). err is non-nil only for a transport failure or a 5xx. A
// patient call: a long-term validation legitimately computes for tens of seconds.
func (c *Client) Validate(ctx context.Context, correlationID, sessionID, documentID string) (int, []byte, error) {
	path := "/api-validation/v2.0/" + sessionID + "/" + documentID + "/validate"
	status, body, err := c.patientCall(ctx, http.MethodGet, path, correlationID, nil, "")
	if err != nil {
		return 0, nil, err
	}
	if status/100 == 5 {
		return 0, nil, fmt.Errorf("signapi: GET %s returned %d: %s", path, status, truncate(body))
	}
	return status, body, nil
}

// AddArchiveTimestamp adds an ARCHIVE_TIMESTAMP to the already-signed document in
// sessionID (POST /api-sign/v1.0/addArchive), authenticated with authCertificate
// (the end-user's auth cert, base64-DER). It is treated as at-most-once (no retry,
// like finalize): re-running would append a second timestamp. It waits the
// patient-call limit for its answer.
func (c *Client) AddArchiveTimestamp(ctx context.Context, correlationID, sessionID, authCertificate string) error {
	req := addArchiveRequest{
		Sessions:        []SessionRef{{SessionID: sessionID}},
		AuthCertificate: authCertificate,
	}
	b, err := json.Marshal(req)
	if err != nil {
		return err
	}
	return c.doOnce(ctx, http.MethodPost, "/api-sign/v1.0/addArchive", correlationID, b, "application/json", nil)
}

// List returns the files in a session (signed results + inner documents).
func (c *Client) List(ctx context.Context, correlationID, sessionID string) ([]FileInfo, error) {
	var out listResponse
	if err := c.doQuick(ctx, http.MethodGet, "/api-storage/v1.0/"+sessionID+"/list", correlationID, nil, "", &out); err != nil {
		return nil, err
	}
	return out.Data, nil
}

// Download streams a stored file's raw bytes. asice selects the ?type=asice
// extension rewrite (cosmetic; same bytes). Upstream serves
// application/octet-stream — the caller sets the real media type itself.
func (c *Client) Download(ctx context.Context, correlationID, sessionID, fileID string, asice bool) ([]byte, error) {
	path := "/api-storage/v1.0/" + sessionID + "/" + fileID
	if asice {
		path += "?type=asice"
	}
	return c.raw(ctx, http.MethodGet, path, correlationID)
}

// CloseSession closes a session (data minimization; sessions otherwise live 24h).
func (c *Client) CloseSession(ctx context.Context, correlationID, sessionID string) error {
	return c.doQuick(ctx, http.MethodGet, "/api-session/v1.0/"+sessionID+"/close", correlationID, nil, "", nil)
}

// --- transport helpers -------------------------------------------------------

// APIError is a definitive non-2xx response from the SignAPI. Status is the
// upstream HTTP status; Body is the (truncated) response body, kept for logs and
// for surfacing a meaningful cause. A 4xx means the request/payload was rejected
// (client-actionable — e.g. the document is not a valid signed document); a 5xx is
// an upstream fault. Callers branch on ClientError to distinguish the two.
type APIError struct {
	Method string
	Path   string
	Status int
	Body   string
}

func (e *APIError) Error() string {
	return fmt.Sprintf("signapi: %s %s returned %d: %s", e.Method, e.Path, e.Status, e.Body)
}

// ClientError reports a definitive 4xx (the request/payload was rejected) as
// opposed to a 5xx or transport fault.
func (e *APIError) ClientError() bool { return e.Status >= 400 && e.Status < 500 }

// do issues a request with up to two retries on 5xx (idempotent calls only).
func (c *Client) do(ctx context.Context, method, path, correlationID string, body []byte, contentType string, out any) error {
	return c.retried(ctx, false, method, path, correlationID, body, contentType, out)
}

// doQuick is do for a call that normally answers at once and is safe to repeat: its
// first try gives up after the first-attempt wait for the answer to begin.
func (c *Client) doQuick(ctx context.Context, method, path, correlationID string, body []byte, contentType string, out any) error {
	return c.retried(ctx, true, method, path, correlationID, body, contentType, out)
}

// client is the HTTP client for one try: the quick one for the first try of a
// quick call, the full-length one otherwise.
func (c *Client) client(quick bool, attempt int) *http.Client {
	if quick && attempt == 0 {
		return c.quick
	}
	return c.httpc
}

func (c *Client) retried(ctx context.Context, quick bool, method, path, correlationID string, body []byte, contentType string, out any) error {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		status, respBody, err := c.send(ctx, c.client(quick, attempt), method, path, correlationID, body, contentType)
		if err != nil {
			lastErr = err
		} else if status/100 == 5 {
			lastErr = &APIError{Method: method, Path: path, Status: status, Body: truncate(respBody)}
		} else if status/100 != 2 {
			return &APIError{Method: method, Path: path, Status: status, Body: truncate(respBody)}
		} else {
			if out != nil && len(respBody) > 0 {
				return json.Unmarshal(respBody, out)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(backoff(attempt)):
		}
	}
	return lastErr
}

// doOnce issues a single request with no retry (finalize: at-most-once).
func (c *Client) doOnce(ctx context.Context, method, path, correlationID string, body []byte, contentType string, out any) error {
	status, respBody, err := c.send(ctx, c.patient, method, path, correlationID, body, contentType)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return &APIError{Method: method, Path: path, Status: status, Body: truncate(respBody)}
	}
	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}

// raw returns the raw response body (for downloads), retrying 5xx. A download
// is a quick call: its first try waits the first-attempt wait for the answer to
// begin, and the transfer itself is bounded only by the full attempt limit.
func (c *Client) raw(ctx context.Context, method, path, correlationID string) ([]byte, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		status, respBody, err := c.send(ctx, c.client(true, attempt), method, path, correlationID, nil, "")
		if err != nil {
			lastErr = err
		} else if status/100 == 5 {
			lastErr = &APIError{Method: method, Path: path, Status: status, Body: truncate(respBody)}
		} else if status/100 != 2 {
			return nil, &APIError{Method: method, Path: path, Status: status, Body: truncate(respBody)}
		} else {
			return respBody, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(backoff(attempt)):
		}
	}
	return nil, lastErr
}

// doPatient issues a patient call and decodes a 2xx answer into out.
func (c *Client) doPatient(ctx context.Context, method, path, correlationID string, body []byte, contentType string, out any) error {
	status, respBody, err := c.patientCall(ctx, method, path, correlationID, body, contentType)
	if err != nil {
		return err
	}
	if status/100 != 2 {
		return &APIError{Method: method, Path: path, Status: status, Body: truncate(respBody)}
	}
	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}

// patientCall waits the patient-call limit for its own answer and asks again only
// when the provider certainly did not take the request (notTaken) — never after a
// timeout, since the provider keeps working on a request its caller gave up on.
func (c *Client) patientCall(ctx context.Context, method, path, correlationID string, body []byte, contentType string) (int, []byte, error) {
	const maxAttempts = 3
	var status int
	var respBody []byte
	var err error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		status, respBody, err = c.send(ctx, c.patient, method, path, correlationID, body, contentType)
		if !notTaken(status, err) {
			return status, respBody, err
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(backoff(attempt)):
		}
	}
	return status, respBody, err
}

// notTaken reports whether the provider certainly did not start the request: no
// connection was made, or the proxy in front of it answered that nothing behind it
// took the request (502, 503). A timeout — ours or a proxy's 504 — is not that.
func notTaken(status int, err error) bool {
	if err != nil {
		var op *net.OpError
		return errors.As(err, &op) && op.Op == "dial"
	}
	return status == http.StatusBadGateway || status == http.StatusServiceUnavailable
}

func (c *Client) send(ctx context.Context, hc *http.Client, method, path, correlationID string, body []byte, contentType string) (int, []byte, error) {
	token, err := c.token(ctx)
	if err != nil {
		return 0, nil, fmt.Errorf("signapi: introspect token: %w", err)
	}

	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	// Build the request on a context stripped of cancellation but keeping its
	// values (the trace span). The request context is a pooled object recycled
	// the instant the handler returns; because this client sets a timeout,
	// net/http would otherwise leave a cancellation-watcher goroutine reading
	// that recycled object afterwards (a data race). The retry loop above still
	// honours the original context's cancellation, and the client's own timeout
	// bounds each call.
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, c.base+path, rdr)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if correlationID != "" {
		req.Header.Set("X-Correlation-ID", correlationID)
	}

	// Debug: log the outbound request. JSON bodies (CalculateDigest, finalize,
	// addDocumentDigest) carry certs/digests — useful and not secret; the Bearer
	// header is never logged. Multipart/binary bodies log only their size.
	if ce := c.log.Check(zap.DebugLevel, "signapi request"); ce != nil {
		fields := []zap.Field{zap.String("method", method), zap.String("path", path), zap.String("correlation_id", correlationID)}
		if contentType == "application/json" && len(body) > 0 {
			fields = append(fields, zap.String("request_body", clip(body, 4096)))
		} else if len(body) > 0 {
			fields = append(fields, zap.Int("request_bytes", len(body)))
		}
		ce.Write(fields...)
	}

	resp, err := hc.Do(req)
	if err != nil {
		c.log.Debug("signapi transport error", zap.String("method", method), zap.String("path", path), zap.Error(err))
		return 0, nil, fmt.Errorf("signapi: %s %s: %w", method, path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<26))
	if err != nil {
		return resp.StatusCode, nil, err
	}

	// Debug: log the response. JSON responses (sessionId, digests, file lists,
	// error JSON) contain no tokens — safe to log; a non-JSON/binary response
	// (an ASiC-E container download) logs only its size, never its bytes.
	if ce := c.log.Check(zap.DebugLevel, "signapi response"); ce != nil {
		fields := []zap.Field{zap.String("method", method), zap.String("path", path), zap.Int("status", resp.StatusCode)}
		if len(respBody) > 0 {
			if isLoggableBody(resp.Header.Get("Content-Type")) {
				fields = append(fields, zap.String("response_body", clip(respBody, 4096)))
			} else {
				fields = append(fields, zap.Int("response_bytes", len(respBody)))
			}
		}
		ce.Write(fields...)
	}

	return resp.StatusCode, respBody, nil
}

// clip returns the first max bytes of b as a string (for debug logging).
func clip(b []byte, max int) string {
	if len(b) > max {
		return string(b[:max]) + "…"
	}
	return string(b)
}

// isLoggableBody reports whether a response body is safe to log at debug. JSON
// and text responses are structured metadata (sessionIds, digests, file lists,
// validation reports, error JSON) — useful and small. A binary download (an
// ASiC-E container, an .edoc, a PDF) is logged as its size only, so document
// bytes never reach the logs. An unset Content-Type is treated as loggable: the
// signing-provider's JSON envelopes are the common case and carry no document
// bytes, while every byte-bearing download declares a binary type.
func isLoggableBody(contentType string) bool {
	ct := strings.ToLower(strings.TrimSpace(contentType))
	if i := strings.IndexByte(ct, ';'); i >= 0 {
		ct = strings.TrimSpace(ct[:i])
	}
	switch {
	case ct == "":
		return true
	case ct == "application/json", strings.HasSuffix(ct, "+json"):
		return true
	case strings.HasPrefix(ct, "text/"):
		return true
	default:
		return false
	}
}

func backoff(attempt int) time.Duration {
	d := 200 * time.Millisecond
	for i := 0; i < attempt; i++ {
		d *= 2
	}
	if d > 2*time.Second {
		d = 2 * time.Second
	}
	return d
}

func truncate(b []byte) string {
	const max = 512
	if len(b) > max {
		return string(b[:max])
	}
	return string(b)
}
