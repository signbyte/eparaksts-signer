package signapi

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
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
	log   *zap.Logger
}

// New builds a SignAPI client for baseURL (e.g. https://eparaksts-dev.zzdats.lv).
// log may be nil; at debug level it logs each call's request/response (bodies are
// digests/sessionIds/containers — never tokens; the Bearer header is not logged).
func New(baseURL string, token TokenProvider, log *zap.Logger) *Client {
	if log == nil {
		log = zap.NewNop()
	}
	return &Client{
		base:  strings.TrimSuffix(baseURL, "/"),
		token: token,
		// External authority (eParaksts SignAPI): transport otel-instrumented for
		// client spans; the correlation id is intentionally NOT propagated — a
		// foreign authority ignores it — so this stays a bespoke client, not the
		// context-bound one our own service-to-service calls use.
		httpc: observability.InstrumentHTTPClient(&http.Client{Timeout: 30 * time.Second}),
		log:   log,
	}
}

// StartSession creates a session and returns its id. One session = one signature
// (= one result container); GET → 201.
func (c *Client) StartSession(ctx context.Context, correlationID string) (string, error) {
	var out startResponse
	if err := c.do(ctx, http.MethodGet, "/api-session/v1.0/start", correlationID, nil, "", &out); err != nil {
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

// CalculateDigest computes the data-to-be-signed for the request's sessions.
func (c *Client) CalculateDigest(ctx context.Context, correlationID string, req CalculateDigestRequest) ([]DigestResult, error) {
	b, err := json.Marshal(req)
	if err != nil {
		return nil, err
	}
	var out calculateDigestResponse
	if err := c.do(ctx, http.MethodPost, "/api-sign/v1.0/CalculateDigest", correlationID, b, "application/json", &out); err != nil {
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
// passed through too). err is non-nil only for a transport failure or a 5xx that
// survived retries.
func (c *Client) Validate(ctx context.Context, correlationID, sessionID, documentID string) (int, []byte, error) {
	path := "/api-validation/v2.0/" + sessionID + "/" + documentID + "/validate"
	return c.getRetry(ctx, http.MethodGet, path, correlationID)
}

// AddArchiveTimestamp adds an ARCHIVE_TIMESTAMP to the already-signed document in
// sessionID (POST /api-sign/v1.0/addArchive), authenticated with authCertificate
// (the end-user's auth cert, base64-DER). It is treated as at-most-once (no retry,
// like finalize): re-running would append a second timestamp.
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
	if err := c.do(ctx, http.MethodGet, "/api-storage/v1.0/"+sessionID+"/list", correlationID, nil, "", &out); err != nil {
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
	return c.do(ctx, http.MethodGet, "/api-session/v1.0/"+sessionID+"/close", correlationID, nil, "", nil)
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
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		status, respBody, err := c.send(ctx, method, path, correlationID, body, contentType)
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
	status, respBody, err := c.send(ctx, method, path, correlationID, body, contentType)
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

// raw returns the raw response body (for downloads), retrying 5xx.
func (c *Client) raw(ctx context.Context, method, path, correlationID string) ([]byte, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		status, respBody, err := c.send(ctx, method, path, correlationID, nil, "")
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

// getRetry issues a bodyless request, retrying 5xx, and returns the status code +
// raw body for any definitive (non-5xx) response so the caller can relay both. Used
// by Validate to pass the SignAPI report (or its error JSON) through verbatim.
func (c *Client) getRetry(ctx context.Context, method, path, correlationID string) (int, []byte, error) {
	const maxAttempts = 3
	var lastErr error
	for attempt := 0; attempt < maxAttempts; attempt++ {
		status, respBody, err := c.send(ctx, method, path, correlationID, nil, "")
		if err != nil {
			lastErr = err
		} else if status/100 == 5 {
			lastErr = fmt.Errorf("signapi: %s %s returned %d: %s", method, path, status, truncate(respBody))
		} else {
			return status, respBody, nil
		}
		select {
		case <-ctx.Done():
			return 0, nil, ctx.Err()
		case <-time.After(backoff(attempt)):
		}
	}
	return 0, nil, lastErr
}

func (c *Client) send(ctx context.Context, method, path, correlationID string, body []byte, contentType string) (int, []byte, error) {
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

	resp, err := c.httpc.Do(req)
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
