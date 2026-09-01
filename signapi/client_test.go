package signapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

const testToken = "introspect-tok"

// newTestClient returns a SignAPI client pointed at an httptest server running h,
// with a fixed-token provider. The server is closed at test end.
func newTestClient(t *testing.T, h http.HandlerFunc) *Client {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return New(srv.URL, func(context.Context) (string, error) { return testToken, nil }, zap.NewNop())
}

// TestStartSession asserts the verb/path, that the introspect token is sent as
// the Bearer, that the correlation id is forwarded, and that the sessionId is
// parsed out of the {data:{sessionId}} envelope.
func TestStartSession(t *testing.T) {
	var gotMethod, gotPath, gotAuth, gotCorr, gotAccept string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCorr = r.Header.Get("X-Correlation-ID")
		gotAccept = r.Header.Get("Accept")
		_, _ = io.WriteString(w, `{"data":{"sessionId":"sess-1"}}`)
	})

	sid, err := c.StartSession(context.Background(), "corr-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sid, "sess-1"))
	qt.Check(t, qt.Equals(gotMethod, http.MethodGet))
	qt.Check(t, qt.Equals(gotPath, "/api-session/v1.0/start"))
	qt.Check(t, qt.Equals(gotAuth, "Bearer "+testToken))
	qt.Check(t, qt.Equals(gotCorr, "corr-1"))
	qt.Check(t, qt.Equals(gotAccept, "application/json"))
}

// TestStartSessionMissingSessionID surfaces an error when the envelope has no id.
func TestStartSessionMissingSessionID(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `{"data":{}}`)
	})
	_, err := c.StartSession(context.Background(), "corr")
	qt.Assert(t, qt.IsNotNil(err))
}

// TestUploadFile asserts the PUT path, the multipart "file" field (filename +
// bytes), and that the inner ASiC-E document ids are returned.
func TestUploadFile(t *testing.T) {
	var gotMethod, gotPath, gotCT, gotFileName string
	var gotContent []byte
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotCT = r.Header.Get("Content-Type")
		mediaType, params, err := mime.ParseMediaType(gotCT)
		if err == nil && strings.HasPrefix(mediaType, "multipart/") {
			mr := multipart.NewReader(r.Body, params["boundary"])
			for {
				p, err := mr.NextPart()
				if err != nil {
					break
				}
				if p.FormName() == "file" {
					gotFileName = p.FileName()
					gotContent, _ = io.ReadAll(p)
				}
			}
		}
		_, _ = io.WriteString(w, `{"data":{"id":"container-1","name":"invoice-1-1.edoc","includedDocuments":[{"id":"doc-a","name":"a.pdf"},{"id":"doc-b","name":"b.pdf"}]}}`)
	})

	res, err := c.UploadFile(context.Background(), "corr", "sess-1", "invoice.pdf", "application/pdf", []byte("PDFBYTES"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(gotMethod, http.MethodPut))
	qt.Check(t, qt.Equals(gotPath, "/api-storage/v1.0/sess-1/upload"))
	qt.Check(t, qt.IsTrue(strings.HasPrefix(gotCT, "multipart/form-data")))
	qt.Check(t, qt.Equals(gotFileName, "invoice.pdf"))
	qt.Check(t, qt.DeepEquals(gotContent, []byte("PDFBYTES")))
	// data.id is the uploaded document/container; includedDocuments are inner files.
	qt.Check(t, qt.Equals(res.DocumentID, "container-1"))
	qt.Check(t, qt.DeepEquals(res.IncludedDocuments, []string{"doc-a", "doc-b"}))
}

// TestAddDocumentDigest asserts the hash-mode path + body shape.
func TestAddDocumentDigest(t *testing.T) {
	var gotPath string
	var body addDocumentDigestRequest
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	})

	err := c.AddDocumentDigest(context.Background(), "corr", "sess-9",
		[]HashFile{{Name: "t.pdf", Digest: "abc", DigestAlgorithm: "SHA-256"}}, 0)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(gotPath, "/api-storage/v1.0/sess-9/addDocumentDigest"))
	qt.Assert(t, qt.Equals(len(body.Files), 1))
	qt.Check(t, qt.Equals(body.Files[0].Name, "t.pdf"))
	qt.Check(t, qt.Equals(body.Files[0].Digest, "abc"))
	qt.Check(t, qt.Equals(body.Files[0].DigestAlgorithm, "SHA-256"))
	qt.Check(t, qt.Equals(body.SignatureIndex, 0))
}

// TestCalculateDigest asserts the request marshalling (cert + signAsPdf +
// createNewEdoc) and that the shared summary/algorithm are broadcast onto each
// per-session result (the flatten the orchestrator relies on; SCAL2-opaque).
func TestCalculateDigest(t *testing.T) {
	var reqBody CalculateDigestRequest
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		qt.Check(t, qt.Equals(r.URL.Path, "/api-sign/v1.0/CalculateDigest"))
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
		_, _ = io.WriteString(w, `{"data":{"sessionDigests":[{"sessionId":"s1","digest":"D1"},{"sessionId":"s2","digest":"D2"}],"digests_summary":"SUM","algorithm":"SHA256","signature_algorithm":"ECDSA"}}`)
	})

	res, err := c.CalculateDigest(context.Background(), "corr", CalculateDigestRequest{
		Sessions:      []SessionRef{{SessionID: "s1"}, {SessionID: "s2"}},
		Certificate:   "CERT",
		SignAsPdf:     true,
		CreateNewEdoc: true,
	})
	qt.Assert(t, qt.IsNil(err))

	// request faithfully marshalled
	qt.Check(t, qt.Equals(reqBody.Certificate, "CERT"))
	qt.Check(t, qt.IsTrue(reqBody.SignAsPdf))
	qt.Check(t, qt.IsTrue(reqBody.CreateNewEdoc))
	qt.Assert(t, qt.Equals(len(reqBody.Sessions), 2))
	qt.Check(t, qt.Equals(reqBody.Sessions[0].SessionID, "s1"))

	// response flattened with the shared summary/algorithm broadcast per session
	qt.Assert(t, qt.Equals(len(res), 2))
	qt.Check(t, qt.Equals(res[0].SessionID, "s1"))
	qt.Check(t, qt.Equals(res[0].Digest, "D1"))
	qt.Check(t, qt.Equals(res[0].DigestsSummary, "SUM"))
	qt.Check(t, qt.Equals(res[0].Algorithm, "SHA256"))
	qt.Check(t, qt.Equals(res[0].SignatureAlgorithm, "ECDSA"))
	qt.Check(t, qt.Equals(res[1].SessionID, "s2"))
	qt.Check(t, qt.Equals(res[1].Digest, "D2"))
	qt.Check(t, qt.Equals(res[1].DigestsSummary, "SUM"))
}

// TestFinalizeSigningSuccess asserts the verb/path and that the request body
// carries the session signature values + authCertificate.
func TestFinalizeSigningSuccess(t *testing.T) {
	var calls int32
	var gotPath string
	var body FinalizeRequest
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusOK)
	})

	err := c.FinalizeSigning(context.Background(), "corr", FinalizeRequest{
		SessionSignatureValues: []SessionSignatureValue{{SessionID: "s1", SignatureValue: "SIG"}},
		AuthCertificate:        "AUTHCERT",
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(atomic.LoadInt32(&calls), 1))
	qt.Check(t, qt.Equals(gotPath, "/api-sign/v1.0/finalizeSigning"))
	qt.Assert(t, qt.Equals(len(body.SessionSignatureValues), 1))
	qt.Check(t, qt.Equals(body.SessionSignatureValues[0].SessionID, "s1"))
	qt.Check(t, qt.Equals(body.AuthCertificate, "AUTHCERT"))
}

// TestFinalizeSigningAtMostOnce is the safety-critical one: finalize must NOT be
// retried on a 5xx (it is at-most-once, to avoid double-signing). The handler
// 500s; the client must call it exactly once and surface the error.
func TestFinalizeSigningAtMostOnce(t *testing.T) {
	var calls int32
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = io.WriteString(w, `{"error":"boom"}`)
	})

	err := c.FinalizeSigning(context.Background(), "corr", FinalizeRequest{
		SessionSignatureValues: []SessionSignatureValue{{SessionID: "s1", SignatureValue: "SIG"}},
		AuthCertificate:        "A",
	})
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(atomic.LoadInt32(&calls), 1)) // NOT retried
}

// TestDoRetriesOn5xx confirms idempotent calls (here StartSession) retry on 5xx
// and recover (the client's do() does up to 3 attempts).
func TestDoRetriesOn5xx(t *testing.T) {
	var calls int32
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&calls, 1) < 3 {
			w.WriteHeader(http.StatusBadGateway) // 502 → retry
			return
		}
		_, _ = io.WriteString(w, `{"data":{"sessionId":"ok"}}`)
	})

	sid, err := c.StartSession(context.Background(), "corr")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sid, "ok"))
	qt.Check(t, qt.Equals(atomic.LoadInt32(&calls), 3))
}

// TestDoNoRetryOn4xx confirms a 4xx is returned immediately (not retried).
func TestDoNoRetryOn4xx(t *testing.T) {
	var calls int32
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusBadRequest)
	})

	_, err := c.StartSession(context.Background(), "corr")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(atomic.LoadInt32(&calls), 1))
}

// TestDoReturnsTypedAPIError confirms a non-2xx surfaces as a typed *APIError
// carrying the upstream status, so a caller can tell a definitive rejection (4xx,
// client-actionable) from an upstream fault (5xx) instead of collapsing to a 502.
func TestDoReturnsTypedAPIError(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"data":{"results":[{"error":{"code":"signing:addArchive"}}]}}`)
	})

	_, err := c.StartSession(context.Background(), "corr")
	qt.Assert(t, qt.IsNotNil(err))
	var ae *APIError
	qt.Assert(t, qt.IsTrue(errors.As(err, &ae)))
	qt.Check(t, qt.Equals(ae.Status, http.StatusBadRequest))
	qt.Check(t, qt.IsTrue(ae.ClientError()))
}

// TestListAndDownload asserts the list path + parse, and that Download appends
// ?type=asice and returns the raw bytes verbatim (caller sets the media type).
func TestListAndDownload(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.HasSuffix(r.URL.Path, "/list"):
			qt.Check(t, qt.Equals(r.URL.Path, "/api-storage/v1.0/sess-7/list"))
			_, _ = io.WriteString(w, `{"data":[{"id":"f1","name":"a.edoc","size":10},{"id":"f2","name":"signed.edoc","size":20}]}`)
		default:
			qt.Check(t, qt.Equals(r.URL.Path, "/api-storage/v1.0/sess-7/f2"))
			qt.Check(t, qt.Equals(r.URL.Query().Get("type"), "asice"))
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("CONTAINERBYTES"))
		}
	})

	files, err := c.List(context.Background(), "corr", "sess-7")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(files), 2))
	qt.Check(t, qt.Equals(files[1].ID, "f2"))
	qt.Check(t, qt.Equals(files[1].Name, "signed.edoc"))

	data, err := c.Download(context.Background(), "corr", "sess-7", "f2", true)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(data, []byte("CONTAINERBYTES")))
}

// TestDownloadDefaultNoType confirms the default download omits ?type=asice.
func TestDownloadDefaultNoType(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		qt.Check(t, qt.Equals(r.URL.RawQuery, ""))
		_, _ = w.Write([]byte("X"))
	})
	_, err := c.Download(context.Background(), "corr", "sess-1", "f1", false)
	qt.Assert(t, qt.IsNil(err))
}

// TestValidate asserts the validate verb/path/headers and that the SignAPI report
// body + status are returned VERBATIM (pass-through).
func TestValidate(t *testing.T) {
	const report = `{"data":{"signatureForm":"ASiC-E","signaturesCount":1,"validSignaturesCount":1}}`
	var gotMethod, gotPath, gotAuth, gotCorr string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotCorr = r.Header.Get("X-Correlation-ID")
		_, _ = io.WriteString(w, report)
	})

	status, body, err := c.Validate(context.Background(), "corr-1", "sess-1", "doc-1")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(status, http.StatusOK))
	qt.Check(t, qt.Equals(string(body), report))
	qt.Check(t, qt.Equals(gotMethod, http.MethodGet))
	qt.Check(t, qt.Equals(gotPath, "/api-validation/v2.0/sess-1/doc-1/validate"))
	qt.Check(t, qt.Equals(gotAuth, "Bearer "+testToken))
	qt.Check(t, qt.Equals(gotCorr, "corr-1"))
}

// TestValidatePassesThrough4xx confirms a definitive 4xx (e.g. "file is not
// signed") is returned with its body, not turned into a transport error.
func TestValidatePassesThrough4xx(t *testing.T) {
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, `{"error":"file is not signed"}`)
	})

	status, body, err := c.Validate(context.Background(), "corr", "sess", "doc")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(status, http.StatusBadRequest))
	qt.Check(t, qt.Equals(string(body), `{"error":"file is not signed"}`))
}

// TestAddArchiveTimestamp asserts the verb/path and that the body carries the
// session + authCertificate, and that it is at-most-once (no 5xx retry).
func TestAddArchiveTimestamp(t *testing.T) {
	var calls int32
	var gotPath string
	var body addArchiveRequest
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&calls, 1)
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&body)
		_, _ = io.WriteString(w, `{"data":{"results":[{"sessionId":"sess-1"}]}}`)
	})

	err := c.AddArchiveTimestamp(context.Background(), "corr", "sess-1", "AUTHCERT")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(atomic.LoadInt32(&calls), 1))
	qt.Check(t, qt.Equals(gotPath, "/api-sign/v1.0/addArchive"))
	qt.Assert(t, qt.Equals(len(body.Sessions), 1))
	qt.Check(t, qt.Equals(body.Sessions[0].SessionID, "sess-1"))
	qt.Check(t, qt.Equals(body.AuthCertificate, "AUTHCERT"))
}

// TestAddArchiveTimestampAtMostOnce confirms a 5xx is NOT retried (like finalize).
func TestAddArchiveTimestampAtMostOnce(t *testing.T) {
	var calls int32
	c := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&calls, 1)
		w.WriteHeader(http.StatusInternalServerError)
	})

	err := c.AddArchiveTimestamp(context.Background(), "corr", "sess-1", "A")
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.Equals(atomic.LoadInt32(&calls), 1))
}

// TestCloseSession asserts the close verb/path.
func TestCloseSession(t *testing.T) {
	var gotMethod, gotPath string
	c := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod, gotPath = r.Method, r.URL.Path
		w.WriteHeader(http.StatusOK)
	})

	err := c.CloseSession(context.Background(), "corr", "sess-3")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(gotMethod, http.MethodGet))
	qt.Check(t, qt.Equals(gotPath, "/api-session/v1.0/sess-3/close"))
}

// TestResponseLoggingElidesBinaryDownloads proves the debug response log records
// a binary container download's SIZE only — never its bytes — while a JSON
// response body is still logged. A signed ASiC-E container must never leak into
// the logs.
func TestResponseLoggingElidesBinaryDownloads(t *testing.T) {
	core, logs := observer.New(zapcore.DebugLevel)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("type") == "asice" {
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write([]byte("PK\x03\x04signed-container-bytes-must-not-be-logged"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"data":{"sessionId":"s1"}}`)
	}))
	t.Cleanup(srv.Close)
	c := New(srv.URL, func(context.Context) (string, error) { return testToken, nil }, zap.New(core))

	_, err := c.Download(context.Background(), "corr", "sess-1", "f1", true) // binary container download
	qt.Assert(t, qt.IsNil(err))
	_, err = c.StartSession(context.Background(), "corr") // JSON API call
	qt.Assert(t, qt.IsNil(err))

	var sawBinarySizeOnly, sawJSONBody bool
	for _, e := range logs.FilterMessage("signapi response").All() {
		m := e.ContextMap()
		if body, ok := m["response_body"].(string); ok {
			sawJSONBody = true
			if strings.Contains(body, "signed-container-bytes") {
				t.Fatalf("document bytes leaked into the response log: %q", body)
			}
		}
		if _, ok := m["response_bytes"]; ok {
			sawBinarySizeOnly = true
		}
	}
	qt.Check(t, qt.Equals(sawBinarySizeOnly, true)) // the asice download logged size only
	qt.Check(t, qt.Equals(sawJSONBody, true))       // the JSON response still logged its body
}
