package routes

import (
	"bytes"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// multipartBody builds a multipart/form-data body with an optional file part and
// optional extra text fields. Returns the body bytes + the Content-Type header.
func multipartBody(t *testing.T, fileField, fileName string, fileData []byte, fields map[string]string) ([]byte, string) {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if fileField != "" {
		fw, err := w.CreateFormFile(fileField, fileName)
		qt.Assert(t, qt.IsNil(err))
		_, err = fw.Write(fileData)
		qt.Assert(t, qt.IsNil(err))
	}
	for k, v := range fields {
		qt.Assert(t, qt.IsNil(w.WriteField(k, v)))
	}
	qt.Assert(t, qt.IsNil(w.Close()))
	return buf.Bytes(), w.FormDataContentType()
}

// TestValidateForbiddenWithoutReadScope confirms /validations enforces
// signatures:read (the scope check runs before any upstream work).
func TestValidateForbiddenWithoutReadScope(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	body, ct := multipartBody(t, "file", "x.pdf", []byte("PDF"), nil)
	resp, err := tc.Post("/api/v1/validations", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("Content-Type", ct),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
}

// TestValidateRejectsNonMultipart confirms a non-multipart body is a 400 before
// any SignAPI call.
func TestValidateRejectsNonMultipart(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/validations", []byte(`{}`),
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

// TestArchiveForbiddenWithoutWriteScope confirms /archive-timestamps enforces
// signatures:write.
func TestArchiveForbiddenWithoutWriteScope(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	body, ct := multipartBody(t, "file", "signed.edoc", []byte("EDOC"), nil)
	resp, err := tc.Post("/api/v1/archive-timestamps", body,
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
		tc.WithHeader("Content-Type", ct),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
}

// TestArchiveMissingAuthCert confirms that with neither a request authCertificate
// nor CSC_AUTH_CERT set, the archive request is a 400 missing_auth_certificate —
// surfaced before any SignAPI call.
func TestArchiveMissingAuthCert(t *testing.T) {
	t.Setenv("CSC_AUTH_CERT", "") // ensure no env fallback
	// This test targets the auth-certificate branch; the fake "EDOC" bytes
	// would (correctly) die at the document gate first, so it is disabled here
	// — gate behavior has its own tests.
	t.Setenv("UPLOAD_HARDENING", "false")
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	body, ct := multipartBody(t, "file", "signed.edoc", []byte("EDOC"), nil)
	resp, err := tc.Post("/api/v1/archive-timestamps", body,
		tc.WithHeader("X-Test-Scopes", "signatures:write"),
		tc.WithHeader("Content-Type", ct),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(buf), "err:signing:missingAuthCertificate")))
}

// TestArchiveMissingFilePart confirms a multipart body without a `file` part is a
// 400.
func TestArchiveMissingFilePart(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	body, ct := multipartBody(t, "", "", nil, map[string]string{"authCertificate": "CERT"})
	resp, err := tc.Post("/api/v1/archive-timestamps", body,
		tc.WithHeader("X-Test-Scopes", "signatures:write"),
		tc.WithHeader("Content-Type", ct),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

// TestArchiveJobDocForbiddenWithoutWriteScope confirms the job-based archive
// endpoint enforces signatures:write (no Redis needed — the scope check precedes
// the job load).
func TestArchiveJobDocForbiddenWithoutWriteScope(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signatures/abc/documents/d1/archive", nil,
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
}
