package routes

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// The server-wide body limit defaults to 64 MiB (a multi-file signing
// preparation), not the framework's 4 MiB.
func TestBodyLimitDefault(t *testing.T) {
	app := testApp(t)
	qt.Check(t, qt.Equals(app.Config().Server.MaxRequestBodySize, 64*1024*1024))
}

// SERVER_MAX_REQUEST_BODY_SIZE overrides the default; a body over it answers 413.
func TestUploadOverBodyLimitIs413(t *testing.T) {
	t.Setenv("SERVER_MAX_REQUEST_BODY_SIZE", "2048")
	t.Setenv("UPLOAD_HARDENING", "false")
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	body, ct := multipartBody(t, "file", "x.edoc", []byte(strings.Repeat("a", 4096)), nil)
	resp, err := tc.Post("/api/v1/validations", body,
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
		tc.WithHeader("Content-Type", ct),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge))
	qt.Check(t, qt.IsTrue(strings.Contains(string(resp.Header.ContentType()), "problem+json")))
}

// A body just under the limit is read (it then fails later on, not with 413).
func TestUploadUnderBodyLimitIsRead(t *testing.T) {
	t.Setenv("SERVER_MAX_REQUEST_BODY_SIZE", "8192")
	t.Setenv("UPLOAD_HARDENING", "false")
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	body, ct := multipartBody(t, "file", "x.edoc", []byte(strings.Repeat("a", 2048)), nil)
	resp, err := tc.Post("/api/v1/archive-timestamps", body,
		tc.WithHeader("X-Test-Scopes", "signatures:write"),
		tc.WithHeader("Content-Type", ct),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusRequestEntityTooLarge)))
	qt.Check(t, qt.Not(qt.Equals(resp.StatusCode(), fasthttp.StatusInternalServerError)))
}

// A multipart body that cannot be parsed answers 400.
func TestMalformedMultipartIs400(t *testing.T) {
	t.Setenv("UPLOAD_HARDENING", "false")
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/validations", []byte("--nope\r\nbroken"),
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
		tc.WithHeader("Content-Type", "multipart/form-data; boundary=wrong"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(buf), "err:signing:invalidRequest")))
}

// A malformed JSON body on the hash-only prepare path keeps the service's own
// problem code.
func TestPrepareMalformedJSONKeepsServiceCode(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signatures/prepare?flow=webEid", []byte("{not json"),
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(buf), "err:signing:invalidRequest")))
}
