package routes

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// postPrepare posts a JSON prepare body for the given flow with the given test
// scopes. The hash-only JSON path validates the request DTO before any upstream
// call, so these tests need no Redis / SignAPI.
func postPrepare(t *testing.T, scopes, flow, body string) *fasthttp.Response {
	t.Helper()
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signatures/prepare?flow="+flow, []byte(body),
		tc.WithHeader("X-Test-Scopes", scopes),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	return resp
}

// TestPrepareForbiddenWithoutCreateScope confirms the per-endpoint scope check
// rejects an authenticated caller that lacks signatures:create.
func TestPrepareForbiddenWithoutCreateScope(t *testing.T) {
	resp := postPrepare(t, "signatures:read", "webEid", `{}`)
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
}

// TestPrepareValidationErrors confirms malformed prepare metadata is a 400 before
// any flow work runs.
func TestPrepareValidationErrors(t *testing.T) {
	cases := map[string]string{
		"no documents field":  `{}`,
		"empty documents":     `{"documents":[]}`,
		"missing documentId":  `{"documents":[{"fileName":"f.txt","signatureFormat":"XAdES","documentHash":"aGk="}]}`,
		"missing fileName":    `{"documents":[{"documentId":"d1","signatureFormat":"XAdES","documentHash":"aGk="}]}`,
		"bad signatureFormat": `{"documents":[{"documentId":"d1","fileName":"f.txt","signatureFormat":"JAdES","documentHash":"aGk="}]}`,
		"bad operation":       `{"documents":[{"documentId":"d1","fileName":"f.txt","signatureFormat":"XAdES","operation":"replace","documentHash":"aGk="}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			resp := postPrepare(t, "signatures:create", "webEid", body)
			defer fasthttp.ReleaseResponse(resp)
			qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
		})
	}
}

// TestPrepareEIDRequiresSigningCert confirms a well-formed webEid hash-only request
// without a signing certificate is rejected by the handler's webEid guard (400),
// surfacing the signingCertificate requirement.
func TestPrepareEIDRequiresSigningCert(t *testing.T) {
	body := `{"documents":[{"documentId":"d1","fileName":"f.txt","signatureFormat":"XAdES","documentHash":"aGk="}]}`
	resp := postPrepare(t, "signatures:create", "webEid", body)
	defer fasthttp.ReleaseResponse(resp)

	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(buf), "signingCertificate")))
}

// TestSubmitForbiddenWithoutWriteScope confirms the eid submit endpoint enforces
// signatures:write.
func TestSubmitForbiddenWithoutWriteScope(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signatures/abc/signatures", []byte(`{}`),
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden))
}

// TestSubmitMalformedJSON confirms a body that is not valid JSON is a 400 (parsed
// before the job is loaded, so no Redis needed).
func TestSubmitMalformedJSON(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signatures/abc/signatures", []byte(`{ not json`),
		tc.WithHeader("X-Test-Scopes", "signatures:write"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
}

// TestSubmitEmptySignatures confirms the SubmitSignatures DTO's min=1 rule is a
// client error.
func TestSubmitEmptySignatures(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signatures/abc/signatures", []byte(`{"signatures":[]}`),
		tc.WithHeader("X-Test-Scopes", "signatures:write"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(resp.StatusCode() >= 400 && resp.StatusCode() < 500))
}
