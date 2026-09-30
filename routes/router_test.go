package routes

import (
	"strings"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	api "github.com/signbyte/eparaksts-signer"
)

func testApp(t testing.TB) *azugo.TestApp {
	app := api.TestApp(t)

	err := Init(app)
	qt.Assert(t, qt.IsNil(err))

	return azugo.NewTestApp(app.App)
}

func TestHealthzPublic(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Get("/healthz")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	fasthttp.ReleaseResponse(resp)
}

// TestPrepareRequiresAuth confirms the service API sits behind the inbound auth
// middleware: a request with no service token / test-scope header is rejected.
func TestPrepareRequiresAuth(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	resp, err := app.TestClient().Post("/api/v1/signatures/prepare", []byte(`{}`))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))
	fasthttp.ReleaseResponse(resp)
}

// TestPrepareRejectsUnknownFlow confirms an authenticated request with a bad
// flow is a 400 (the request reaches the handler past auth + scope).
func TestPrepareRejectsUnknownFlow(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	defer app.Stop()

	tc := app.TestClient()
	resp, err := tc.Post("/api/v1/signatures/prepare?flow=nope", []byte(`{"documents":[]}`),
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("Content-Type", "application/json"),
	)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
	fasthttp.ReleaseResponse(resp)

	// No flow at all is refused the same way, and says so: there is no default.
	// The retired single CSC flow is an unknown flow like any other.
	for q, want := range map[string]string{"": "flow is required", "?flow=csc": "unknown flow: csc"} {
		resp, err := tc.Post("/api/v1/signatures/prepare"+q, []byte(`{"documents":[]}`),
			tc.WithHeader("X-Test-Scopes", "signatures:create"),
			tc.WithHeader("Content-Type", "application/json"),
		)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadRequest))
		body, _ := resp.BodyUncompressed()
		qt.Check(t, qt.IsTrue(strings.Contains(string(body), want)), qt.Commentf("%s: %s", q, body))
		fasthttp.ReleaseResponse(resp)
	}
}
