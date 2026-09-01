package eparakstssigner

import (
	"testing"

	"azugo.io/azugo"
	"azugo.io/azugo/token"
	"azugo.io/azugo/user"
	"github.com/go-quicktest/qt"
)

// TestApp builds an App for tests with a stub auth middleware driven by the
// X-Test-Scopes request header (production wiring always uses the go-authbyte
// DPoP middleware). Redis is configured but go-redis connects lazily, so New()
// does not require a running Redis; tests that exercise the job store need one.
func TestApp(tb testing.TB) *App {
	tb.Helper()

	tb.Setenv("METRICS_ENABLED", "false")
	tb.Setenv("SERVICE_NAME", "eparaksts-signer")
	tb.Setenv("ENVIRONMENT", "development")
	tb.Setenv("AUTH_ISSUER_URL", "http://localhost:8080")
	tb.Setenv("SERVICE_AUDIENCE", "svc:eparaksts-signer")
	tb.Setenv("REDIS_URL", "redis://localhost:6379/0")

	app, err := New(nil, "0.0.0-test")
	qt.Assert(tb, qt.IsNil(err))

	app.SetAuthMiddleware(TestAuthMiddleware())
	return app
}

// TestAuthMiddleware authenticates requests carrying the X-Test-Scopes header
// (comma- or space-separated scopes, e.g. "signatures:create"). Requests without
// it are rejected 401 — mirroring the production middleware contract.
func TestAuthMiddleware() azugo.RequestHandlerFunc {
	return func(next azugo.RequestHandler) azugo.RequestHandler {
		return func(ctx *azugo.Context) {
			scopes := ctx.Header.Get("X-Test-Scopes")
			if scopes == "" {
				ctx.StatusCode(401)
				ctx.Text("unauthorized")
				return
			}
			ctx.SetUser(user.NewIdentity("svc:test-client", scopes, map[string]token.ClaimStrings{}))
			next(ctx)
		}
	}
}
