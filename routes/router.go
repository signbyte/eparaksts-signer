// Package routes registers the eParaksts Signing Service inbound HTTP API.
// All /api/v1/signatures/* endpoints are
// service-to-service (Portal-API), gated by the go-authbyte DPoP middleware and
// per-endpoint scopes — EXCEPT the OAuth callback, which is the only
// browser-facing endpoint (secured by `state` + PKCE, not DPoP).
package routes

import (
	"azugo.io/azugo"
	corehttp "azugo.io/core/http"

	app "github.com/signbyte/eparaksts-signer"
)

// Scope groups / levels.
const (
	scopeResource = "signatures"
	levelCreate   = "create"
	levelWrite    = "write"
	levelRead     = "read"
)

type router struct {
	*app.App
}

// Init registers all routes.
func Init(a *app.App) error {
	r := &router{App: a}

	// Public probes.
	a.Get("/healthz", r.healthz)
	a.Get("/readyz", r.readyz)

	// Public browser callback (state + PKCE; NOT behind DPoP). Mounted outside the
	// secured group so the inbound auth middleware does not reject the browser. The
	// path is configurable (derived from TX_REDIRECT_URI) so it can match an
	// already-registered redirect URI (e.g. /Sign/Complete); default
	// /api/v1/signatures/callback.
	a.Get(a.CallbackPath(), r.callback)

	// Service-to-service signing API (DPoP-gated).
	api := a.Group("/api/v1")
	api.Use(a.AuthMiddleware())
	api.Post("/signatures/prepare", r.scoped(levelCreate, r.prepare))
	api.Post("/signatures/{jobId}/signatures", r.scoped(levelWrite, r.submit))
	api.Get("/signatures/{jobId}/status", r.scoped(levelRead, r.status))
	api.Get("/signatures/{jobId}/documents/{documentId}", r.scoped(levelRead, r.download))
	api.Post("/signatures/{jobId}/documents/{documentId}/archive", r.scoped(levelWrite, r.archiveJobDoc))
	api.Delete("/signatures/{jobId}", r.scoped(levelWrite, r.deleteJob))

	// Stateless preservation / inspection (transient SignAPI session; no job):
	// validate an already-signed document, or add an archive timestamp (B-LT→B-LTA).
	api.Post("/validations", r.scoped(levelRead, r.validate))
	api.Post("/archive-timestamps", r.scoped(levelWrite, r.archive))

	return nil
}

// scoped wraps a handler with a scope check; on denial it records a NIS2-audit
// authz-denial event and returns 403.
func (r *router) scoped(level string, h azugo.RequestHandler) azugo.RequestHandler {
	return func(ctx *azugo.Context) {
		if !ctx.User().HasScopeLevel(scopeResource, level) {
			r.Audit().Denied(ctx, callerID(ctx), scopeResource+":"+level)
			ctx.Error(corehttp.ForbiddenError{})
			return
		}
		h(ctx)
	}
}

// callerID returns the authenticated caller's id, or "".
func callerID(ctx *azugo.Context) string {
	u := ctx.User()
	if u == nil || !u.Authorized() {
		return ""
	}
	return u.ID()
}
