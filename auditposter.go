package eparakstssigner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"azugo.io/azugo"

	"github.com/gmb-lib/go-authbyte/authclient"
	"github.com/gmb-lib/go-platform-kit/broker"
)

// accessAuditPoster implements gdpr.Poster: it delivers one access record to the
// access-audit service authenticated as this service with a DPoP-bound service
// token (go-authbyte). On the request path it reuses the request-scoped
// PostJSON; the background outbox drainer (plain context) uses DoService.
type accessAuditPoster struct {
	auth     *authclient.Client
	url      string
	audience string
	scope    string
}

// newAccessAuditPoster builds a Poster targeting baseURL's /v1/access-records.
func newAccessAuditPoster(ac *authclient.Client, baseURL, audience, scope string) *accessAuditPoster {
	return &accessAuditPoster{
		auth:     ac,
		url:      strings.TrimSuffix(baseURL, "/") + "/v1/access-records",
		audience: audience,
		scope:    scope,
	}
}

// Post delivers rec. A non-nil error means the record was NOT persisted (the
// gdpr client then buffers a routine record or fails a privileged one).
func (p *accessAuditPoster) Post(ctx context.Context, rec *broker.Envelope) error {
	// Request path: reuse the DPoP-bound, service-token PostJSON.
	if ac, ok := ctx.(*azugo.Context); ok {
		return p.auth.PostJSON(ac, p.audience, p.scope, p.url, rec, nil)
	}

	// Background drain: acquire a service token with the plain context and POST.
	body, err := json.Marshal(rec)
	if err != nil {
		return err
	}

	resp, err := p.auth.DoService(ctx, p.audience, p.scope, http.MethodPost, p.url, nil, body)
	if err != nil {
		return err
	}
	if resp.StatusCode/100 != 2 {
		return fmt.Errorf("access-audit: POST %s returned %d", p.url, resp.StatusCode)
	}

	return nil
}
