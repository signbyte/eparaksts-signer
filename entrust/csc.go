package entrust

import (
	"net/http"
	"strings"
	"time"

	"github.com/gmb-lib/go-csc"
	"github.com/gmb-lib/go-csc/lvrtc"
	"github.com/gmb-lib/go-platform-kit/observability"
)

// The CSC API layer. The protocol — the two authorizations, the token-bound
// signHash, the provider's departures from the specification — lives in the CSC
// client library and its eParaksts profile; this file only builds that client from
// the platform configuration.

// cscPath is where the provider serves the CSC API on its TrustedX host.
const cscPath = "/trustedx-resources/csc/v2"

// CSCEnabled reports whether the CSC layer is configured.
func (c *Client) CSCEnabled() bool {
	return strings.TrimSpace(c.cfg.CSCClientID) != ""
}

// cscBaseURI is the CSC service base, ending in /csc/v2 as the specification
// requires. A configured base without that suffix gets it appended, so both the
// provider's full base and its host-level path are accepted; without one, the CSC
// layer is the TrustedX host's.
func (c *Client) cscBaseURI() string {
	base := c.cfg.CSCBaseURL
	if base == "" {
		return c.cfg.BaseURL + cscPath
	}
	if !strings.HasSuffix(base, "/csc/v2") {
		base += "/csc/v2"
	}
	return base
}

// CSC returns the CSC API client, speaking the eParaksts profile. The transport
// never follows a redirect: an answer's Location is data.
func (c *Client) CSC() *csc.Client {
	return &csc.Client{
		BaseURI:      c.cscBaseURI(),
		ClientID:     c.cfg.CSCClientID,
		ClientSecret: c.cfg.CSCClientSecret,
		Profile:      lvrtc.Profile,
		HTTP: observability.InstrumentHTTPClient(&http.Client{
			Timeout:       20 * time.Second,
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}),
	}
}

// CSCRedirectURI is the callback both CSC authorizations return to: the signing
// service's one registered callback, the same one the TrustedX flows use.
func (c *Client) CSCRedirectURI() string {
	return c.cfg.RedirectURI
}
