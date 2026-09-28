package entrust

import (
	"net/url"
	"strings"
	"testing"

	"github.com/gmb-lib/go-csc/lvrtc"
	"github.com/go-quicktest/qt"
)

func testClient() *Client {
	return New(Config{
		BaseURL:         "https://host",
		ASPath:          "/as",
		ClientID:        "cid",
		RedirectURI:     "https://signer/cb",
		ACRMobile:       "acr-mobile",
		ACREIDScan:      "acr-eidscan",
		ACRCloudEseal:   "acr-cloudeseal",
		CSCBaseURL:      "https://csc",
		CSCClientID:     "csc-cid",
		CSCClientSecret: "csc-secret",
	}, nil)
}

// parseQuery parses a built URL and returns its prefix-before-? and the query.
func parseQuery(t *testing.T, raw string) (string, url.Values) {
	t.Helper()
	u, err := url.Parse(raw)
	qt.Assert(t, qt.IsNil(err))
	return u.Scheme + "://" + u.Host + u.Path, u.Query()
}

func TestProfileAuthorizeURL(t *testing.T) {
	c := testClient()
	base, q := parseQuery(t, c.ProfileAuthorizeURL(ProfileAuthorizeParams{
		State: "S1", ACRValues: "acr-mobile", UILocales: "lv",
	}))
	qt.Check(t, qt.Equals(base, "https://host/as"))
	qt.Check(t, qt.Equals(q.Get("response_type"), "code"))
	qt.Check(t, qt.Equals(q.Get("client_id"), "cid"))
	qt.Check(t, qt.Equals(q.Get("redirect_uri"), "https://signer/cb"))
	qt.Check(t, qt.Equals(q.Get("state"), "S1"))
	qt.Check(t, qt.Equals(q.Get("scope"), scopeProfile+" "+scopeAA))
	qt.Check(t, qt.Equals(q.Get("acr_values"), "acr-mobile"))
	qt.Check(t, qt.Equals(q.Get("ui_locales"), "lv"))

	// acr_values / ui_locales are omitted when empty.
	_, q = parseQuery(t, c.ProfileAuthorizeURL(ProfileAuthorizeParams{State: "S1"}))
	qt.Check(t, qt.IsFalse(q.Has("acr_values")))
	qt.Check(t, qt.IsFalse(q.Has("ui_locales")))
}

func TestSignAuthorizeURLServerVsDevice(t *testing.T) {
	c := testClient()

	_, q := parseQuery(t, c.SignAuthorizeURL(SignAuthorizeParams{
		State: "S2", SignIdentityID: "id-9", DigestsSummary: "ZGln", DigestsSummaryAlgorithm: "SHA256",
		UseDevice: false,
	}))
	qt.Check(t, qt.Equals(q.Get("scope"), scopeUseServer))
	qt.Check(t, qt.Equals(q.Get("sign_identity_id"), "id-9"))
	qt.Check(t, qt.Equals(q.Get("digests_summary"), "ZGln"))
	qt.Check(t, qt.Equals(q.Get("digests_summary_algorithm"), "SHA256"))

	_, q = parseQuery(t, c.SignAuthorizeURL(SignAuthorizeParams{State: "S2", UseDevice: true}))
	qt.Check(t, qt.Equals(q.Get("scope"), scopeUseDevice))
}

func TestACRForFlow(t *testing.T) {
	c := testClient()
	qt.Check(t, qt.Equals(c.ACRForFlow(true, false), "acr-eidscan"))    // device → eidScan
	qt.Check(t, qt.Equals(c.ACRForFlow(false, true), "acr-cloudeseal")) // cloudEseal configured
	qt.Check(t, qt.Equals(c.ACRForFlow(false, false), "acr-mobile"))    // default

	// cloudEseal with no configured acr falls back to mobile.
	c2 := New(Config{ACRMobile: "acr-mobile"}, nil)
	qt.Check(t, qt.Equals(c2.ACRForFlow(false, true), "acr-mobile"))
}

func TestCSCEnabledAndBase(t *testing.T) {
	enabled := testClient()
	qt.Check(t, qt.IsTrue(enabled.CSCEnabled()))
	// A base without the specification's /csc/v2 suffix gets it.
	qt.Check(t, qt.Equals(enabled.CSC().BaseURI, "https://csc/csc/v2"))

	full := New(Config{CSCBaseURL: "https://eidas-demo.eparaksts.lv/trustedx-resources/csc/v2/", CSCClientID: "c"}, nil)
	qt.Check(t, qt.Equals(full.CSC().BaseURI, "https://eidas-demo.eparaksts.lv/trustedx-resources/csc/v2"))

	disabled := New(Config{BaseURL: "https://host"}, nil)
	qt.Check(t, qt.IsFalse(disabled.CSCEnabled()))
	// Without a CSC base, the CSC layer is the TrustedX host's.
	qt.Check(t, qt.Equals(disabled.CSC().BaseURI, "https://host/trustedx-resources/csc/v2"))

	// The eParaksts profile, and no redirect ever followed.
	c := enabled.CSC()
	qt.Check(t, qt.Equals(c.Profile.Name, lvrtc.Profile.Name))
	qt.Check(t, qt.IsNotNil(c.HTTP.CheckRedirect))
}

func TestCSCEIDFlows(t *testing.T) {
	none := New(Config{}, nil)
	qt.Check(t, qt.HasLen(none.CSCEIDFlows(), 0))

	both := New(Config{CSCACRValues: "urn:eparaksts:authentication:flow:mobile-eid | urn:eparaksts:authentication:flow:sc_plugin"}, nil)
	qt.Check(t, qt.DeepEquals(both.CSCEIDFlows(), lvrtc.EIDFlows{lvrtc.EIDScan, lvrtc.CardOnComputer}))
}

// TestNewTrimsTrailingSlash confirms New() trims trailing slashes so endpoints
// do not double up.
func TestNewTrimsTrailingSlash(t *testing.T) {
	c := New(Config{BaseURL: "https://host/", ASPath: "/as", ClientID: "cid"}, nil)
	got := c.ProfileAuthorizeURL(ProfileAuthorizeParams{State: "S"})
	qt.Check(t, qt.IsTrue(strings.HasPrefix(got, "https://host/as?")))
}
