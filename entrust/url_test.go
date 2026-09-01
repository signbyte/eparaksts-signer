package entrust

import (
	"net/url"
	"strings"
	"testing"

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

func TestCSCAuthorizeURL(t *testing.T) {
	c := testClient()
	base, q := parseQuery(t, c.CSCAuthorizeURL(CSCAuthorizeParams{
		State: "S3", CodeChallenge: "chal", Scope: "service", DocumentDigests: "dd",
	}))
	qt.Check(t, qt.Equals(base, "https://csc"+cscPathOAuthAuthorize))
	qt.Check(t, qt.Equals(q.Get("response_type"), "code"))
	qt.Check(t, qt.Equals(q.Get("client_id"), "csc-cid"))
	qt.Check(t, qt.Equals(q.Get("code_challenge"), "chal"))
	qt.Check(t, qt.Equals(q.Get("code_challenge_method"), "S256"))
	qt.Check(t, qt.Equals(q.Get("scope"), "service"))
	qt.Check(t, qt.Equals(q.Get("documentDigests"), "dd"))

	// documentDigests / scope omitted when empty.
	_, q = parseQuery(t, c.CSCAuthorizeURL(CSCAuthorizeParams{State: "S3", CodeChallenge: "chal"}))
	qt.Check(t, qt.IsFalse(q.Has("documentDigests")))
	qt.Check(t, qt.IsFalse(q.Has("scope")))
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
	qt.Check(t, qt.Equals(enabled.cscBase(), "https://csc"))

	disabled := New(Config{BaseURL: "https://host"}, nil)
	qt.Check(t, qt.IsFalse(disabled.CSCEnabled()))
	// cscBase falls back to BaseURL when CSCBaseURL is unset.
	qt.Check(t, qt.Equals(disabled.cscBase(), "https://host"))
}

// TestNewTrimsTrailingSlash confirms New() trims trailing slashes so endpoints
// do not double up.
func TestNewTrimsTrailingSlash(t *testing.T) {
	c := New(Config{BaseURL: "https://host/", ASPath: "/as", ClientID: "cid"}, nil)
	got := c.ProfileAuthorizeURL(ProfileAuthorizeParams{State: "S"})
	qt.Check(t, qt.IsTrue(strings.HasPrefix(got, "https://host/as?")))
}
