package routes

import (
	"encoding/json"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"

	"github.com/signbyte/eparaksts-signer/routes/response"
)

// getInfo reads /api/v1/info with the given test scopes ("" = unauthenticated).
func getInfo(t *testing.T, scopes string) *fasthttp.Response {
	t.Helper()
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)

	tc := app.TestClient()
	var opts []azugo.TestClientOption
	if scopes != "" {
		opts = append(opts, tc.WithHeader("X-Test-Scopes", scopes))
	}
	resp, err := tc.Get("/api/v1/info", opts...)
	qt.Assert(t, qt.IsNil(err))
	return resp
}

func infoFlows(t *testing.T, resp *fasthttp.Response) []string {
	t.Helper()
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusOK))
	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	var out response.Info
	qt.Assert(t, qt.IsNil(json.Unmarshal(body, &out)), qt.Commentf("%s", body))
	names := make([]string, 0, len(out.Flows))
	for _, f := range out.Flows {
		names = append(names, f.Name)
	}
	return names
}

// The discovery read sits behind the service authentication like the rest of the
// API, and takes the read scope — no other.
func TestInfoRequiresAuthAndReadScope(t *testing.T) {
	resp := getInfo(t, "")
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnauthorized))

	for _, scopes := range []string{"signatures:create", "signatures:write"} {
		resp := getInfo(t, scopes)
		qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusForbidden), qt.Commentf("%s", scopes))
		fasthttp.ReleaseResponse(resp)
	}
}

// Without a CSC client the deployment runs every flow but the two CSC ones, and
// says so, in display order.
func TestInfoListsNoCSCFlowWithoutACSCClient(t *testing.T) {
	resp := getInfo(t, "signatures:read")
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.DeepEquals(infoFlows(t, resp),
		[]string{"webEid", "eparakstsMobile", "eidScan", "eparakstsMobileEseal"}))
}

// A configured CSC client adds both CSC flows.
func TestInfoListsBothCSCFlowsWithACSCClient(t *testing.T) {
	t.Setenv("CSC_CLIENT_ID", "the-csc-client")
	resp := getInfo(t, "signatures:read")
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.DeepEquals(infoFlows(t, resp),
		[]string{"webEid", "eparakstsMobile", "eidScan", "eparakstsMobileEseal", "cscEidScan", "cscEidPlugin"}))
}
