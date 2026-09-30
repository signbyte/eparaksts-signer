package routes

import (
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// cscPrepareBody is a one-document hash-only CSC prepare, with or without the
// person's login authentication certificate.
func cscPrepareBody(authCert string) string {
	body := `{"documents":[{"documentId":"d1","fileName":"f.txt","signatureFormat":"XAdES","documentHash":"aGk="}]`
	if authCert != "" {
		body += `,"authCertificate":"` + authCert + `"`
	}
	return body + `}`
}

func prepareCode(t *testing.T, resp *fasthttp.Response) (int, string) {
	t.Helper()
	body, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	return resp.StatusCode(), string(body)
}

// A CSC signing can request its timestamp only with the certificate the request
// carries, so one without it is refused before anything is uploaded or the person
// is asked to confirm — not at finalize, after both confirmations.
func TestCSCPrepareWithoutALoginCertificateIsRefusedUpFront(t *testing.T) {
	t.Setenv("CSC_CLIENT_ID", "the-csc-client")
	for _, flow := range []string{"cscEidScan", "cscEidPlugin"} {
		resp := postPrepare(t, "signatures:create", flow, cscPrepareBody(""))
		status, body := prepareCode(t, resp)
		fasthttp.ReleaseResponse(resp)
		qt.Check(t, qt.Equals(status, fasthttp.StatusBadRequest), qt.Commentf("%s: %s", flow, body))
		qt.Check(t, qt.IsTrue(strings.Contains(body, "err:signing:missingAuthCertificate")), qt.Commentf("%s: %s", flow, body))
	}

	// With the certificate the request gets past the check (and on to the signing
	// API, which this test app does not have).
	resp := postPrepare(t, "signatures:create", "cscEidScan", cscPrepareBody("MIIauth"))
	status, body := prepareCode(t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsFalse(strings.Contains(body, "missingAuthCertificate")), qt.Commentf("%d %s", status, body))
}

// A deployment that pays for this flow's timestamps needs no certificate from the
// request.
func TestCSCPrepareOnTheDeploymentsCertificateNeedsNoLoginCertificate(t *testing.T) {
	t.Setenv("CSC_CLIENT_ID", "the-csc-client")
	t.Setenv("TSA_ACCESS_CERT", "MIIdeployment")
	t.Setenv("TSA_ACCESS_CERT_FLOWS", "cscEidScan")
	resp := postPrepare(t, "signatures:create", "cscEidScan", cscPrepareBody(""))
	status, body := prepareCode(t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsFalse(strings.Contains(body, "missingAuthCertificate")), qt.Commentf("%d %s", status, body))

	// The other CSC flow is not on the list, so it still needs one.
	resp = postPrepare(t, "signatures:create", "cscEidPlugin", cscPrepareBody(""))
	status, body = prepareCode(t, resp)
	fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(strings.Contains(body, "err:signing:missingAuthCertificate")), qt.Commentf("%d %s", status, body))
}
