package signing

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
)

// newTxFlowOrchestrator wires an orchestrator whose SignAPI answers digests and
// whose provider client only builds URLs (no provider HTTP happens on the
// supplied-identity path — that is the point of it).
func newTxFlowOrchestrator(t *testing.T) *Orchestrator {
	t.Helper()
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		var req json.RawMessage
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, _ = io.WriteString(w, `{"data":{"sessionDigests":[{"sessionId":"s1","digest":"DG1"}],"digests_summary":"SUMM","algorithm":"SHA256","signature_algorithm":"SHA256withECDSA"}}`)
	})
	o.entrust = entrust.New(entrust.Config{
		BaseURL:     "https://provider.example",
		ClientID:    "cid",
		RedirectURI: "https://signer.example/callback",
	}, zap.NewNop())

	return o
}

func suppliedJob() *job.Job {
	return &job.Job{
		JobID: "j1",
		Documents: []job.Document{
			{DocumentID: "d1", SessionID: "s1", Format: job.FormatXAdES, Operation: job.OpCreate, State: job.DocPending},
		},
	}
}

// TestBeginAuthorizationSkipsProfileLegWhenIdentitySupplied proves the fast
// path: a job carrying the sign identity + both certificates gets the SIGNATURE
// authorization as its FIRST redirect — no profile authorize, digests computed
// with the supplied certificate, the pending leg already the sign leg.
func TestBeginAuthorizationSkipsProfileLegWhenIdentitySupplied(t *testing.T) {
	o := newTxFlowOrchestrator(t)
	f := &txFlow{o: o, variant: txMobile}

	j := suppliedJob()
	j.SignIdentityID = "id-serverid-sign"
	j.SigningCert = "MIIsignCaptured"
	j.AuthCert = "MIIauthCaptured"

	url, err := f.BeginAuthorization(&azugo.Context{}, j)
	qt.Assert(t, qt.IsNil(err))

	// The URL is the signature authorization, carrying the supplied identity
	// and the freshly computed digests summary — not the profile authorize.
	qt.Check(t, qt.IsTrue(strings.Contains(url, "sign_identity_id=id-serverid-sign")))
	qt.Check(t, qt.IsTrue(strings.Contains(url, "digests_summary=SUMM")))
	qt.Check(t, qt.IsFalse(strings.Contains(url, "sign:identity:profile")))
	qt.Check(t, qt.Equals(int(j.PendingLeg), int(job.LegSign)))
	qt.Check(t, qt.Equals(j.Documents[0].Digest, "DG1"))
}

// TestBeginAuthorizationPartialSupplyTakesFullPath proves anything missing
// falls back to the profile leg — a half-supplied identity never half-skips.
func TestBeginAuthorizationPartialSupplyTakesFullPath(t *testing.T) {
	o := newTxFlowOrchestrator(t)
	f := &txFlow{o: o, variant: txMobile}

	j := suppliedJob()
	j.SignIdentityID = "id-serverid-sign"
	j.SigningCert = "MIIsignCaptured"
	// AuthCert deliberately absent.

	url, err := f.BeginAuthorization(&azugo.Context{}, j)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(url, "sign%3Aidentity%3Aprofile") || strings.Contains(url, "sign:identity:profile")))
	qt.Check(t, qt.Equals(int(j.PendingLeg), int(job.LegProfile)))
}
