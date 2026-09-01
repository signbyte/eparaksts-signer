package signing

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-quicktest/qt"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/job"
	"github.com/signbyte/eparaksts-signer/signapi"
)

// newSpineOrchestrator builds an Orchestrator wired only with a real SignAPI
// client pointed at h (the store/entrust are unused by the spine functions under
// test: calculateDigests + finalize touch only o.signapi and o.log).
func newSpineOrchestrator(t *testing.T, h http.HandlerFunc) *Orchestrator {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	sa := signapi.New(srv.URL, func(context.Context) (string, error) { return "tok", nil }, zap.NewNop())
	return &Orchestrator{signapi: sa, log: zap.NewNop()}
}

// TestCalculateDigestsEchoesOpaqueValues confirms the spine stores the SignAPI
// outputs verbatim (SCAL2): per-session digest, the batch signature_algorithm,
// and the digests_summary (+ its algorithm), and fills an empty digest algorithm
// from the response. Also checks the request carries signAsPdf/createNewEdoc
// derived from the first document.
func TestCalculateDigestsEchoesOpaqueValues(t *testing.T) {
	var req signapi.CalculateDigestRequest
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		qt.Check(t, qt.Equals(r.URL.Path, "/api-sign/v1.0/CalculateDigest"))
		_ = json.NewDecoder(r.Body).Decode(&req)
		_, _ = io.WriteString(w, `{"data":{"sessionDigests":[{"sessionId":"s1","digest":"DG1"}],"digests_summary":"SUMM","algorithm":"SHA256","signature_algorithm":"SHA256withECDSA"}}`)
	})

	j := &job.Job{
		JobID: "j1",
		Documents: []job.Document{
			{DocumentID: "d1", SessionID: "s1", Format: job.FormatPAdES, Operation: job.OpCreate, State: job.DocPending},
		},
	}

	err := o.calculateDigests(context.Background(), j, "SIGNCERT")
	qt.Assert(t, qt.IsNil(err))

	// request derived from the document
	qt.Check(t, qt.Equals(req.Certificate, "SIGNCERT"))
	qt.Check(t, qt.IsTrue(req.SignAsPdf))      // first doc is PAdES → sign the PDF natively
	qt.Check(t, qt.IsFalse(req.CreateNewEdoc)) // PAdES is mutually exclusive with a new ASiC-E container

	// opaque outputs echoed onto the job (SCAL2)
	qt.Check(t, qt.Equals(j.Documents[0].Digest, "DG1"))
	qt.Check(t, qt.Equals(j.Documents[0].DigestAlgorithm, "SHA256"))
	qt.Check(t, qt.Equals(j.SignAlgo, "SHA256withECDSA"))
	qt.Check(t, qt.Equals(j.DigestsSummary, "SUMM"))
	qt.Check(t, qt.Equals(j.DigestsSummaryAlgo, "SHA256"))
}

// TestCalculateDigestFormatOperationMatrix locks the signAsPdf/createNewEdoc
// derivation: the SignAPI rejects the two flags set together ("mutually
// exclusive"), so a PAdES signature never asks for a new container, a new ASiC-E
// is created only for a non-PAdES "create", and a parallel op creates nothing.
func TestCalculateDigestFormatOperationMatrix(t *testing.T) {
	cases := []struct {
		name          string
		format        job.SignatureFormat
		op            job.Operation
		wantSignAsPdf bool
		wantNewEdoc   bool
	}{
		{"pades create signs the pdf, no container", job.FormatPAdES, job.OpCreate, true, false},
		{"pades parallel adds a signature, no container", job.FormatPAdES, job.OpParallel, true, false},
		{"xades create makes a new container", job.FormatXAdES, job.OpCreate, false, true},
		{"xades parallel co-signs an existing container", job.FormatXAdES, job.OpParallel, false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var req signapi.CalculateDigestRequest
			o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewDecoder(r.Body).Decode(&req)
				_, _ = io.WriteString(w, `{"data":{"sessionDigests":[{"sessionId":"s1","digest":"DG1"}],"digests_summary":"SUMM","algorithm":"SHA256","signature_algorithm":"SHA256withECDSA"}}`)
			})
			j := &job.Job{
				JobID: "j1",
				Documents: []job.Document{
					{DocumentID: "d1", SessionID: "s1", Format: tc.format, Operation: tc.op, State: job.DocPending},
				},
			}

			err := o.calculateDigests(context.Background(), j, "SIGNCERT")
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.Equals(req.SignAsPdf, tc.wantSignAsPdf))
			qt.Check(t, qt.Equals(req.CreateNewEdoc, tc.wantNewEdoc))
			// The two are never sent together — the invariant the SignAPI enforces.
			qt.Check(t, qt.IsFalse(req.SignAsPdf && req.CreateNewEdoc))
		})
	}
}

// TestFinalizeNormalizesToDER is the core spine test: every signature value is
// normalized to DER at the finalize boundary regardless of input encoding, the
// person's auth cert is forwarded as the
// finalize authCertificate, the job goes READY, documents become DocReady, and
// the transient signature values are cleared (data minimization). Reuses the
// ECDSA vectors + helpers from ecdsa_test.go (same package).
func TestFinalizeNormalizesToDER(t *testing.T) {
	var fin signapi.FinalizeRequest
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		qt.Check(t, qt.Equals(r.URL.Path, "/api-sign/v1.0/finalizeSigning"))
		_ = json.NewDecoder(r.Body).Decode(&fin)
		w.WriteHeader(http.StatusOK)
	})

	// d1: a P1363 (raw r‖s) signature — the eid/card branch, must be converted.
	r := mustHex("a1b2c3d4e5f6071829384756abcdef00112233445566778899aabbccddeeff01")
	s := mustHex("0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff02")
	p1363Sig := base64.StdEncoding.EncodeToString(p1363(r, s, 32))
	// d2: already DER — the TrustedX/SignAPI branch, must pass through.
	derSig := base64.StdEncoding.EncodeToString(derOf(t, big.NewInt(7), big.NewInt(9)))

	j := &job.Job{
		JobID:    "j1",
		Flow:     job.FlowWebEID,
		State:    job.StateFinalizing,
		AuthCert: "AUTHCERT",
		Documents: []job.Document{
			{DocumentID: "d1", SessionID: "s1", SignatureValue: p1363Sig, State: job.DocPending, Format: job.FormatXAdES},
			{DocumentID: "d2", SessionID: "s2", SignatureValue: derSig, State: job.DocPending, Format: job.FormatXAdES},
		},
	}

	err := o.finalize(context.Background(), j)
	qt.Assert(t, qt.IsNil(err))

	// state machine + minimization
	qt.Check(t, qt.Equals(j.State, job.StateReady))
	for i := range j.Documents {
		qt.Check(t, qt.Equals(j.Documents[i].State, job.DocReady))
		qt.Check(t, qt.Equals(j.Documents[i].SignatureValue, "")) // cleared post-finalize
	}

	// finalize request: auth cert forwarded, one ssv per session
	qt.Check(t, qt.Equals(fin.AuthCertificate, "AUTHCERT"))
	qt.Assert(t, qt.Equals(len(fin.SessionSignatureValues), 2))

	bySession := map[string]string{}
	for _, ssv := range fin.SessionSignatureValues {
		bySession[ssv.SessionID] = ssv.SignatureValue
	}

	// both values arrive at finalize as DER (ASN.1 SEQUENCE, 0x30 prefix)
	for sid, b64 := range bySession {
		raw, err := base64.StdEncoding.DecodeString(b64)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.IsTrue(len(raw) > 0))
		qt.Check(t, qt.Equals(raw[0], byte(0x30)), qt.Commentf("session %s not DER", sid))
	}

	// the P1363 input (s1) round-trips to the same r,s once DER-encoded
	rawS1, err := base64.StdEncoding.DecodeString(bySession["s1"])
	qt.Assert(t, qt.IsNil(err))
	gotR, gotS := parseDER(t, rawS1)
	qt.Check(t, qt.Equals(gotR.Cmp(r), 0))
	qt.Check(t, qt.Equals(gotS.Cmp(s), 0))

	// the DER input (s2) round-trips to 7,9 unchanged
	rawS2, err := base64.StdEncoding.DecodeString(bySession["s2"])
	qt.Assert(t, qt.IsNil(err))
	gotR2, gotS2 := parseDER(t, rawS2)
	qt.Check(t, qt.Equals(gotR2.Cmp(big.NewInt(7)), 0))
	qt.Check(t, qt.Equals(gotS2.Cmp(big.NewInt(9)), 0))
}

// TestFinalizeRejectsBadSignature confirms an unrecognized signature width is a
// hard failure (never guessed) and the job is NOT marked ready.
func TestFinalizeRejectsBadSignature(t *testing.T) {
	called := false
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})

	bad := base64.StdEncoding.EncodeToString(make([]byte, 70)) // neither DER nor a P1363 width
	j := &job.Job{
		JobID: "j1", Flow: job.FlowWebEID, State: job.StateFinalizing, AuthCert: "A",
		Documents: []job.Document{{DocumentID: "d1", SessionID: "s1", SignatureValue: bad, State: job.DocPending, Format: job.FormatXAdES}},
	}

	err := o.finalize(context.Background(), j)
	qt.Assert(t, qt.IsNotNil(err))
	qt.Check(t, qt.IsTrue(errors.Is(err, ErrBadSignatureEncoding)))
	qt.Check(t, qt.IsFalse(called))                      // never reached finalizeSigning
	qt.Check(t, qt.Equals(j.State, job.StateFinalizing)) // not advanced to READY
}

// NOTE: validateBatch is already covered by TestValidateBatch in helpers_test.go
// (empty / single / batch-without-support / single-session / mixed / same-format),
// so it is intentionally not duplicated here.
