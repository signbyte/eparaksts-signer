package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-csc"
	"github.com/go-quicktest/qt"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
	"github.com/signbyte/eparaksts-signer/signapi"
)

// shapeSignAPI is the signing API's CalculateDigest for any number of sessions:
// one digest per session asked for, of the length the path produces — SHA-384 for
// a document signed with the P-384 certificate, SHA-256 on the hash-only path
// (documents registered as digests), whatever the key.
type shapeSignAPI struct {
	mu       sync.Mutex
	hashOnly bool
	req      signapi.CalculateDigestRequest
	digests  map[string][]byte // by session id
}

func (s *shapeSignAPI) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = json.NewDecoder(r.Body).Decode(&s.req)
	s.digests = map[string][]byte{}
	parts := make([]string, 0, len(s.req.Sessions))
	for _, ref := range s.req.Sessions {
		var d []byte
		if s.hashOnly {
			sum := sha256.Sum256([]byte("SignedInfo of " + ref.SessionID))
			d = sum[:]
		} else {
			sum := sha512.Sum384([]byte("SignedInfo of " + ref.SessionID))
			d = sum[:]
		}
		s.digests[ref.SessionID] = d
		parts = append(parts, fmt.Sprintf(`{"sessionId":%q,"digest":%q}`, ref.SessionID, base64.StdEncoding.EncodeToString(d)))
	}
	_, _ = fmt.Fprintf(w, `{"data":{"sessionDigests":[%s],"digests_summary":"SUMM","algorithm":"SHA256","signature_algorithm":"ecdsa"}}`,
		strings.Join(parts, ","))
}

func newShapeOrchestrator(t *testing.T, hashOnly bool) (*Orchestrator, *shapeSignAPI, *fakeCSC) {
	t.Helper()
	sa := &shapeSignAPI{hashOnly: hashOnly}
	o := newSpineOrchestrator(t, sa.serve)
	fake, srv := newFakeCSC(t)
	o.entrust = entrust.New(entrust.Config{
		CSCBaseURL: srv.URL, CSCClientID: "app", CSCClientSecret: "s",
		RedirectURI: "https://signer.example/sign/eparaksts/callback",
	}, zap.NewNop())
	return o, sa, fake
}

// shapeJob is a CSC job of n documents, each in its own signing-API session.
func shapeJob(n int, format job.SignatureFormat, op job.Operation) *job.Job {
	j := &job.Job{JobID: "j1", Flow: job.FlowCSCEidScan}
	for i := 1; i <= n; i++ {
		j.Documents = append(j.Documents, job.Document{
			DocumentID: fmt.Sprintf("d%d", i), SessionID: fmt.Sprintf("s%d", i),
			Format: format, Operation: op, State: job.DocPending,
		})
	}
	return j
}

// runCSC drives the flow through both authorizations and signHash.
func runCSC(t *testing.T, o *Orchestrator, j *job.Job) {
	t.Helper()
	f := scanFlow(o)
	ctx := &azugo.Context{}
	_, err := f.BeginAuthorization(ctx, j)
	qt.Assert(t, qt.IsNil(err))
	_, done, err := f.AdvanceCallback(ctx, j, "registration")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(done))
	_, done, err = f.AdvanceCallback(ctx, j, "signing")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(done))
	qt.Assert(t, qt.IsNil(f.Sign(context.Background(), j)))
}

// checkSignedEach asserts every document carries a signature by the credential's
// key over exactly its own session's digest.
func checkSignedEach(t *testing.T, j *job.Job, sa *shapeSignAPI, fake *fakeCSC) {
	t.Helper()
	for _, d := range j.Documents {
		sig, err := base64.StdEncoding.DecodeString(d.SignatureValue)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.IsTrue(ecdsa.VerifyASN1(&fake.key.PublicKey, sa.digests[d.SessionID], sig)),
			qt.Commentf("document %s is not signed over its own digest", d.DocumentID))
	}
}

// Several documents are signed in ONE authorization: the person confirms once, the
// signature authorization names every digest in document order, one signHash
// returns a signature per document, and each lands on its own document.
func TestCSCFlowSignsSeveralDocumentsInOneAuthorization(t *testing.T) {
	o, sa, fake := newShapeOrchestrator(t, false)
	j := shapeJob(3, job.FormatXAdES, job.OpCreate)
	runCSC(t, o, j)

	qt.Check(t, qt.HasLen(sa.req.Sessions, 3)) // one CalculateDigest over every session
	qt.Assert(t, qt.HasLen(fake.pushed, 2))    // the credential, then ONE signature authorization
	sign := fake.pushed[1]
	qt.Check(t, qt.Equals(sign.Get("numSignatures"), "3"))
	want := make([]string, 0, 3)
	for _, d := range j.Documents {
		want = append(want, base64.StdEncoding.EncodeToString(sa.digests[d.SessionID]))
	}
	qt.Check(t, qt.Equals(sign.Get("hashes"), strings.Join(want, ",")))
	hashes, _ := fake.signBody["hashes"].([]any)
	qt.Check(t, qt.HasLen(hashes, 3)) // one signHash for all three
	checkSignedEach(t, j, sa, fake)
}

// A batch larger than the credential can sign in one authorization is refused
// before the person is asked to confirm it.
func TestCSCFlowRefusesMoreDocumentsThanTheCredentialSigns(t *testing.T) {
	o, _, fake := newShapeOrchestrator(t, false)
	j := shapeJob(41, job.FormatXAdES, job.OpCreate) // the provider's measured multisign is 40
	f := scanFlow(o)
	ctx := &azugo.Context{}
	_, err := f.BeginAuthorization(ctx, j)
	qt.Assert(t, qt.IsNil(err))
	next, _, err := f.AdvanceCallback(ctx, j, "registration")
	qt.Check(t, qt.ErrorIs(err, csc.ErrMultisign))
	qt.Check(t, qt.Equals(next, ""))
	qt.Check(t, qt.HasLen(fake.pushed, 1)) // no signature authorization was asked for
}

// A PDF is signed as PAdES through CSC: the digest is computed for a signature
// embedded in the PDF itself (no container), and signed like any other.
func TestCSCFlowSignsAPDF(t *testing.T) {
	o, sa, fake := newShapeOrchestrator(t, false)
	j := shapeJob(1, job.FormatPAdES, job.OpCreate)
	runCSC(t, o, j)

	qt.Check(t, qt.IsTrue(sa.req.SignAsPdf))
	qt.Check(t, qt.IsFalse(sa.req.CreateNewEdoc))
	qt.Check(t, qt.Equals(sa.req.Certificate, base64.StdEncoding.EncodeToString(fake.cert.Raw)))
	qt.Check(t, qt.Equals(j.HashAlgorithmOID, csc.OIDSHA384))
	checkSignedEach(t, j, sa, fake)
	ct, ext := containerType(j.Documents[0].Format, false)
	qt.Check(t, qt.Equals(ct, "application/pdf"))
	qt.Check(t, qt.Equals(ext, ".pdf"))
}

// A further signature on an already-signed container goes the hash-only path: the
// signing API returns SHA-256 digests whatever the key, so the authorization and
// signHash name SHA-256 and the signature algorithm is the credential key's SHA-256
// variant, and the signature is checked against that digest.
func TestCSCFlowSignsAFurtherSignatureOnTheHashOnlyPath(t *testing.T) {
	o, sa, fake := newShapeOrchestrator(t, true)
	j := shapeJob(1, job.FormatXAdES, job.OpParallel)
	runCSC(t, o, j)

	qt.Check(t, qt.IsFalse(sa.req.CreateNewEdoc)) // into the existing container, not a new one
	qt.Check(t, qt.IsFalse(sa.req.SignAsPdf))
	qt.Check(t, qt.Equals(j.HashAlgorithmOID, csc.OIDSHA256))
	qt.Check(t, qt.Equals(j.SignAlgo, csc.OIDECDSAWithSHA256))
	sign := fake.pushed[1]
	qt.Check(t, qt.Equals(sign.Get("hashAlgorithmOID"), csc.OIDSHA256))
	qt.Check(t, qt.Equals(fake.signBody["hashAlgorithmOID"], csc.OIDSHA256))
	qt.Check(t, qt.Equals(fake.signBody["signAlgo"], csc.OIDECDSAWithSHA256))
	checkSignedEach(t, j, sa, fake)
}

// All three shapes at once: several PDFs in one authorization.
func TestCSCFlowSignsSeveralPDFsInOneAuthorization(t *testing.T) {
	o, sa, fake := newShapeOrchestrator(t, false)
	j := shapeJob(2, job.FormatPAdES, job.OpCreate)
	runCSC(t, o, j)

	qt.Check(t, qt.IsTrue(sa.req.SignAsPdf))
	qt.Check(t, qt.Equals(fake.pushed[1].Get("numSignatures"), "2"))
	checkSignedEach(t, j, sa, fake)
}
