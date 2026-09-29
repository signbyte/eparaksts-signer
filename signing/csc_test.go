package signing

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-csc"
	"github.com/gmb-lib/go-csc/lvrtc"
	"github.com/go-quicktest/qt"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
)

// fakeCSC is the provider's CSC layer reduced to what the flow's calls need. It
// records what arrived and answers in the provider's shapes.
type fakeCSC struct {
	mu        sync.Mutex
	key       *ecdsa.PrivateKey
	cert      *x509.Certificate
	pushed    []url.Values
	signBody  map[string]any
	signAuth  string
	boundTo   []string // the digests the sign token says were confirmed (standard Base64)
	badSig    bool     // answer signHash with a value that is not a signature
	unbound   bool     // answer the sign token with a digest nobody confirmed
	certUntil time.Duration
}

func newFakeCSC(t *testing.T) (*fakeCSC, *httptest.Server) {
	t.Helper()
	f := &fakeCSC{certUntil: 15 * time.Minute}
	f.key, _ = ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	return f, srv
}

func (f *fakeCSC) mint() {
	tpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: "CSC SIGNER", SerialNumber: testIDCode()},
		NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(f.certUntil), KeyUsage: x509.KeyUsageContentCommitment}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, f.key.Public(), f.key)
	f.cert, _ = x509.ParseCertificate(der)
}

func (f *fakeCSC) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case "/csc/v2/oauth2/pushed_authorize":
		_ = r.ParseForm()
		f.pushed = append(f.pushed, r.PostForm)
		if h := r.PostForm.Get("hashes"); h != "" {
			f.boundTo = strings.Split(h, ",")
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{"request_uri":"urn:ietf:params:oauth:request_uri:x","expires_in":60}`)
	case "/csc/v2/oauth2/token":
		_ = r.ParseForm()
		switch r.PostForm.Get("code") {
		case "registration":
			_, _ = io.WriteString(w, `{"access_token":"credential-token","token_type":"Bearer","expires_in":600,"credentialID":"cred-1",`+
				`"authorization_details":[{"type":"sign_identity_registration","group_labels":["urn:csc:signatureQualifier:eu_eidas_qes"]}]}`)
		case "signing":
			digests := make([]string, len(f.boundTo))
			for i, d := range f.boundTo {
				digests[i] = fmt.Sprintf(`{"value":%q,"algorithm":"SHA-384"}`, d)
			}
			if f.unbound {
				other := sha512.Sum384([]byte("a document nobody confirmed"))
				digests = []string{fmt.Sprintf(`{"value":%q,"algorithm":"SHA-384"}`, base64.StdEncoding.EncodeToString(other[:]))}
			}
			_, _ = fmt.Fprintf(w, `{"access_token":"sign-token","token_type":"Bearer","expires_in":600,"authorization_details":[{"type":"digest_signing","digests":[%s],"sign_identity_id":"cred-1","num_signatures":%d}]}`,
				strings.Join(digests, ","), len(digests))
		default:
			w.WriteHeader(http.StatusBadRequest)
			_, _ = io.WriteString(w, `{"error":"invalid_grant","error_description":"invalidOrExpiredCode"}`)
		}
	case "/csc/v2/credentials/info":
		f.mint()
		_, _ = fmt.Fprintf(w, `{"key":{"status":"enabled","algo":["1.2.840.10045.4.3.2","1.2.840.10045.4.3.3","1.2.840.10045.4.3.4"],"len":384,"curve":"1.3.132.0.34"},`+
			`"cert":{"status":"valid","certificates":[%q]},"auth":{"mode":"oauth2code"},"multisign":40,"signatureQualifier":"eu_eidas_qes","SCAL":"2"}`,
			base64.StdEncoding.EncodeToString(f.cert.Raw))
	case "/csc/v2/signatures/signHash":
		f.signAuth = r.Header.Get("Authorization")
		_ = json.NewDecoder(r.Body).Decode(&f.signBody)
		hashes, _ := f.signBody["hashes"].([]any)
		sigs := make([]string, len(hashes))
		for i, h := range hashes {
			d, _ := base64.StdEncoding.DecodeString(h.(string))
			sig, _ := ecdsa.SignASN1(rand.Reader, f.key, d)
			if f.badSig {
				sig[len(sig)-1] ^= 1
			}
			sigs[i] = base64.StdEncoding.EncodeToString(sig)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"signatures": sigs})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// cscDigest is what SignAPI answers for a P-384 certificate: a SHA-384 digest.
var cscDigest = func() []byte { d := sha512.Sum384([]byte("the container's SignedInfo")); return d[:] }()

func newCSCOrchestrator(t *testing.T) (*Orchestrator, *fakeCSC) {
	t.Helper()
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"data":{"sessionDigests":[{"sessionId":"s1","digest":%q}],"digests_summary":"SUMM","algorithm":"SHA256","signature_algorithm":"ecdsa"}}`,
			base64.StdEncoding.EncodeToString(cscDigest))
	})
	fake, srv := newFakeCSC(t)
	o.entrust = entrust.New(entrust.Config{
		CSCBaseURL: srv.URL, CSCClientID: "app", CSCClientSecret: "s",
		RedirectURI: "https://signer.example/sign/eparaksts/callback",
	}, zap.NewNop())
	return o, fake
}

// scanFlow is the eID Scan CSC flow on the test orchestrator.
func scanFlow(o *Orchestrator) *cscFlow {
	return &cscFlow{o: o, flow: job.FlowCSCEidScan, eid: lvrtc.EIDScan}
}

// The orchestrator carries one CSC flow per way the card is read, each sending its
// own acr_values, and the retired single flow is not a flow any more.
func TestCSCFlowsRegisteredByCardRoute(t *testing.T) {
	o := New(nil, nil, nil, Config{}, nil)
	scan, ok := o.Flow(job.FlowCSCEidScan).(*cscFlow)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(scan.eid, lvrtc.EIDScan))
	qt.Check(t, qt.Equals(scan.Type(), job.FlowCSCEidScan))
	plugin, ok := o.Flow(job.FlowCSCEidPlugin).(*cscFlow)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(plugin.eid, lvrtc.CardOnComputer))
	qt.Check(t, qt.Equals(plugin.Type(), job.FlowCSCEidPlugin))
	qt.Check(t, qt.IsNil(o.Flow(job.Flow("csc"))))
}

// The card-in-reader flow asks the provider for its card route in both authorizations.
func TestCSCPluginFlowSendsTheCardRoute(t *testing.T) {
	o, fake := newCSCOrchestrator(t)
	f := &cscFlow{o: o, flow: job.FlowCSCEidPlugin, eid: lvrtc.CardOnComputer}
	j := cscJob()
	j.Flow = job.FlowCSCEidPlugin
	ctx := &azugo.Context{}
	_, err := f.BeginAuthorization(ctx, j)
	qt.Assert(t, qt.IsNil(err))
	_, _, err = f.AdvanceCallback(ctx, j, "registration")
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.HasLen(fake.pushed, 2))
	for _, form := range fake.pushed {
		qt.Check(t, qt.Equals(form.Get("acr_values"), string(lvrtc.CardOnComputer)))
	}
}

func cscJob() *job.Job {
	return &job.Job{JobID: "j1", Flow: job.FlowCSCEidScan, Documents: []job.Document{
		{DocumentID: "d1", SessionID: "s1", Format: job.FormatXAdES, Operation: job.OpCreate, State: job.DocPending},
	}}
}

// The two authorizations and signHash, as the provider was measured answering: the
// credential registration, the digests computed with the short-term certificate, a
// signature authorization bound to exactly those digests, signHash with the bound
// token, and a signature verified against the certificate before finalize sees it.
func TestCSCFlowTwoAuthorizationsThenVerifiedSignature(t *testing.T) {
	o, fake := newCSCOrchestrator(t)
	f := scanFlow(o)
	j := cscJob()
	ctx := &azugo.Context{}

	first, err := f.BeginAuthorization(ctx, j)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(first, "/csc/v2/oauth2/authorize?")))
	qt.Check(t, qt.IsTrue(strings.Contains(first, "request_uri=")))
	qt.Check(t, qt.Equals(int(j.PendingLeg), int(job.LegCredential)))
	reg := fake.pushed[0]
	qt.Check(t, qt.Equals(reg.Get("scope"), "credential"))
	qt.Check(t, qt.Equals(reg.Get("signatureQualifier"), "eu_eidas_qes"))
	qt.Check(t, qt.Equals(reg.Get("acr_values"), "urn:eparaksts:authentication:flow:mobile-eid"))
	qt.Check(t, qt.Equals(reg.Get("redirect_uri"), "https://signer.example/sign/eparaksts/callback"))
	qt.Check(t, qt.Equals(reg.Get("state"), j.OAuthState))

	next, done, err := f.AdvanceCallback(ctx, j, "registration")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(done))
	qt.Check(t, qt.IsTrue(strings.Contains(next, "request_uri=")))
	qt.Check(t, qt.Equals(int(j.PendingLeg), int(job.LegSign)))
	qt.Check(t, qt.Equals(j.CredentialID, "cred-1"))
	qt.Check(t, qt.Equals(j.SigningCert, base64.StdEncoding.EncodeToString(fake.cert.Raw)))
	qt.Check(t, qt.Equals(j.SubjectRef, testIDCode()))
	qt.Check(t, qt.Equals(j.HashAlgorithmOID, csc.OIDSHA384))
	qt.Check(t, qt.Equals(j.SignAlgo, csc.OIDECDSAWithSHA384)) // an OID from key/algo, never SignAPI's name
	sign := fake.pushed[1]
	qt.Check(t, qt.Equals(sign.Get("credentialID"), "cred-1"))
	qt.Check(t, qt.Equals(sign.Get("numSignatures"), "1"))
	qt.Check(t, qt.Equals(sign.Get("hashes"), base64.StdEncoding.EncodeToString(cscDigest)))
	qt.Check(t, qt.Equals(sign.Get("hashAlgorithmOID"), csc.OIDSHA384))
	qt.Check(t, qt.Equals(sign.Get("state"), j.OAuthState))

	_, done, err = f.AdvanceCallback(ctx, j, "signing")
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(done))
	qt.Check(t, qt.Equals(j.SigningToken, "sign-token"))

	qt.Assert(t, qt.IsNil(f.Sign(context.Background(), j)))
	qt.Check(t, qt.Equals(fake.signAuth, "Bearer sign-token"))
	qt.Check(t, qt.Equals(fake.signBody["hashAlgorithmOID"], csc.OIDSHA384))
	qt.Check(t, qt.Equals(fake.signBody["signAlgo"], csc.OIDECDSAWithSHA384))
	qt.Check(t, qt.Equals(j.SigningToken, ""))
	sig, _ := base64.StdEncoding.DecodeString(j.Documents[0].SignatureValue)
	qt.Check(t, qt.IsTrue(ecdsa.VerifyASN1(&fake.key.PublicKey, cscDigest, sig)))
}

// A signature authorization for other digests than the ones about to be signed is
// refused before signHash.
func TestCSCFlowRefusesAnUnboundAuthorization(t *testing.T) {
	o, fake := newCSCOrchestrator(t)
	fake.unbound = true
	f := scanFlow(o)
	j := cscJob()
	ctx := &azugo.Context{}
	_, err := f.BeginAuthorization(ctx, j)
	qt.Assert(t, qt.IsNil(err))
	_, _, err = f.AdvanceCallback(ctx, j, "registration")
	qt.Assert(t, qt.IsNil(err))
	_, done, err := f.AdvanceCallback(ctx, j, "signing")
	qt.Check(t, qt.IsFalse(done))
	qt.Check(t, qt.ErrorIs(err, ErrCSCNotBound))
	qt.Check(t, qt.Equals(j.SigningToken, ""))
}

// A value that is not a signature by the credential over the digest never reaches
// finalize, and the spent token is not kept.
func TestCSCFlowRefusesASignatureThatDoesNotVerify(t *testing.T) {
	o, fake := newCSCOrchestrator(t)
	fake.badSig = true
	f := scanFlow(o)
	j := cscJob()
	ctx := &azugo.Context{}
	_, _ = f.BeginAuthorization(ctx, j)
	_, _, _ = f.AdvanceCallback(ctx, j, "registration")
	_, _, err := f.AdvanceCallback(ctx, j, "signing")
	qt.Assert(t, qt.IsNil(err))

	err = f.Sign(context.Background(), j)
	qt.Check(t, qt.ErrorIs(err, csc.ErrSignatureInvalid))
	qt.Check(t, qt.Equals(j.Documents[0].SignatureValue, ""))
	qt.Check(t, qt.Equals(j.SigningToken, ""))
}

// A reused short-term credential about to expire is refused before the person is
// asked to confirm a signature it could not complete.
func TestCSCFlowRefusesAnExpiringCredential(t *testing.T) {
	o, fake := newCSCOrchestrator(t)
	fake.certUntil = time.Minute
	f := scanFlow(o)
	j := cscJob()
	ctx := &azugo.Context{}
	_, _ = f.BeginAuthorization(ctx, j)
	next, _, err := f.AdvanceCallback(ctx, j, "registration")
	qt.Check(t, qt.ErrorIs(err, ErrCSCCredentialExpiring))
	qt.Check(t, qt.Equals(next, ""))
	qt.Check(t, qt.HasLen(fake.pushed, 1)) // no signature authorization was asked for
}

func TestDigestAlgorithmOID(t *testing.T) {
	for n, want := range map[int]string{32: csc.OIDSHA256, 48: csc.OIDSHA384, 64: csc.OIDSHA512} {
		got, err := digestAlgorithmOID([][]byte{make([]byte, n)})
		qt.Check(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got, want))
	}
	_, err := digestAlgorithmOID([][]byte{make([]byte, 48), make([]byte, 32)})
	qt.Check(t, qt.IsNotNil(err))
	_, err = digestAlgorithmOID([][]byte{make([]byte, 20)})
	qt.Check(t, qt.IsNotNil(err))
	_, err = digestAlgorithmOID(nil)
	qt.Check(t, qt.IsTrue(err != nil && !errors.Is(err, context.Canceled)))
}
