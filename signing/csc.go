package signing

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-csc"
	"github.com/gmb-lib/go-csc/lvrtc"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/job"
)

// cscFlow signs through the provider's CSC API layer, one flow per way the
// person's eID card is read (eid). Two browser legs, both confirmed by the person:
//
//  1. the credential registration: a short-term signing credential for this
//     person, whose certificate then feeds CalculateDigest;
//  2. the signature authorization, bound to exactly the digests CalculateDigest
//     returned; its token is the only authorization signHash accepts.
//
// The worker then calls signHash once, verifies every returned value against the
// credential's certificate, and hands the signatures to finalize.
type cscFlow struct {
	o    *Orchestrator
	flow job.Flow
	// eid is how the eID card is read during both authorizations.
	eid lvrtc.EIDFlow
}

func (f *cscFlow) Type() job.Flow { return f.flow }

func (f *cscFlow) Capabilities() Capabilities {
	return Capabilities{SupportsBatch: true, Level: "QES"}
}

// cscSignMargin is how long the short-term credential must stay valid after the
// registration returns: the second authorization (the person confirming in the
// browser) and signHash still have to happen. The provider reuses a credential for
// the fifteen minutes after its first registration, so a second signing in that
// window can meet a certificate about to expire.
const cscSignMargin = 2 * time.Minute

// ErrCSCCredentialExpiring means the provider's short-term credential expires
// before a signing could complete. It is replaced once it has expired; the
// person starts again then.
var ErrCSCCredentialExpiring = errors.New("signing: the short-term signing certificate expires before this signing could finish")

// ErrCSCNotBound means the signature authorization is not for the digests the
// person was shown: never signed.
var ErrCSCNotBound = errors.New("signing: the signature authorization is not bound to these documents")

func (f *cscFlow) BeginAuthorization(ctx *azugo.Context, j *job.Job) (string, error) {
	req, err := f.newRequest(j)
	if err != nil {
		return "", err
	}
	j.PendingLeg = job.LegCredential
	return f.push(ctx, lvrtc.CredentialRequest(f.o.entrust.CSCRedirectURI(), j.OAuthState, req, lvrtc.EIDFlows{f.eid}))
}

// newRequest mints the state and PKCE pair of one authorization and keeps them on
// the job for the callback.
func (f *cscFlow) newRequest(j *job.Job) (csc.PKCE, error) {
	state, err := f.o.newState()
	if err != nil {
		return csc.PKCE{}, err
	}
	pkce, err := csc.NewPKCE()
	if err != nil {
		return csc.PKCE{}, err
	}
	j.OAuthState = state
	j.PKCEVerifier = pkce.Verifier
	return pkce, nil
}

func (f *cscFlow) push(ctx context.Context, req csc.AuthorizationRequest) (string, error) {
	c := f.o.entrust.CSC()
	par, err := c.PushedAuthorize(ctx, req)
	if err != nil {
		return "", err
	}
	return c.AuthorizeURL(par), nil
}

func (f *cscFlow) AdvanceCallback(ctx *azugo.Context, j *job.Job, code string) (string, bool, error) {
	c := f.o.entrust.CSC()
	tok, err := c.Token(ctx, code, f.o.entrust.CSCRedirectURI(), j.PKCEVerifier)
	j.PKCEVerifier = ""
	if err != nil {
		return "", false, err
	}
	switch j.PendingLeg {
	case job.LegCredential:
		return f.advanceCredential(ctx, j, c, tok)
	case job.LegSign:
		ds, err := lvrtc.Signing(tok)
		if err != nil {
			return "", false, err
		}
		digests, err := j.Digests()
		if err != nil {
			return "", false, err
		}
		// What the provider says the person confirmed must be exactly what is about
		// to be signed.
		if err := lvrtc.Bound(ds, j.CredentialID, digests); err != nil {
			return "", false, fmt.Errorf("%w: %w", ErrCSCNotBound, err)
		}
		j.SigningToken = tok.AccessToken
		j.PendingLeg = job.LegNone
		return "", true, nil
	default:
		return "", false, fmt.Errorf("signing: unexpected callback leg %d", j.PendingLeg)
	}
}

// advanceCredential reads the short-term credential, computes the digests with its
// certificate, and pushes the signature authorization for exactly those digests.
func (f *cscFlow) advanceCredential(ctx *azugo.Context, j *job.Job, c *csc.Client, tok csc.TokenResponse) (string, bool, error) {
	if tok.CredentialID == "" {
		return "", false, errors.New("signing: the credential registration named no credential")
	}
	cred, err := c.CredentialsInfo(ctx, tok.AccessToken, csc.CredentialsInfoRequest{
		CredentialID: tok.CredentialID, Certificates: csc.CertificatesSingle, CertInfo: true, AuthInfo: true,
	})
	if err != nil {
		return "", false, err
	}
	if err := cred.CheckSigning(len(j.Documents), time.Now().Add(cscSignMargin)); err != nil {
		if errors.Is(err, csc.ErrCertificateValidity) {
			return "", false, fmt.Errorf("%w: %w", ErrCSCCredentialExpiring, err)
		}
		return "", false, err
	}
	leaf, err := cred.LeafCertificate()
	if err != nil {
		return "", false, err
	}
	j.CredentialID = cred.CredentialID
	j.SigningCert = base64.StdEncoding.EncodeToString(leaf)
	j.SubjectRef = certSubject(j.SigningCert)

	if err := f.o.calculateDigests(ctx, j, j.SigningCert); err != nil {
		return "", false, err
	}
	digests, err := j.Digests()
	if err != nil {
		return "", false, err
	}
	hashOID, err := digestAlgorithmOID(digests)
	if err != nil {
		return "", false, err
	}
	algo, err := cred.SignAlgoFor(hashOID)
	if err != nil {
		return "", false, err
	}
	j.HashAlgorithmOID = hashOID
	j.SignAlgo = algo

	req, err := f.newRequest(j)
	if err != nil {
		return "", false, err
	}
	j.PendingLeg = job.LegSign
	next, err := f.push(ctx, lvrtc.SigningRequest(f.o.entrust.CSCRedirectURI(), j.OAuthState, req, lvrtc.EIDFlows{f.eid},
		j.CredentialID, digests, hashOID))
	if err != nil {
		return "", false, err
	}
	return next, false, nil
}

// Sign calls signHash once with the bound token and verifies each signature
// against the credential's certificate before it goes anywhere. A refused
// signHash is never retried: the provider spends the person's confirmation on it.
func (f *cscFlow) Sign(ctx context.Context, j *job.Job) error {
	digests, err := j.Digests()
	if err != nil {
		return err
	}
	der, err := base64.StdEncoding.DecodeString(j.SigningCert)
	if err != nil {
		return fmt.Errorf("signing: the credential certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("signing: the credential certificate: %w", err)
	}

	out, err := f.o.entrust.CSC().SignHash(ctx, j.SigningToken, csc.SignHashRequest{
		CredentialID:     j.CredentialID,
		Hashes:           digests,
		HashAlgorithmOID: j.HashAlgorithmOID,
		SignAlgo:         j.SignAlgo,
	})
	j.SigningToken = "" // single-use, whatever the answer
	if err != nil {
		return err
	}
	for i := range j.Documents {
		sig, err := out.Signature(i)
		if err != nil {
			return err
		}
		if err := csc.VerifySignature(cert, j.SignAlgo, j.HashAlgorithmOID, digests[i], sig); err != nil {
			f.o.log.Warn("csc signature refused before finalize", zap.String("job", j.JobID),
				zap.String("document", j.Documents[i].DocumentID), zap.Error(err))
			return fmt.Errorf("document %q: %w", j.Documents[i].DocumentID, err)
		}
		j.Documents[i].SignatureValue = base64.StdEncoding.EncodeToString(sig)
	}
	return nil
}

// digestAlgorithmOID names the digest algorithm of a batch by its length: the
// signing API's digest follows the signing key (SHA-384 for a P-384 key), except
// on its hash-only path, which is SHA-256 whatever the key — the length is the one
// thing that says which. One authorization names one algorithm, so a batch mixing
// lengths is refused.
func digestAlgorithmOID(digests [][]byte) (string, error) {
	if len(digests) == 0 {
		return "", errors.New("signing: no digests")
	}
	var oid string
	for _, d := range digests {
		var o string
		for _, candidate := range []string{csc.OIDSHA256, csc.OIDSHA384, csc.OIDSHA512} {
			if csc.DigestLength(candidate) == len(d) {
				o = candidate
			}
		}
		if o == "" {
			return "", fmt.Errorf("signing: a %d-byte digest names no SHA-2 algorithm", len(d))
		}
		if oid != "" && o != oid {
			return "", errors.New("signing: the batch mixes digest algorithms")
		}
		oid = o
	}
	return oid, nil
}
