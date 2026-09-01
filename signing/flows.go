package signing

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
)

// ============================ eid (client-side) =============================

// eidFlow is the local eID card flow: digests are returned to the caller and the
// signatures are submitted back. There is no
// upstream authorization or signing call.
type eidFlow struct{ o *Orchestrator }

func (f *eidFlow) Type() job.Flow { return job.FlowWebEID }

func (f *eidFlow) Capabilities() Capabilities {
	return Capabilities{SupportsBatch: true, ClientSide: true, Level: "QES"}
}

func (f *eidFlow) BeginAuthorization(*azugo.Context, *job.Job) (string, error) {
	return "", errors.New("signing: eid is client-side (no authorization)")
}

func (f *eidFlow) AdvanceCallback(*azugo.Context, *job.Job, string) (string, bool, error) {
	return "", false, errors.New("signing: eid has no callback")
}

func (f *eidFlow) Sign(context.Context, *job.Job) error {
	return errors.New("signing: eid signatures are submitted by the client")
}

// ============================== csc (CSC layer) ==============================

// cscFlow drives the new CSC API layer: oauth2code consent → credential token →
// signHash. KNOWN parts are implemented; the open items (E/F/Cert/K) are marked
// inline and resolved when the LVRTC platform update lands.
type cscFlow struct{ o *Orchestrator }

func (f *cscFlow) Type() job.Flow { return job.FlowCSC }

func (f *cscFlow) Capabilities() Capabilities {
	return Capabilities{SupportsBatch: true, Level: "QES"}
}

func (f *cscFlow) BeginAuthorization(ctx *azugo.Context, j *job.Job) (string, error) {
	state, err := f.o.newState()
	if err != nil {
		return "", err
	}
	verifier, challenge, err := pkce()
	if err != nil {
		return "", err
	}
	j.OAuthState = state
	j.PKCEVerifier = verifier
	j.PendingLeg = job.LegCredential
	// Interim finalize authCertificate from config.
	j.AuthCert = f.o.cfg.CSCAuthCert

	// OPEN (item Cert): the `documentDigests` consent binding needs the digests
	// up front, but the csc signing cert is only available after the credential
	// token — so digests are computed in AdvanceCallback. The consent is issued
	// without a pre-bound documentDigests until the platform sequencing is fixed.
	return f.o.entrust.CSCAuthorizeURL(entrust.CSCAuthorizeParams{
		State:         state,
		CodeChallenge: challenge,
		Scope:         "service",
	}), nil
}

func (f *cscFlow) AdvanceCallback(ctx *azugo.Context, j *job.Job, code string) (string, bool, error) {
	token, err := f.o.entrust.CSCExchange(ctx, code, j.PKCEVerifier)
	if err != nil {
		return "", false, err
	}
	j.SigningToken = token
	j.PKCEVerifier = ""

	credID := j.CredentialID
	if credID == "" {
		ids, err := f.o.entrust.CredentialsList(ctx, token)
		if err != nil {
			return "", false, err
		}
		if len(ids) == 0 {
			return "", false, errors.New("signing: no csc credential available")
		}
		credID = ids[0]
	}
	cred, err := f.o.entrust.CredentialInfo(ctx, token, credID)
	if err != nil {
		return "", false, err
	}
	if len(cred.Cert.Certificates) == 0 {
		return "", false, errors.New("signing: csc credential has no certificate")
	}
	j.CredentialID = credID
	j.SigningCert = cred.Cert.Certificates[0]
	j.SubjectRef = certSubject(j.SigningCert)
	if j.AuthCert == "" {
		j.AuthCert = j.SigningCert
	}

	if err := f.o.calculateDigests(ctx, j, j.SigningCert); err != nil {
		return "", false, err
	}
	return "", true, nil
}

func (f *cscFlow) Sign(ctx context.Context, j *job.Job) error {
	hashes := make([]string, len(j.Documents))
	for i := range j.Documents {
		hashes[i] = j.Documents[i].Digest
	}
	// OPEN (item E): SAD / account_token sequencing is unconfirmed — passing the
	// credential token as the Bearer with an empty SAD.
	sigs, err := f.o.entrust.SignHash(ctx, j.SigningToken, j.CredentialID, "", j.SignAlgo, hashes)
	if err != nil {
		return err
	}
	if len(sigs) != len(j.Documents) {
		return fmt.Errorf("signing: csc returned %d signatures for %d documents", len(sigs), len(j.Documents))
	}
	for i := range j.Documents {
		j.Documents[i].SignatureValue = sigs[i]
	}
	return nil
}

// ============================ TrustedX flows ================================

type txVariant int

const (
	txMobile txVariant = iota
	txEIDScan
	txCloudEseal
)

// txFlow implements mobile / eidScan / cloudEseal over the TrustedX surface —
// ~90% shared code, differing only in scopes, acr, identity selection, the sign
// primitive (serverRawSigner vs deviceRawSigner) and capabilities.
type txFlow struct {
	o       *Orchestrator
	variant txVariant
}

func (f *txFlow) Type() job.Flow {
	switch f.variant {
	case txEIDScan:
		return job.FlowEIDScan
	case txCloudEseal:
		return job.FlowEParakstsMobileEseal
	default:
		return job.FlowEParakstsMobile
	}
}

func (f *txFlow) Capabilities() Capabilities {
	switch f.variant {
	case txEIDScan:
		return Capabilities{UsesDigestSummary: true, DevicePush: true, SingleSessionOnly: true, Level: "QES"}
	case txCloudEseal:
		return Capabilities{SupportsBatch: true, UsesDigestSummary: true, Level: "SEAL"}
	default: // mobile
		return Capabilities{SupportsBatch: true, UsesDigestSummary: true, Level: "QES"}
	}
}

func (f *txFlow) BeginAuthorization(ctx *azugo.Context, j *job.Job) (string, error) {
	// A caller that resolved the person's sign identity at login supplies it
	// with both certificates; the profile leg (an extra authenticate+consent
	// redirect plus the identity and certificate reads) then has nothing left
	// to do and is skipped — the flow goes straight to the signature
	// authorization. No trust moves: the provider still binds the identity to
	// the authenticated user at that authorization, so a stale or foreign
	// identity fails there. Partial input takes the full path.
	if j.SignIdentityID != "" && j.SigningCert != "" && j.AuthCert != "" {
		return f.beginSuppliedIdentity(ctx, j)
	}

	state, err := f.o.newState()
	if err != nil {
		return "", err
	}
	j.OAuthState = state
	j.PendingLeg = job.LegProfile
	return f.o.entrust.ProfileAuthorizeURL(entrust.ProfileAuthorizeParams{
		State:     state,
		ACRValues: f.o.entrust.ACRForFlow(f.variant == txEIDScan, f.variant == txCloudEseal),
		UILocales: j.Locale,
	}), nil
}

// beginSuppliedIdentity is the supplied-identity fast path: digests are
// computed with the supplied signing certificate and the FIRST redirect the
// user sees is already the signature authorization (what advanceProfile
// otherwise builds after the profile leg).
func (f *txFlow) beginSuppliedIdentity(ctx *azugo.Context, j *job.Job) (string, error) {
	j.SubjectRef = certSubject(j.SigningCert)
	if err := f.o.calculateDigests(ctx, j, j.SigningCert); err != nil {
		return "", err
	}

	state, err := f.o.newState()
	if err != nil {
		return "", err
	}
	j.OAuthState = state
	j.PendingLeg = job.LegSign

	return f.o.entrust.SignAuthorizeURL(entrust.SignAuthorizeParams{
		State:                   state,
		ACRValues:               f.o.entrust.ACRForFlow(f.variant == txEIDScan, f.variant == txCloudEseal),
		UILocales:               j.Locale,
		SignIdentityID:          j.SignIdentityID,
		DigestsSummary:          j.DigestsSummary,
		DigestsSummaryAlgorithm: j.DigestsSummaryAlgo,
		UseDevice:               f.variant == txEIDScan,
	}), nil
}

func (f *txFlow) AdvanceCallback(ctx *azugo.Context, j *job.Job, code string) (string, bool, error) {
	switch j.PendingLeg {
	case job.LegProfile:
		return f.advanceProfile(ctx, j, code)
	case job.LegSign:
		token, err := f.o.entrust.Exchange(ctx, code)
		if err != nil {
			return "", false, err
		}
		j.SigningToken = token
		j.PendingLeg = job.LegNone
		return "", true, nil
	default:
		return "", false, fmt.Errorf("signing: unexpected callback leg %d", j.PendingLeg)
	}
}

// advanceProfile handles redirect #1: read identities, select sign + auth
// identities, fetch certs, compute digests, and build redirect #2.
func (f *txFlow) advanceProfile(ctx *azugo.Context, j *job.Job, code string) (string, bool, error) {
	profileToken, err := f.o.entrust.Exchange(ctx, code)
	if err != nil {
		return "", false, err
	}
	j.ProfileToken = profileToken

	ids, err := f.o.entrust.UsersMe(ctx, profileToken)
	if err != nil {
		return "", false, err
	}

	// Diagnostic: log the available sign-identities (id/description/status/labels —
	// the selection metadata; NOT the names/national-id/certificate, which are PII).
	for _, id := range ids {
		f.o.log.Debug("trustedx sign_identity",
			zap.String("id", id.ID),
			zap.String("description", id.Description),
			zap.String("status", id.Status.Value),
			zap.Strings("labels", id.Labels),
			zap.Any("access", id.Access))
	}

	var signIdent entrust.SignIdentity
	switch f.variant {
	case txEIDScan:
		signIdent, err = entrust.SelectEIDScanSigning(ids)
	case txCloudEseal:
		signIdent, err = entrust.SelectSealSigning(ids, j.SealID)
	default:
		signIdent, err = entrust.SelectMobileSigning(ids)
	}
	if err != nil {
		return "", false, err
	}
	j.SignIdentityID = signIdent.ID

	j.SigningCert, err = f.o.entrust.SignIdentityCert(ctx, profileToken, signIdent.ID)
	if err != nil {
		return "", false, err
	}
	j.SubjectRef = certSubject(j.SigningCert)

	authID, err := entrust.SelectAuthIdentity(ids, f.variant == txEIDScan)
	if err != nil {
		return "", false, err
	}
	j.AuthCert, err = f.o.entrust.SignIdentityCert(ctx, profileToken, authID.ID)
	if err != nil {
		return "", false, err
	}

	// CalculateDigest runs BETWEEN the redirects, with the signing cert.
	if err := f.o.calculateDigests(ctx, j, j.SigningCert); err != nil {
		return "", false, err
	}

	state, err := f.o.newState()
	if err != nil {
		return "", false, err
	}
	j.OAuthState = state
	j.PendingLeg = job.LegSign
	url := f.o.entrust.SignAuthorizeURL(entrust.SignAuthorizeParams{
		State:                   state,
		ACRValues:               f.o.entrust.ACRForFlow(f.variant == txEIDScan, f.variant == txCloudEseal),
		UILocales:               j.Locale,
		SignIdentityID:          j.SignIdentityID,
		DigestsSummary:          j.DigestsSummary,
		DigestsSummaryAlgorithm: j.DigestsSummaryAlgo,
		UseDevice:               f.variant == txEIDScan,
	})
	return url, false, nil
}

func (f *txFlow) Sign(ctx context.Context, j *job.Job) error {
	if f.variant == txEIDScan {
		return f.signDevice(ctx, j)
	}
	return f.signServerBatch(ctx, j)
}

// signServerBatch signs the batch server-side (mobile / cloudEseal).
func (f *txFlow) signServerBatch(ctx context.Context, j *job.Job) error {
	reqs := make([]entrust.ServerRawRequest, len(j.Documents))
	for i := range j.Documents {
		reqs[i] = entrust.ServerRawRequest{DigestValue: j.Documents[i].Digest, SignatureAlgorithm: j.SignAlgo}
	}
	sigs, err := f.o.entrust.ServerRawBatch(ctx, j.SigningToken, j.SignIdentityID, j.SignAlgo, reqs)
	if err != nil {
		return err
	}
	if len(sigs) != len(j.Documents) {
		return fmt.Errorf("signing: server/raw returned %d signatures for %d documents", len(sigs), len(j.Documents))
	}
	for i := range j.Documents {
		j.Documents[i].SignatureValue = sigs[i]
	}
	return nil
}

// signDevice pushes the single digest to the device, surfaces the verification
// code, and polls for the result (eidScan).
func (f *txFlow) signDevice(ctx context.Context, j *job.Job) error {
	if len(j.Documents) != 1 {
		return ErrBatchUnsupport
	}
	d := &j.Documents[0]

	code, err := entrust.VerificationCode(d.Digest)
	if err != nil {
		return err
	}
	deadline := time.Now().Add(f.o.cfg.EIDScanDeadline)
	// The prompt the device shows next to the code. Published on the job together
	// with the code so /status lets a portal display the exact same code + text
	// for the user to match during the device-push window.
	const message = "Confirm signing in eParaksts"
	j.VerificationCode = code
	j.VerificationMessage = message
	j.SigningDeadline = deadline.UnixMilli()
	if err := f.o.jobs.Save(ctx, j); err != nil {
		return err
	}

	sigID, err := f.o.entrust.DeviceRaw(ctx, j.SigningToken, j.SignIdentityID, d.Digest, digestAlgoFor(d.Digest),
		code, message, deadline.UnixMilli())
	if err != nil {
		return err
	}
	defer func() { _ = f.o.entrust.DeleteSignature(ctx, j.SigningToken, sigID) }()

	ticker := time.NewTicker(f.o.cfg.EIDScanPollInterval)
	defer ticker.Stop()
	grace := deadline.Add(10 * time.Second)
	for {
		res, err := f.o.entrust.PollDeviceResult(ctx, j.SigningToken, sigID)
		if err == nil {
			switch res.Status {
			case "finished":
				d.SignatureValue = res.Value
				return nil
			case "failed":
				return errors.New("signing:device_failed")
			case "canceled", "cancelled":
				return errors.New("signing:device_canceled")
			}
		}
		if time.Now().After(grace) {
			return errors.New("signing:device_timeout")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

// digestAlgoFor returns the SignAPI/TrustedX hash-algorithm label matching a
// base64 digest's decoded byte length (P-256→sha256, P-384→sha384, P-521→sha512).
// The Latvian eID signing key is P-384, so the DTBS is a 48-byte SHA-384 digest.
func digestAlgoFor(digestB64 string) string {
	if raw, err := base64.StdEncoding.DecodeString(digestB64); err == nil {
		switch len(raw) {
		case 48:
			return "sha384"
		case 64:
			return "sha512"
		}
	}
	return "sha256"
}

// pkce mints a PKCE verifier and its S256 challenge.
func pkce() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	sum := sha256.Sum256([]byte(verifier))
	challenge = base64.RawURLEncoding.EncodeToString(sum[:])
	return verifier, challenge, nil
}
