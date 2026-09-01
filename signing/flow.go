// Package signing is the signing orchestrator: the shared document spine
// (sessions → CalculateDigest → finalize → deliver) plus the pluggable
// SigningFlow seam that supplies only the variable step #4 — obtaining the
// signature value(s). One spine, many flows.
package signing

import (
	"context"

	"azugo.io/azugo"

	"github.com/signbyte/eparaksts-signer/job"
)

// Capabilities describes a flow's shape so the orchestrator can run it generically.
type Capabilities struct {
	// SupportsBatch — the flow can sign more than one session per job.
	SupportsBatch bool
	// UsesDigestSummary — the flow binds the digests_summary in its authorization.
	UsesDigestSummary bool
	// ClientSide — eid: digests are returned to the caller and the signatures are
	// submitted back; there is no upstream signing call and no authorize redirect.
	ClientSide bool
	// DevicePush — eidScan: server push to the device + verification code + poll.
	DevicePush bool
	// SingleSessionOnly — eidScan: device/raw signs exactly one digest.
	SingleSessionOnly bool
	// Level is the eIDAS signature level recorded in the eIDAS-audit trail.
	Level string // "QES" | "SEAL"
}

// Flow is the per-`?flow=` strategy. The orchestrator owns the spine and
// delegates only these variable steps. eid is client-side (ClientSide) and does
// not implement the authorization/sign methods.
type Flow interface {
	Type() job.Flow
	Capabilities() Capabilities

	// BeginAuthorization builds the first authorize URL for a remote flow (csc:
	// oauth2code consent; TrustedX: profile redirect). It stamps j.OAuthState and
	// j.PendingLeg. Not called for ClientSide flows.
	BeginAuthorization(ctx *azugo.Context, j *job.Job) (authorizeURL string, err error)

	// AdvanceCallback handles one browser /callback leg, exchanging the code and
	// advancing the flow. It returns either the next authorize URL (another
	// redirect) or done=true (the job is ready for the background worker). Not
	// called for ClientSide flows.
	AdvanceCallback(ctx *azugo.Context, j *job.Job, code string) (nextURL string, done bool, err error)

	// Sign runs in the background worker: it obtains the signature value(s) and
	// writes them onto j.Documents[i].SignatureValue (raw, pre-DER-normalize).
	// For eidScan it also publishes the verification code mid-flight (via the
	// store) so /status can surface it. Not called for ClientSide flows.
	Sign(ctx context.Context, j *job.Job) error
}

// InputDocument is one document of a prepare batch (bytes XOR hash). When the
// document being signed is itself an ASiC-E container, Files carries its inner data
// objects — they are registered together under one signature (a parallel
// co-signature), instead of the single Hash.
type InputDocument struct {
	DocumentID      string
	FileName        string
	MimeType        string
	Format          job.SignatureFormat
	Operation       job.Operation
	Bytes           []byte // nil when HashOnly
	Hash            string // base64 digest, when HashOnly (single file)
	DigestAlgorithm string // for HashOnly
	// Files are the container's inner data objects when co-signing (hash-only); all
	// are registered under one signature. Empty for a normal document.
	Files []InputFile
}

// InputFile is one inner data object of a container being co-signed: the
// in-container filename and its digest.
type InputFile struct {
	Name            string
	Digest          string
	DigestAlgorithm string
}

// PrepareInput is the parsed /prepare request.
type PrepareInput struct {
	Flow               job.Flow
	Caller             string
	Locale             string
	SignatureQualifier string
	// SigningCert / AuthCert (base64 DER): the card certificates for the eid
	// flow (signing → CalculateDigest; auth → finalize authCertificate/TSA),
	// or a caller's login-captured identity certificates for a remote flow —
	// with SignIdentityID, they let the flow skip its identity-resolution leg.
	SigningCert string
	AuthCert    string
	// SignIdentityID is the provider-side sign identity the supplied
	// certificates belong to (remote flows; optional, captured at login).
	SignIdentityID    string
	SealID            string // seal selector (the e-seal flow)
	PostAuthRedirect  string
	AuthErrorRedirect string
	Documents         []InputDocument
}

// DigestOut is one digest returned to the caller (eid).
type DigestOut struct {
	DocumentID      string
	Digest          string
	DigestAlgorithm string
}

// PrepareResult is the outcome of /prepare.
type PrepareResult struct {
	Job          *job.Job
	AuthorizeURL string      // remote flows
	Digests      []DigestOut // eid
	SignAlgo     string      // eid (e.g. "ecdsa")
}

// SubmittedSignature is one client-side signature value submitted for eid.
type SubmittedSignature struct {
	DocumentID     string
	SignatureValue string // base64
}
