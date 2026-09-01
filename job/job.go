// Package job is the signing-job aggregate: the flow-aware state machine and the
// data the eParaksts Signing Service keeps in Redis for the lifetime of a job.
//
// The service is a stateless coordinator: a Job holds NO document bytes — only
// the SignAPI sessionIds, the (opaque) digests, the transient signature values,
// and the short-lived upstream tokens. Any replica can resume any job from Redis,
// which is what makes the callback/worker split and horizontal scaling safe.
package job

import "time"

// Flow is the signing flow selected by the inbound `?flow=` query parameter.
// One platform, two surfaces: csc rides the CSC API layer; eparakstsMobile/
// eidScan/eparakstsMobileEseal ride the existing TrustedX surface; webEid is the
// local card (client-side). Each token is identical to the auth login_method
// that authorizes it, so a login and the signing it drives correlate by name.
type Flow string

const (
	FlowCSC                  Flow = "csc"                  // CSC API layer · signHash (default)
	FlowWebEID               Flow = "webEid"               // local eID card via Web eID, client-side signing
	FlowEParakstsMobile      Flow = "eparakstsMobile"      // TrustedX · eParaksts Mobile · server/raw
	FlowEIDScan              Flow = "eidScan"              // TrustedX · eID NFC · device/raw + poll
	FlowEParakstsMobileEseal Flow = "eparakstsMobileEseal" // TrustedX · qualified eSeal · server/raw
)

// Valid reports whether f is a known flow.
func (f Flow) Valid() bool {
	switch f {
	case FlowCSC, FlowWebEID, FlowEParakstsMobile, FlowEIDScan, FlowEParakstsMobileEseal:
		return true
	default:
		return false
	}
}

// State is the coarse job state.
type State string

const (
	StatePreparing             State = "PREPARING"
	StateAwaitingAuthorization State = "AWAITING_AUTHORIZATION"
	StateAwaitingClientSig     State = "AWAITING_CLIENT_SIGNATURE"
	StateSigning               State = "SIGNING"
	StateFinalizing            State = "FINALIZING"
	StateReady                 State = "READY"
	StateFailed                State = "FAILED"
)

// Terminal reports whether the state is an end state.
func (s State) Terminal() bool { return s == StateReady || s == StateFailed }

// transitions encodes the valid state machine. A transition not listed here is
// rejected by Job.Transition.
var transitions = map[State]map[State]bool{
	StatePreparing: {
		StateAwaitingAuthorization: true, // csc / eparakstsMobile / eidScan / eparakstsMobileEseal
		StateAwaitingClientSig:     true, // webEid
		StateFailed:                true,
	},
	StateAwaitingAuthorization: {
		StateSigning: true, // consent / confirm obtained
		StateFailed:  true, // declined or expired
	},
	StateAwaitingClientSig: {
		StateFinalizing: true, // frontend submits signatures
		StateFailed:     true, // timeout or error
	},
	StateSigning: {
		StateFinalizing: true, // signature value(s) obtained
		StateFailed:     true,
	},
	StateFinalizing: {
		StateReady:  true,
		StateFailed: true,
	},
}

// CanTransition reports whether moving from -> to is allowed.
func CanTransition(from, to State) bool {
	if from == to {
		return true
	}
	return transitions[from][to]
}

// SignatureFormat is the AdES profile requested for a document.
type SignatureFormat string

const (
	FormatPAdES SignatureFormat = "PAdES"
	FormatXAdES SignatureFormat = "XAdES"
)

// Operation is the signature operation against the container.
type Operation string

const (
	OpCreate   Operation = "create"   // new container / signature
	OpParallel Operation = "parallel" // add a parallel signature to an existing one
)

// DocState is the per-document state surfaced in the status payload.
type DocState string

const (
	DocPending DocState = "PENDING"
	DocReady   DocState = "READY"
	DocFailed  DocState = "FAILED"
)

// Error is a structured per-document or per-job error (the inbound API error
// shape's inner object).
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Document is one item of the signing batch. It carries the SignAPI session it
// lives in, the opaque digest to sign, the transient signature value, and the
// per-document result — never the document bytes.
type Document struct {
	DocumentID string          `json:"document_id"`
	FileName   string          `json:"file_name"`
	MimeType   string          `json:"mime_type,omitempty"`
	Format     SignatureFormat `json:"format"`
	Operation  Operation       `json:"operation"`
	HashOnly   bool            `json:"hash_only,omitempty"` // confidential (addDocumentDigest)

	// SignAPI session this document is signed in. One session = one signature/
	// result container; an ASiC-E session may bundle several documents.
	SessionID string `json:"session_id,omitempty"`
	// Digest is the opaque DTBS from CalculateDigest (base64). SCAL2: echoed
	// verbatim into the signer, never recomputed.
	Digest          string `json:"digest,omitempty"`
	DigestAlgorithm string `json:"digest_algorithm,omitempty"`
	// DigestsSummary is the internal SAD-like value bound in the TrustedX
	// sign-consent redirect (not used by csc, not exposed to the caller).
	DigestsSummary string `json:"digests_summary,omitempty"`
	// SignatureValue is the transient signature (base64) from the signer, before
	// finalize. Cleared after finalize.
	SignatureValue string `json:"signature_value,omitempty"`

	State DocState `json:"state"`
	Error *Error   `json:"error,omitempty"`
}

// OAuthLeg holds the per-redirect correlation for a flow that bounces the
// browser through one or more authorize → /callback legs.
type OAuthLeg int

const (
	LegNone       OAuthLeg = iota
	LegProfile             // TrustedX redirect #1 (profile) — pending
	LegSign                // TrustedX redirect #2 (sign-consent) — pending
	LegCredential          // CSC credential-auth leg — pending
)

// Job is the signing-job aggregate persisted in Redis.
type Job struct {
	JobID string `json:"job_id"`
	Flow  Flow   `json:"flow"`
	State State  `json:"state"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`

	// Caller is the authenticated Portal-API service identity that created the job.
	Caller string `json:"caller,omitempty"`
	// Locale drives ui_locales on the upstream authorize requests.
	Locale string `json:"locale,omitempty"`

	// Redirect targets the browser is sent to after the flow completes / fails.
	PostAuthRedirect  string `json:"post_auth_redirect,omitempty"`
	AuthErrorRedirect string `json:"auth_error_redirect,omitempty"`

	// SignatureQualifier requested (e.g. eu_eidas_qes). csc credential selection.
	SignatureQualifier string `json:"signature_qualifier,omitempty"`
	// SignAlgo is the batch signature algorithm echoed from CalculateDigest
	// (the `signature_algorithm` field), echoed verbatim to the signer (SCAL2).
	SignAlgo string `json:"sign_algo,omitempty"`
	// DigestsSummary / DigestsSummaryAlgo are the internal SAD-like value (and its
	// `algorithm`, e.g. SHA256) bound in the TrustedX sign-consent redirect. Not
	// used by csc, never exposed to the caller.
	DigestsSummary     string `json:"digests_summary,omitempty"`
	DigestsSummaryAlgo string `json:"digests_summary_algo,omitempty"`
	// SealID is the cloudEseal qsealc sign-identity selector (optional).
	SealID string `json:"seal_id,omitempty"`

	Documents []Document `json:"documents"`

	// --- Flow correlation (single-use, short-lived; never returned to caller) ---

	// State (OAuth) value the upstream callback echoes; the Redis lookup key for
	// the in-flight authorization.
	OAuthState string `json:"oauth_state,omitempty"`
	// PendingLeg is which redirect leg the next /callback completes.
	PendingLeg OAuthLeg `json:"pending_leg,omitempty"`
	// PKCEVerifier for the csc oauth2code exchange.
	PKCEVerifier string `json:"pkce_verifier,omitempty"`

	// TrustedX selection (resolved after redirect #1).
	SignIdentityID string `json:"sign_identity_id,omitempty"`
	// SigningCert / AuthCert are base64-DER. SigningCert feeds CalculateDigest;
	// AuthCert is the SignAPI finalize authCertificate (the person's auth cert for
	// TrustedX flows; config-supplied for csc; the card cert for eid).
	SigningCert string `json:"signing_cert,omitempty"`
	AuthCert    string `json:"auth_cert,omitempty"`

	// CSC selection.
	CredentialID string `json:"credential_id,omitempty"`

	// Tokens are job-scoped and short-lived (≤600 s upstream token lifetime).
	// Stored in Redis with the job TTL; never logged, never sent to the caller.
	ProfileToken string `json:"profile_token,omitempty"`
	SigningToken string `json:"signing_token,omitempty"`

	// eidScan device-push surface, exposed in the status payload while SIGNING.
	// The message mirrors what the device displays with the code, so a portal can
	// show the exact same prompt for the user to match.
	VerificationCode    string `json:"verification_code,omitempty"`
	VerificationMessage string `json:"verification_message,omitempty"`
	SigningDeadline     int64  `json:"signing_deadline,omitempty"` // epoch ms

	// SubjectRef is the raw eID national id of the signer, captured for GDPR-audit
	// pseudonymization on the request path. Never persisted to the access log raw.
	SubjectRef string `json:"subject_ref,omitempty"`

	// AuditFinalEmitted guards the one-shot terminal eIDAS-audit audit emission so a
	// repeated status poll does not re-emit signing.applied. See routes/status.
	AuditFinalEmitted bool `json:"audit_final_emitted,omitempty"`

	// Err is the job-level failure (interim: finalize is all-or-nothing, Q G).
	Err *Error `json:"err,omitempty"`
}

// Transition moves the job to a new state if the transition is valid, stamping
// UpdatedAt. It returns false when the transition is not allowed.
func (j *Job) Transition(to State) bool {
	if !CanTransition(j.State, to) {
		return false
	}
	j.State = to
	j.UpdatedAt = time.Now().UTC()
	return true
}

// Fail moves the job to FAILED with a structured error and marks every
// not-yet-ready document failed (interim all-or-nothing semantics).
func (j *Job) Fail(code, message string) {
	j.Err = &Error{Code: code, Message: message}
	for i := range j.Documents {
		if j.Documents[i].State != DocReady {
			j.Documents[i].State = DocFailed
			if j.Documents[i].Error == nil {
				j.Documents[i].Error = &Error{Code: code, Message: message}
			}
		}
	}
	j.State = StateFailed
	j.UpdatedAt = time.Now().UTC()
}

// Doc returns the document with the given id, or nil.
func (j *Job) Doc(id string) *Document {
	for i := range j.Documents {
		if j.Documents[i].DocumentID == id {
			return &j.Documents[i]
		}
	}
	return nil
}
