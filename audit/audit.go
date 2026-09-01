// Package audit records the eParaksts Signing Service's audit events through all
// three platform regimes — the signer wires all three:
//
// - eIDAS-audit (eIDAS signing evidence) via go-eidas-audit → the audit broker
// topic: signing.initiated / signing.redirect / signing.callback /
// signing.applied (Level QES|SEAL, container Format), lean references only.
// - GDPR-audit (GDPR personal-data access) via go-gdpr-audit → access-audit: each
// time the service processes a signer's certificate/identity, with a
// PSEUDONYMIZED data-subject ref (HMAC of the national id; raw id never logged).
// Optional — wired only when access-audit is configured.
// - NIS2-audit (NIS2 security telemetry) via go-sec-events → SIEM: endpoint
// outcomes and authorization denials, metadata only.
//
// Every method takes the request *azugo.Context, so emission happens on the
// request path (the worker carries no request context); the terminal
// signing.applied is emitted once from /status when the job first goes READY.
package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"azugo.io/azugo"
	"go.uber.org/zap"

	"github.com/gmb-lib/go-eidas-audit/eidas"
	"github.com/gmb-lib/go-gdpr-audit/gdpr"
	"github.com/gmb-lib/go-platform-kit/broker"
	"github.com/gmb-lib/go-sec-events/secevents"

	"github.com/signbyte/eparaksts-signer/job"
)

// NIS2-audit security event types for the signing endpoints.
const (
	eventPrepare  = "eparaksts.prepare"
	eventSign     = "eparaksts.sign"
	eventValidate = "eparaksts.validate"
	eventArchive  = "eparaksts.archive"
)

// Pseudonymizer turns an eID national id into a stable, non-reversible reference
// for the access log (HMAC-SHA256, key held in memory from Vault).
type Pseudonymizer struct {
	key []byte
}

// NewPseudonymizer returns a Pseudonymizer over a copy of key (must be non-empty).
func NewPseudonymizer(key []byte) (*Pseudonymizer, error) {
	if len(key) == 0 {
		return nil, errors.New("audit: empty pseudonym key")
	}
	k := make([]byte, len(key))
	copy(k, key)
	return &Pseudonymizer{key: k}, nil
}

// Ref returns the pseudonymous data-subject ref for an eID national id, or "".
func (p *Pseudonymizer) Ref(id string) string {
	if p == nil || id == "" {
		return ""
	}
	mac := hmac.New(sha256.New, p.key)
	_, _ = mac.Write([]byte(id))
	return "psn:" + hex.EncodeToString(mac.Sum(nil))
}

// Recorder emits the three regimes. eidasEmitter and sec are required; gdpr+psn
// may be nil together (GDPR-audit then no-ops).
type Recorder struct {
	eidas *eidas.Emitter
	sec   *secevents.Emitter
	gdpr  *gdpr.Client
	psn   *Pseudonymizer
	log   *zap.Logger
}

// New builds a Recorder.
func New(eidasEmitter *eidas.Emitter, sec *secevents.Emitter, gdprClient *gdpr.Client, psn *Pseudonymizer, log *zap.Logger) *Recorder {
	if log == nil {
		log = zap.NewNop()
	}
	return &Recorder{eidas: eidasEmitter, sec: sec, gdpr: gdprClient, psn: psn, log: log}
}

// ---- eIDAS-audit — eIDAS signing evidence -------------------------------------

// Initiated records signing.initiated for the job.
func (r *Recorder) Initiated(ctx *azugo.Context, j *job.Job) {
	if r == nil || r.eidas == nil {
		return
	}
	if err := r.eidas.SigningInitiated(ctx, eidas.SigningInit{
		Actor:      broker.Actor{ID: j.Caller, Type: "service"},
		EnvelopeID: j.JobID,
		Method:     string(j.Flow),
		InputType:  inputType(j),
	}); err != nil {
		r.log.Error("eidas initiated emit failed", zap.Error(err))
	}
}

// Redirect records signing.redirect (a remote flow sent the browser upstream).
func (r *Recorder) Redirect(ctx *azugo.Context, j *job.Job) {
	if r == nil || r.eidas == nil {
		return
	}
	if err := r.eidas.ProviderRedirect(ctx, eidas.Provider{
		Actor:      broker.Actor{ID: j.Caller, Type: "service"},
		EnvelopeID: j.JobID,
		Provider:   eidas.ProviderEntrust,
		StateRef:   refOf(j.OAuthState),
		Outcome:    broker.OutcomeSuccess,
	}); err != nil {
		r.log.Error("eidas redirect emit failed", zap.Error(err))
	}
}

// Callback records signing.callback (the upstream authorization returned).
func (r *Recorder) Callback(ctx *azugo.Context, j *job.Job, success bool) {
	if r == nil || r.eidas == nil {
		return
	}
	out := broker.OutcomeSuccess
	if !success {
		out = broker.OutcomeFailure
	}
	if err := r.eidas.ProviderCallback(ctx, eidas.Provider{
		Actor:      broker.Actor{ID: j.Caller, Type: "service"},
		EnvelopeID: j.JobID,
		Provider:   eidas.ProviderEntrust,
		Outcome:    out,
	}); err != nil {
		r.log.Error("eidas callback emit failed", zap.Error(err))
	}
}

// Applied records signing.applied for every document of a completed job (the
// terminal evidence event), plus a NIS2-audit success outcome.
func (r *Recorder) Applied(ctx *azugo.Context, j *job.Job) {
	if r != nil && r.eidas != nil {
		for i := range j.Documents {
			d := &j.Documents[i]
			if d.State != job.DocReady {
				continue
			}
			if err := r.eidas.SignatureApplied(ctx, eidas.Signature{
				Actor:             broker.Actor{ID: j.Caller, Type: "service"},
				EnvelopeID:        j.JobID,
				Slot:              d.DocumentID,
				Format:            formatOf(d.Format),
				Level:             levelForFlow(j.Flow),
				BaselineConfirmed: true, // SignAPI finalize produces B-LT
			}); err != nil {
				r.log.Error("eidas applied emit failed", zap.Error(err))
			}
		}
	}
	r.outcome(ctx, eventSign, j.Caller, true)
}

// Failed records a NIS2-audit failure outcome for a terminal-failed job.
func (r *Recorder) Failed(ctx *azugo.Context, j *job.Job) {
	r.outcome(ctx, eventSign, j.Caller, false)
}

// ---- GDPR-audit — GDPR personal-data access ----------------------------------

// SignerAccessed records that the service processed a signer's certificate /
// identity (the personal-data access). subjectID is the raw national id; it is
// pseudonymized here and never stored raw. No-op when GDPR-audit is off.
func (r *Recorder) SignerAccessed(ctx *azugo.Context, caller, subjectID string) {
	if r == nil || r.gdpr == nil || r.psn == nil {
		return
	}
	ref := r.psn.Ref(subjectID)
	if ref == "" {
		return
	}
	err := r.gdpr.Record(ctx, gdpr.EventEnvelopeAccess, gdpr.Access{
		Actor:        broker.Actor{ID: caller, Type: "service"},
		DataSubjects: []string{ref},
		Resource:     broker.Resource{Type: "signature"},
		Operation:    broker.OpSign,
		LawfulBasis:  gdpr.BasisContract,
		Purpose:      gdpr.PurposeSigning,
		Channel:      gdpr.ChannelBackground,
	})
	if err != nil {
		// Routine / fail-open: never break signing on audit back-pressure.
		r.log.Warn("gdpr access record not persisted (non-fatal)", zap.Error(err))
	}
}

// ---- NIS2-audit — security telemetry -----------------------------------------

// PrepareOutcome records the outcome of a /prepare request.
func (r *Recorder) PrepareOutcome(ctx *azugo.Context, caller string, success bool) {
	r.outcome(ctx, eventPrepare, caller, success)
}

// ValidateOutcome records the outcome of a /validations request.
func (r *Recorder) ValidateOutcome(ctx *azugo.Context, caller string, success bool) {
	r.outcome(ctx, eventValidate, caller, success)
}

// ArchiveOutcome records the outcome of an archive-timestamp request.
func (r *Recorder) ArchiveOutcome(ctx *azugo.Context, caller string, success bool) {
	r.outcome(ctx, eventArchive, caller, success)
}

// Denied records an authorization (scope) denial.
func (r *Recorder) Denied(ctx *azugo.Context, caller, requiredScope string) {
	if r == nil || r.sec == nil {
		return
	}
	if err := r.sec.AuthZDenied(ctx, secevents.Denial{
		Actor:         broker.Actor{ID: caller, Type: "service"},
		RequiredScope: requiredScope,
		Reason:        "missing scope",
	}); err != nil {
		r.log.Error("secevents denied emit failed", zap.Error(err))
	}
}

func (r *Recorder) outcome(ctx *azugo.Context, eventType, caller string, success bool) {
	if r == nil || r.sec == nil {
		return
	}
	out := broker.OutcomeSuccess
	if !success {
		out = broker.OutcomeFailure
	}
	ev := &broker.Envelope{
		EventType:  eventType,
		Categories: []broker.Category{broker.CategorySecurity},
		Actor:      &broker.Actor{ID: caller, Type: "service"},
		Outcome:    out,
	}
	if err := r.sec.Emit(ctx, ev); err != nil {
		r.log.Error("secevents emit failed", zap.String("event_type", eventType), zap.Error(err))
	}
}

// ---- mapping helpers --------------------------------------------------------

func levelForFlow(f job.Flow) eidas.SignatureLevel {
	if f == job.FlowEParakstsMobileEseal {
		return eidas.LevelSeal
	}
	return eidas.LevelQES
}

func formatOf(f job.SignatureFormat) eidas.SignatureFormat {
	if f == job.FormatPAdES {
		return eidas.FormatPAdES
	}
	return eidas.FormatXAdES
}

func inputType(j *job.Job) eidas.InputType {
	if len(j.Documents) > 0 {
		switch {
		case j.Documents[0].HashOnly:
			return eidas.InputHash
		case j.Documents[0].Format == job.FormatPAdES:
			return eidas.InputPDF
		}
	}
	return eidas.InputFile
}

func refOf(s string) string {
	if len(s) > 12 {
		return s[:12]
	}
	return s
}
