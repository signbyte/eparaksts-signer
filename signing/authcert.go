package signing

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"

	"github.com/gmb-lib/go-platform-kit/observability"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/job"
)

// The finalize authCertificate is the certificate the timestamp is requested
// with, and there are two ways to supply it.
//
// By default it is the signer's own authentication certificate, carried on the
// request: the signer is entitled to the timestamp, so it costs the deployment
// nothing. The alternative is this deployment's own timestamping-access
// certificate, configured once — the timestamp is then billed to the
// deployment rather than to the signer.
//
// The second is not a fallback, it is a choice made per signing flow, and for
// some flows it is the only option: a method whose authentication certificates
// carry no timestamping entitlement, or that issues no authentication
// certificate at all, sends no certificate and cannot be finalized without a
// configured one.

// allFlows selects every signing flow.
const allFlows = "all"

// DefaultTSAAccessCertFlows is the shipped default — only the flow that has
// never carried a signer certificate, so an existing deployment is unaffected.
const DefaultTSAAccessCertFlows = string(job.FlowCSC)

// FlowSet is the set of flows that finalize with the deployment's own
// timestamping-access certificate.
type FlowSet struct {
	all   bool
	flows map[job.Flow]struct{}
}

// ParseFlowSet reads a flow list: "all", or comma-separated flow names.
// Whitespace is trimmed, empty entries are skipped, and an unrecognized name is
// ignored here — UnknownFlowNames reports it so startup can say so once.
func ParseFlowSet(list string) FlowSet {
	set := FlowSet{flows: map[job.Flow]struct{}{}}
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		switch {
		case name == "":
			continue
		case strings.EqualFold(name, allFlows):
			set.all = true
		default:
			if f := job.Flow(name); f.Valid() {
				set.flows[f] = struct{}{}
			}
		}
	}

	return set
}

// Has reports whether f finalizes with the deployment's certificate.
func (s FlowSet) Has(f job.Flow) bool {
	if s.all {
		return true
	}
	_, ok := s.flows[f]

	return ok
}

// UnknownFlowNames returns the entries of a flow list that name no signing
// flow. An unrecognized name selects nothing, so it is worth reporting but not
// worth refusing to start over: it is almost always a typo, and the flow it was
// meant to name simply keeps using the signer's own certificate — or, when that
// flow supplies none, is refused at signing time.
func UnknownFlowNames(list string) []string {
	var unknown []string
	for _, name := range strings.Split(list, ",") {
		name = strings.TrimSpace(name)
		if name == "" || strings.EqualFold(name, allFlows) {
			continue
		}
		if !job.Flow(name).Valid() {
			unknown = append(unknown, name)
		}
	}

	return unknown
}

// KnownFlowNames lists every flow name a flow list may carry, so a report about
// an unrecognized one can say what was expected.
func KnownFlowNames() []string {
	return []string{
		string(job.FlowWebEID),
		string(job.FlowEParakstsMobile),
		string(job.FlowEIDScan),
		string(job.FlowEParakstsMobileEseal),
		string(job.FlowCSC),
	}
}

// CertSource says whose certificate a timestamp was requested with. It is the
// answer to "who pays for this one": the signer is entitled to their own
// timestamp, the deployment is billed for the timestamps it requests with its
// own certificate.
type CertSource string

// Certificate sources.
const (
	// SourceSigner — the signer's own authentication certificate, carried on
	// the request. The timestamp is free to them.
	SourceSigner CertSource = "signer"
	// SourceDeployment — this deployment's configured timestamping-access
	// certificate. The timestamp is billed to the deployment.
	SourceDeployment CertSource = "deployment"
)

// Metric names. Requests and refusals are counted separately so "how many
// timestamps did we request, and of those how many did we pay for" is a sum
// over one series rather than a filtered subset of a mixed one.
const (
	// MetricTimestampRequests counts timestamps requested, labelled by whose
	// certificate requested it and which flow and operation it was for.
	MetricTimestampRequests = "signing_timestamp_requests_total"
	// MetricTimestampRefused counts signings and archive runs refused because
	// nothing was available to request the timestamp with — a misconfiguration
	// signal, not a request.
	MetricTimestampRefused = "signing_timestamp_refused_total"
)

// Metric label keys.
const (
	labelSource = "source"
	labelFlow   = "flow"
	labelOp     = "op"
)

// Operations that request a timestamp.
const (
	// OpSign is the timestamp taken when a signature is finalized.
	OpSign = "sign"
	// OpArchive is the timestamp added when a signed document is archived.
	OpArchive = "archive"
)

// authCertFor returns the certificate to send as the finalize authCertificate
// for this job, whose it is, and whether one is available at all. A flow
// configured to use the deployment's certificate uses it; every other flow uses
// the signer's own, captured on the job when the signing was prepared.
func (o *Orchestrator) authCertFor(j *job.Job) (string, CertSource, bool) {
	if o.cfg.TSAAccessCertFlows.Has(j.Flow) {
		if cert := strings.TrimSpace(o.cfg.TSAAccessCert); cert != "" {
			return cert, SourceDeployment, true
		}

		return "", SourceDeployment, false
	}
	cert := strings.TrimSpace(j.AuthCert)

	return cert, SourceSigner, cert != ""
}

// recordTimestampRequest records that a timestamp was requested, and with whose
// certificate. Every timestamp requested with the deployment's own certificate
// is a billable act, so this is what a deployment counts to know what it owes,
// and what tells the two paths apart after the fact — the validation answer
// reports nothing about the timestamping service.
//
// The source and the flow are kept as separate fields rather than packed into
// one token so either can be grouped on: "how many did the deployment pay for
// this month" and "which flows used the signer's own certificate" are different
// questions over the same record.
func (o *Orchestrator) recordTimestampRequest(j *job.Job, source CertSource, op, cert string) {
	observability.IncCounter(MetricTimestampRequests, map[string]string{
		labelSource: string(source),
		labelFlow:   string(j.Flow),
		labelOp:     op,
	})

	fields := []zap.Field{
		zap.String("certificate_source", string(source)),
		zap.String("flow", string(j.Flow)),
		zap.String("operation", op),
		zap.String("job", j.JobID),
	}
	// Which configured certificate was charged, so a run can still be
	// reconciled after the deployment rotates to another one. A fingerprint,
	// never the certificate itself.
	if source == SourceDeployment {
		fields = append(fields, zap.String("certificate_fingerprint", certFingerprint(cert)))
	}
	o.log.Info("timestamp requested", fields...)
}

// recordTimestampRefused records a signing or archive refused for want of any
// certificate to request the timestamp with. Counted apart from requests
// because it is a configuration fault, and it is the one an operator wants to
// see: nothing else announces it until someone tries to sign.
func (o *Orchestrator) recordTimestampRefused(j *job.Job, op string) {
	observability.IncCounter(MetricTimestampRefused, map[string]string{
		labelFlow: string(j.Flow),
		labelOp:   op,
	})
	o.log.Warn("no certificate to request the timestamp with",
		zap.String("flow", string(j.Flow)),
		zap.String("operation", op),
		zap.String("job", j.JobID))
}

// certFingerprint is the SHA-256 of a base64 certificate, truncated — enough to
// tell two configured certificates apart in a log without carrying either.
// An unparseable value fingerprints as-is rather than failing: this runs on the
// reporting path, never on the deciding one.
func certFingerprint(cert string) string {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(cert))
	if err != nil {
		raw = []byte(cert)
	}
	sum := sha256.Sum256(raw)

	return hex.EncodeToString(sum[:8])
}
