package signing

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"azugo.io/azugo"
	"github.com/gmb-lib/go-csc/lvrtc"
	"github.com/oklog/ulid/v2"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
	"github.com/signbyte/eparaksts-signer/signapi"
)

// Errors surfaced to handlers.
var (
	ErrUnknownFlow    = errors.New("signing: unknown flow")
	ErrNotClientFlow  = errors.New("signing: not a client-signature flow")
	ErrWrongState     = errors.New("signing: job not in the expected state")
	ErrCSCNotEnabled  = errors.New("signing: csc flow not enabled (no CSC client configured)")
	ErrBatchUnsupport = errors.New("signing: batch not supported for this flow")
	ErrMixedFormat    = errors.New("signing: mixed-format batch not supported")
	ErrNoAuthCert     = errors.New("signing: no auth certificate (supply the signed-in user's authCertificate)")
	// ErrNoTimestampCert means nothing can request the timestamp for this
	// signing: the request carried no authentication certificate, and this
	// flow is not configured to use the deployment's own timestamping-access
	// certificate. Client-actionable — send the signer's certificate, or
	// configure the deployment to pay for this flow's timestamps.
	ErrNoTimestampCert = errors.New("signing: no certificate to request the timestamp with (send the signer's authCertificate, or configure this flow to use the deployment's timestamping-access certificate)")
	// ErrDocumentRejected means the signing provider gave a definitive rejection
	// (a 4xx) of the document we sent — it is not a valid signed document (e.g. not
	// a PDF, or a PDF with no signature to extend). Client-actionable, NOT an
	// upstream outage, so handlers map it to a 4xx rather than a 502.
	ErrDocumentRejected = errors.New("signing: provider rejected the document as not a valid signed document")
)

// classifyUpstream maps a definitive SignAPI 4xx (the document/payload we sent was
// refused) to ErrDocumentRejected — client-actionable — while leaving 5xx and
// transport errors intact so a genuine upstream outage still surfaces as
// unavailable. The original error is kept in the chain for logging.
func classifyUpstream(err error) error {
	var ae *signapi.APIError
	if errors.As(err, &ae) && ae.ClientError() {
		return fmt.Errorf("%w: %w", ErrDocumentRejected, err)
	}
	return err
}

// Config holds orchestrator-level knobs (the upstream surface lives in the
// entrust client and SignAPI client).
type Config struct {
	DefaultSignatureQualifier string
	EIDScanPollInterval       time.Duration
	EIDScanDeadline           time.Duration
	// TSAAccessCert is this deployment's own timestamping-access certificate
	// (base64), used as the finalize authCertificate for TSAAccessCertFlows.
	TSAAccessCert string
	// TSAAccessCertFlows names the flows that finalize with TSAAccessCert
	// rather than with the signer's own authentication certificate.
	TSAAccessCertFlows FlowSet
}

// Orchestrator runs the shared spine and dispatches to the SigningFlow seam.
type Orchestrator struct {
	jobs    *job.Store
	signapi *signapi.Client
	entrust *entrust.Client
	cfg     Config
	log     *zap.Logger
	flows   map[job.Flow]Flow
	// closing tracks the session closes still running after their caller answered.
	closing sync.WaitGroup
}

// New builds the orchestrator and registers all flows.
func New(jobs *job.Store, sa *signapi.Client, ent *entrust.Client, cfg Config, log *zap.Logger) *Orchestrator {
	if log == nil {
		log = zap.NewNop()
	}
	if cfg.EIDScanPollInterval <= 0 {
		cfg.EIDScanPollInterval = 2 * time.Second
	}
	if cfg.EIDScanDeadline <= 0 {
		cfg.EIDScanDeadline = 120 * time.Second
	}
	o := &Orchestrator{jobs: jobs, signapi: sa, entrust: ent, cfg: cfg, log: log}
	o.flows = map[job.Flow]Flow{
		job.FlowWebEID:               &eidFlow{o: o},
		job.FlowCSCEidScan:           &cscFlow{o: o, flow: job.FlowCSCEidScan, eid: lvrtc.EIDScan},
		job.FlowCSCEidPlugin:         &cscFlow{o: o, flow: job.FlowCSCEidPlugin, eid: lvrtc.CardOnComputer},
		job.FlowEParakstsMobile:      &txFlow{o: o, variant: txMobile},
		job.FlowEIDScan:              &txFlow{o: o, variant: txEIDScan},
		job.FlowEParakstsMobileEseal: &txFlow{o: o, variant: txCloudEseal},
	}
	return o
}

// Flow returns the strategy for a flow value, or nil.
func (o *Orchestrator) Flow(f job.Flow) Flow { return o.flows[f] }

// Offered reports whether this deployment runs flow f. Every registered flow
// runs wherever the service does — the signing API it depends on authenticates
// with the same platform client the other remote flows use — except the CSC
// flows, which need a CSC client of their own.
func (o *Orchestrator) Offered(f job.Flow) bool {
	if o.flows[f] == nil {
		return false
	}
	if f.IsCSC() {
		return o.entrust != nil && o.entrust.CSCEnabled()
	}
	return true
}

// OfferedFlows lists the flows this deployment runs, in the order a caller is
// shown them. Prepare refuses exactly the flows missing from it.
func (o *Orchestrator) OfferedFlows() []job.Flow {
	var out []job.Flow
	for _, f := range job.Flows() {
		if o.Offered(f) {
			out = append(out, f)
		}
	}
	return out
}

// Store exposes the job store (used by the worker + handlers).
func (o *Orchestrator) Store() *job.Store { return o.jobs }

// Prepare creates a job, uploads documents, and begins the selected flow. It
// returns the next action: an authorize URL (remote) or digests to sign (eid).
func (o *Orchestrator) Prepare(ctx *azugo.Context, in PrepareInput) (*PrepareResult, error) {
	flow := o.flows[in.Flow]
	if flow == nil {
		return nil, ErrUnknownFlow
	}
	caps := flow.Capabilities()

	if err := validateBatch(in, caps); err != nil {
		return nil, err
	}
	if !o.Offered(in.Flow) {
		return nil, ErrCSCNotEnabled
	}
	// A CSC signing's timestamp certificate can only come from the request (its
	// signing credential is minted for the signing and cannot request one), so a
	// request without one is refused now, before anything is uploaded and before the
	// person is asked to confirm twice — finalize would refuse it only after both.
	if in.Flow.IsCSC() {
		if _, _, ok := o.authCertFor(&job.Job{Flow: in.Flow, AuthCert: in.AuthCert}); !ok {
			return nil, ErrNoTimestampCert
		}
	}

	j := &job.Job{
		JobID:              ulid.Make().String(),
		Flow:               in.Flow,
		State:              job.StatePreparing,
		CreatedAt:          time.Now().UTC(),
		UpdatedAt:          time.Now().UTC(),
		Caller:             in.Caller,
		Locale:             in.Locale,
		PostAuthRedirect:   in.PostAuthRedirect,
		AuthErrorRedirect:  in.AuthErrorRedirect,
		SignatureQualifier: orDefault(in.SignatureQualifier, o.cfg.DefaultSignatureQualifier),
		SealID:             in.SealID,
	}
	for _, d := range in.Documents {
		j.Documents = append(j.Documents, job.Document{
			DocumentID:      d.DocumentID,
			FileName:        d.FileName,
			MimeType:        d.MimeType,
			Format:          d.Format,
			Operation:       d.Operation,
			HashOnly:        len(d.Bytes) == 0,
			DigestAlgorithm: d.DigestAlgorithm,
			State:           job.DocPending,
		})
	}

	// Spine step 2: create one SignAPI session per document and upload.
	if err := o.createSessionsAndUpload(ctx, j, in.Documents); err != nil {
		j.Fail("signapi:upload_failed", err.Error())
		_ = o.jobs.Save(ctx, j)
		return nil, err
	}

	res := &PrepareResult{Job: j}

	if caps.ClientSide {
		// eid: the card certs are supplied; compute the digests and hand them back.
		// The signing certificate feeds the digest calculation; the authentication
		// certificate is what the timestamp is later requested with, and the two are
		// not interchangeable — a missing one is refused at finalize rather than
		// replaced by the other.
		j.SigningCert = in.SigningCert
		j.AuthCert = in.AuthCert
		j.SubjectRef = certSubject(in.SigningCert)
		if err := o.calculateDigests(ctx, j, in.SigningCert); err != nil {
			j.Fail("signapi:calculate_digest_failed", err.Error())
			_ = o.jobs.Save(ctx, j)
			return nil, err
		}
		j.Transition(job.StateAwaitingClientSig)
		res.SignAlgo = signAlgoName(j.SignAlgo)
		for i := range j.Documents {
			res.Digests = append(res.Digests, DigestOut{
				DocumentID:      j.Documents[i].DocumentID,
				Digest:          j.Documents[i].Digest,
				DigestAlgorithm: j.Documents[i].DigestAlgorithm,
			})
		}
	} else {
		// Remote: a caller may supply the person's sign identity + certificates
		// (captured at their login); the flow then skips its own identity
		// resolution. Only a complete set is taken — anything missing and the
		// flow resolves identities itself, exactly as without a caller supply.
		//
		// A CSC flow takes only the authentication certificate: its signing credential is
		// minted for this signing, and the login's authentication certificate is what
		// the timestamp can be requested with.
		switch {
		case in.Flow.IsCSC():
			j.AuthCert = in.AuthCert
		case in.SignIdentityID != "" && in.SigningCert != "" && in.AuthCert != "":
			j.SignIdentityID = in.SignIdentityID
			j.SigningCert = in.SigningCert
			j.AuthCert = in.AuthCert
		}
		// Begin the flow's authorization and hand back the redirect URL.
		url, err := flow.BeginAuthorization(ctx, j)
		if err != nil {
			j.Fail("signing:begin_authorization_failed", err.Error())
			_ = o.jobs.Save(ctx, j)
			return nil, err
		}
		j.Transition(job.StateAwaitingAuthorization)
		res.AuthorizeURL = url
	}

	if err := o.jobs.Save(ctx, j); err != nil {
		return nil, err
	}
	return res, nil
}

// Callback advances a browser /callback leg. It returns the job and the URL the
// browser must be redirected to next (the next authorize step, or
// postAuthRedirect on completion, or authErrorRedirect on failure). ErrNotFound
// from the store means an unknown/expired state (potential tampering) — the
// handler returns 400.
func (o *Orchestrator) Callback(ctx *azugo.Context, state, code string, declined bool) (*job.Job, string, error) {
	j, err := o.jobs.LoadByState(ctx, state)
	if err != nil {
		return nil, "", err
	}
	o.jobs.ClearState(ctx, state) // single-use

	if declined {
		j.Fail("signing:declined", "user declined authorization")
		_ = o.jobs.Save(ctx, j)
		return j, substituteJobID(j.AuthErrorRedirect, j.JobID), nil
	}

	flow := o.flows[j.Flow]
	if flow == nil {
		j.Fail("signing:unknown_flow", string(j.Flow))
		_ = o.jobs.Save(ctx, j)
		return j, substituteJobID(j.AuthErrorRedirect, j.JobID), nil
	}

	nextURL, done, err := flow.AdvanceCallback(ctx, j, code)
	if err != nil {
		o.log.Warn("callback advance failed", zap.String("job", j.JobID), zap.String("flow", string(j.Flow)), zap.Int("leg", int(j.PendingLeg)), zap.Error(err))
		j.Fail("signing:callback_failed", err.Error())
		_ = o.jobs.Save(ctx, j)
		return j, substituteJobID(j.AuthErrorRedirect, j.JobID), nil
	}

	if !done {
		// Another redirect leg; the new state index is persisted by Save.
		if err := o.jobs.Save(ctx, j); err != nil {
			return j, "", err
		}
		return j, nextURL, nil
	}

	// Authorization complete → enqueue the background signing worker.
	j.Transition(job.StateSigning)
	if err := o.jobs.Save(ctx, j); err != nil {
		return j, "", err
	}
	if err := o.jobs.EnqueueWork(ctx, j.JobID); err != nil {
		o.log.Error("enqueue work failed", zap.String("job", j.JobID), zap.Error(err))
	}
	return j, substituteJobID(j.PostAuthRedirect, j.JobID), nil
}

// substituteJobID replaces the {jobId} placeholder in a redirect target with the
// actual job id (inbound-API contract — lets the portal recover the job on
// return without threading it through client state).
func substituteJobID(rawURL, jobID string) string {
	return strings.ReplaceAll(rawURL, "{jobId}", jobID)
}

// SubmitSignatures attaches client-side signatures (eid) and enqueues finalize.
func (o *Orchestrator) SubmitSignatures(ctx *azugo.Context, jobID string, sigs []SubmittedSignature) (*job.Job, error) {
	j, err := o.jobs.Load(ctx, jobID)
	if err != nil {
		return nil, err
	}
	if o.flows[j.Flow] == nil || !o.flows[j.Flow].Capabilities().ClientSide {
		return nil, ErrNotClientFlow
	}
	if j.State != job.StateAwaitingClientSig {
		return nil, ErrWrongState
	}

	want := make(map[string]bool, len(j.Documents))
	for i := range j.Documents {
		want[j.Documents[i].DocumentID] = true
	}
	for _, s := range sigs {
		d := j.Doc(s.DocumentID)
		if d == nil {
			return nil, fmt.Errorf("signing: unknown document %q", s.DocumentID)
		}
		d.SignatureValue = s.SignatureValue
		delete(want, s.DocumentID)
	}
	if len(want) != 0 {
		return nil, fmt.Errorf("signing: missing signatures for %d document(s)", len(want))
	}

	j.Transition(job.StateFinalizing)
	if err := o.jobs.Save(ctx, j); err != nil {
		return nil, err
	}
	if err := o.jobs.EnqueueWork(ctx, j.JobID); err != nil {
		o.log.Error("enqueue work failed", zap.String("job", j.JobID), zap.Error(err))
	}
	return j, nil
}

// RunJob is the background worker step. It signs (remote flows) and finalizes,
// driving SIGNING → FINALIZING → READY (or FAILED). It is idempotent: a job not
// in a workable state is a no-op.
func (o *Orchestrator) RunJob(ctx context.Context, jobID string) {
	j, err := o.jobs.Load(ctx, jobID)
	if err != nil {
		o.log.Warn("worker: job not found", zap.String("job", jobID), zap.Error(err))
		return
	}

	switch j.State {
	case job.StateSigning:
		flow := o.flows[j.Flow]
		if flow == nil {
			j.Fail("signing:unknown_flow", string(j.Flow))
			_ = o.jobs.Save(ctx, j)
			return
		}
		if err := flow.Sign(ctx, j); err != nil {
			o.log.Warn("worker: sign failed", zap.String("job", j.JobID), zap.Error(err))
			j.Fail("signing:sign_failed", err.Error())
			_ = o.jobs.Save(ctx, j)
			o.closeSessions(j)
			return
		}
		j.Transition(job.StateFinalizing)
		_ = o.jobs.Save(ctx, j)
		fallthrough
	case job.StateFinalizing:
		if err := o.finalize(ctx, j); err != nil {
			o.log.Warn("worker: finalize failed", zap.String("job", j.JobID), zap.Error(err))
			j.Fail("signapi:finalize_failed", err.Error())
			_ = o.jobs.Save(ctx, j)
			o.closeSessions(j)
			return
		}
		_ = o.jobs.Save(ctx, j)
	default:
		// Nothing to do (already terminal or awaiting input).
	}
}

// Status loads a job for the status endpoint.
func (o *Orchestrator) Status(ctx context.Context, jobID string) (*job.Job, error) {
	return o.jobs.Load(ctx, jobID)
}

// Download fetches a signed container from SignAPI and returns its bytes plus the
// media type and a suggested filename.
func (o *Orchestrator) Download(ctx context.Context, jobID, documentID string, asice bool) (data []byte, contentType, filename string, err error) {
	j, err := o.jobs.Load(ctx, jobID)
	if err != nil {
		return nil, "", "", err
	}
	d := j.Doc(documentID)
	if d == nil {
		return nil, "", "", job.ErrNotFound
	}
	if d.State != job.DocReady {
		return nil, "", "", ErrWrongState
	}

	files, err := o.signapi.List(ctx, jobID, d.SessionID)
	if err != nil {
		return nil, "", "", err
	}
	if len(files) == 0 {
		return nil, "", "", fmt.Errorf("signing: no signed file for document %q", documentID)
	}
	// The signed container is the (single-signature) session's result file.
	fileID := files[len(files)-1].ID
	data, err = o.signapi.Download(ctx, jobID, d.SessionID, fileID, asice)
	if err != nil {
		return nil, "", "", err
	}

	contentType, ext := containerType(d.Format, asice)
	filename = strings.TrimSuffix(d.FileName, fileExt(d.FileName)) + "-signed" + ext
	return data, contentType, filename, nil
}

// DeleteJob deletes the job and closes its SignAPI sessions (data minimization).
func (o *Orchestrator) DeleteJob(ctx context.Context, jobID string) error {
	j, err := o.jobs.Load(ctx, jobID)
	if err != nil {
		return err
	}
	if err := o.jobs.Delete(ctx, j); err != nil {
		return err
	}
	o.closeSessions(j)
	return nil
}

// --- shared spine ------------------------------------------------------------

// signapiDocDigestAlgo normalizes a digest-algorithm label to the form the SignAPI
// add-document-digest call accepts. SignAPI supports only SHA256 for the document-
// reference digest and matches the bare token "SHA256", whereas callers commonly
// label it "SHA-256". Strip separators and upper-case so the document digest is
// accepted; an empty label defaults to SHA256 (the only supported value here).
func signapiDocDigestAlgo(s string) string {
	s = strings.ToUpper(strings.NewReplacer("-", "", "_", "", " ", "").Replace(s))
	if s == "" {
		return "SHA256"
	}

	return s
}

func (o *Orchestrator) createSessionsAndUpload(ctx context.Context, j *job.Job, in []InputDocument) error {
	for i := range j.Documents {
		sid, err := o.signapi.StartSession(ctx, j.JobID)
		if err != nil {
			return fmt.Errorf("start session: %w", err)
		}
		j.Documents[i].SessionID = sid

		d := in[i]
		if len(d.Bytes) > 0 {
			if _, err := o.signapi.UploadFile(ctx, j.JobID, sid, d.FileName, d.MimeType, d.Bytes); err != nil {
				return fmt.Errorf("upload %q: %w", d.DocumentID, err)
			}
		} else {
			// signatureIndex stays 0: the result is fileless and go-asice re-derives the
			// real signature-file index when it merges the co-signature into the existing
			// container, so the fileless's internal name is immaterial.
			if err := o.signapi.AddDocumentDigest(ctx, j.JobID, sid, hashFilesFor(d), 0); err != nil {
				return fmt.Errorf("add digest %q: %w", d.DocumentID, err)
			}
		}
	}
	return nil
}

// hashFilesFor builds the addDocumentDigest file list for a hash-only document. A
// document co-signing a container carries its inner data objects in Files (all
// registered under one signature, so the co-signature targets the same objects the
// container already holds); a normal document registers its single digest.
func hashFilesFor(d InputDocument) []signapi.HashFile {
	if len(d.Files) > 0 {
		files := make([]signapi.HashFile, 0, len(d.Files))
		for _, f := range d.Files {
			files = append(files, signapi.HashFile{
				Name:            f.Name,
				Digest:          f.Digest,
				DigestAlgorithm: signapiDocDigestAlgo(f.DigestAlgorithm),
			})
		}
		return files
	}

	return []signapi.HashFile{{Name: d.FileName, Digest: d.Hash, DigestAlgorithm: signapiDocDigestAlgo(d.DigestAlgorithm)}}
}

// calculateDigests runs CalculateDigest for all of the job's sessions with the
// given signing certificate and stores the opaque results (SCAL2).
func (o *Orchestrator) calculateDigests(ctx context.Context, j *job.Job, signingCertB64 string) error {
	if len(j.Documents) == 0 {
		return errors.New("signing: no documents")
	}
	sessions := make([]signapi.SessionRef, 0, len(j.Documents))
	for i := range j.Documents {
		sessions = append(sessions, signapi.SessionRef{SessionID: j.Documents[i].SessionID})
	}
	first := j.Documents[0]
	req := signapi.CalculateDigestRequest{
		Sessions:    sessions,
		Certificate: signingCertB64,
		SignAsPdf:   first.Format == job.FormatPAdES,
		// signAsPdf and createNewEdoc are mutually exclusive at the SignAPI: a PAdES
		// signature signs the PDF natively (there is no container), so a new ASiC-E
		// is created only for a non-PAdES "create". A parallel op co-signs an existing
		// container and creates nothing.
		CreateNewEdoc: first.Format != job.FormatPAdES && first.Operation == job.OpCreate,
	}
	results, err := o.signapi.CalculateDigest(ctx, j.JobID, req)
	if err != nil {
		return err
	}
	bySession := make(map[string]signapi.DigestResult, len(results))
	for _, r := range results {
		bySession[r.SessionID] = r
	}
	for i := range j.Documents {
		r, ok := bySession[j.Documents[i].SessionID]
		if !ok {
			return fmt.Errorf("signing: no digest for session %q", j.Documents[i].SessionID)
		}
		j.Documents[i].Digest = r.Digest
		if j.Documents[i].DigestAlgorithm == "" {
			j.Documents[i].DigestAlgorithm = r.Algorithm
		}
		if j.SignAlgo == "" {
			j.SignAlgo = r.SignatureAlgorithm
		}
		if j.DigestsSummary == "" {
			j.DigestsSummary = r.DigestsSummary
			j.DigestsSummaryAlgo = r.Algorithm
		}
	}
	return nil
}

// finalize normalizes every signature to DER and applies it, then marks the
// documents READY and the job complete.
func (o *Orchestrator) finalize(ctx context.Context, j *job.Job) error {
	// Resolved first: without a certificate to request the timestamp with there
	// is nothing to finalize, and refusing here costs no upstream traffic.
	authCert, certSource, ok := o.authCertFor(j)
	if !ok {
		o.recordTimestampRefused(j, OpSign)

		return ErrNoTimestampCert
	}
	o.recordTimestampRequest(j, certSource, OpSign, authCert)

	ssv := make([]signapi.SessionSignatureValue, 0, len(j.Documents))
	for i := range j.Documents {
		d := &j.Documents[i]
		input := d.SignatureValue
		der, wasP1363, err := NormalizeSignatureToDER(input)
		if err != nil {
			return fmt.Errorf("document %q: %w", d.DocumentID, err)
		}
		inputEnc := "der"
		if wasP1363 {
			inputEnc = "p1363"
		}
		// Encoding visibility: log the input encoding and the input/output signatures
		// so the P1363→DER conversion at the finalize boundary is explicit (debug only;
		// a signature value is public, not a secret).
		o.log.Debug("ecdsa signature normalized to DER",
			zap.String("job", j.JobID),
			zap.String("document", d.DocumentID),
			zap.String("flow", string(j.Flow)),
			zap.String("input_encoding", inputEnc),
			zap.String("input_signature_b64", input),
			zap.String("der_signature_b64", der))
		if wasP1363 && j.Flow != job.FlowWebEID {
			// Encoding telemetry: a TrustedX/CSC response unexpectedly arrived as P1363.
			o.log.Info("normalized P1363 signature from a non-eid flow",
				zap.String("job", j.JobID), zap.String("flow", string(j.Flow)), zap.String("document", d.DocumentID))
		}
		ssv = append(ssv, signapi.SessionSignatureValue{SessionID: d.SessionID, SignatureValue: der})
	}

	if err := o.signapi.FinalizeSigning(ctx, j.JobID, signapi.FinalizeRequest{
		SessionSignatureValues: ssv,
		AuthCertificate:        authCert,
	}); err != nil {
		return err
	}

	for i := range j.Documents {
		j.Documents[i].State = job.DocReady
		j.Documents[i].SignatureValue = "" // transient — clear after finalize
	}
	j.Transition(job.StateReady)
	return nil
}

// closeSessions closes every SignAPI session of the job, after its caller has
// moved on (closeLater).
func (o *Orchestrator) closeSessions(j *job.Job) {
	sids := make([]string, 0, len(j.Documents))
	for i := range j.Documents {
		sids = append(sids, j.Documents[i].SessionID)
	}
	o.closeLater(j.JobID, sids...)
}

// sessionCloseLimit bounds the closes of one closeLater call, all their tries included.
const sessionCloseLimit = 2 * time.Minute

// closeLater closes SignAPI sessions in the background, so a close never holds back
// the answer, the saved state or the next job before it. The provider sometimes
// holds a request without answering; a close is best effort, and a session left
// open expires on the provider's side after a day. The closes run on their own
// context: the caller's request context is recycled the moment it answers.
func (o *Orchestrator) closeLater(correlationID string, sessionIDs ...string) {
	var sids []string
	for _, sid := range sessionIDs {
		if sid != "" {
			sids = append(sids, sid)
		}
	}
	if len(sids) == 0 {
		return
	}
	o.closing.Add(1)
	go func() {
		defer o.closing.Done()
		ctx, cancel := context.WithTimeout(context.Background(), sessionCloseLimit)
		defer cancel()
		for _, sid := range sids {
			o.closeSession(ctx, correlationID, sid)
		}
	}()
}

// WaitClosing waits for the background session closes to finish.
func (o *Orchestrator) WaitClosing() {
	o.closing.Wait()
}

// --- helpers -----------------------------------------------------------------

// newState mints a 256-bit opaque OAuth state value.
func (o *Orchestrator) newState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// validateBatch enforces single-format batches and the per-flow batch limit.
func validateBatch(in PrepareInput, caps Capabilities) error {
	if len(in.Documents) == 0 {
		return errors.New("signing: no documents")
	}
	if len(in.Documents) > 1 && (!caps.SupportsBatch || caps.SingleSessionOnly) {
		return ErrBatchUnsupport
	}
	format := in.Documents[0].Format
	for _, d := range in.Documents[1:] {
		if d.Format != format {
			return ErrMixedFormat
		}
	}
	return nil
}

// certSubject extracts the eID national identifier (the subject serialNumber,
// e.g. "PNOLV-XXXXXX-XXXXX") from a base64-DER certificate, or "" — used for
// GDPR-audit pseudonymization on the request path.
func certSubject(b64 string) string {
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		return ""
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return ""
	}
	return cert.Subject.SerialNumber
}

func containerType(format job.SignatureFormat, asice bool) (contentType, ext string) {
	if format == job.FormatPAdES {
		return "application/pdf", ".pdf"
	}
	if asice {
		return "application/vnd.etsi.asic-e+zip", ".asice"
	}
	return "application/vnd.etsi.asic-e+zip", ".edoc"
}

func fileExt(name string) string {
	if i := strings.LastIndexByte(name, '.'); i >= 0 {
		return name[i:]
	}
	return ""
}

func orDefault(v, def string) string {
	if strings.TrimSpace(v) == "" {
		return def
	}
	return v
}

// signAlgoName maps the SignAPI signature_algorithm to the caller-facing
// algorithm family hint for eid (e.g. "ecdsa" | "rsa"); best effort.
func signAlgoName(sigAlgo string) string {
	s := strings.ToLower(sigAlgo)
	switch {
	case strings.Contains(s, "ecdsa"), strings.Contains(s, "ecc"):
		return "ecdsa"
	case strings.Contains(s, "rsa"):
		return "rsa"
	default:
		return sigAlgo
	}
}
