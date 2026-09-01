package routes

import (
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	docgate "github.com/gmb-lib/go-docgate"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/eparaksts-signer/job"
	"github.com/signbyte/eparaksts-signer/routes/request"
	"github.com/signbyte/eparaksts-signer/routes/response"
	"github.com/signbyte/eparaksts-signer/signing"
)

// authorizeExpiresIn is the advertised lifetime of the returned authorize URL.
const authorizeExpiresIn = 90

// statusLongPollMax caps the long-poll window.
const statusLongPollMax = 30

// prepare — POST /api/v1/signatures/prepare?flow={flow}
func (r *router) prepare(ctx *azugo.Context) {
	flowStr := "csc"
	if f := ctx.Query.StringOptional("flow"); f != nil && *f != "" {
		flowStr = *f
	}
	flow := job.Flow(flowStr)
	if !flow.Valid() {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("unknown flow: "+flowStr)))
		return
	}

	meta, files, err := parsePrepare(ctx)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
		return
	}

	// Gate every uploaded file part (signing mode: any format is admitted, but a
	// checked extension must be honest — a .pdf must carry PDF magic, an ASiC-E
	// name must be a well-formed container; per-file size cap — the whole request
	// is bounded by the server body limit). Hash-only preparations carry no bytes
	// to gate.
	for _, d := range meta.Documents {
		data, ok := files[d.FileRef]
		if !ok {
			continue
		}
		if !r.gateUpload(ctx, docgate.ModeSigning, d.FileName, data) {
			return
		}
	}

	in := signing.PrepareInput{
		Flow:               flow,
		Caller:             callerID(ctx),
		Locale:             meta.Locale,
		SignatureQualifier: meta.SignatureQualifier,
		SigningCert:        meta.SigningCertificate,
		AuthCert:           meta.AuthCertificate,
		SignIdentityID:     meta.SignIdentityID,
		SealID:             meta.SealID,
		PostAuthRedirect:   meta.PostAuthRedirect,
		AuthErrorRedirect:  meta.AuthErrorRedirect,
	}
	for _, d := range meta.Documents {
		doc := signing.InputDocument{
			DocumentID:      d.DocumentID,
			FileName:        d.FileName,
			MimeType:        d.MimeType,
			Format:          job.SignatureFormat(d.SignatureFormat),
			Operation:       operationOf(d.Operation),
			DigestAlgorithm: d.DigestAlgorithm,
		}
		switch {
		case len(d.Files) > 0:
			// The document is an ASiC-E container being co-signed: its inner data
			// objects are registered together under one signature (hash-only).
			for _, f := range d.Files {
				doc.Files = append(doc.Files, signing.InputFile{
					Name:            f.Name,
					Digest:          f.Digest,
					DigestAlgorithm: f.DigestAlgorithm,
				})
			}
		case d.DocumentHash != "":
			doc.Hash = d.DocumentHash
		default:
			b, ok := files[d.FileRef]
			if !ok {
				ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
					pkerrors.WithStatus(fasthttp.StatusBadRequest),
					pkerrors.WithDetail("missing file part for document "+d.DocumentID)))
				return
			}
			doc.Bytes = b
		}
		in.Documents = append(in.Documents, doc)
	}
	if flow == job.FlowWebEID && in.SigningCert == "" {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("signingCertificate is required for the webEid flow")))
		return
	}

	res, err := r.Orchestrator().Prepare(ctx, in)
	if err != nil {
		ctx.Log().Warn("prepare failed", zap.String("flow", string(flow)), zap.Error(err))
		r.Audit().PrepareOutcome(ctx, callerID(ctx), false)
		r.mapPrepareErr(ctx, err)
		return
	}

	j := res.Job
	r.Audit().Initiated(ctx, j)
	if res.AuthorizeURL != "" {
		r.Audit().Redirect(ctx, j)
	}
	if flow == job.FlowWebEID && j.SubjectRef != "" {
		r.Audit().SignerAccessed(ctx, callerID(ctx), j.SubjectRef)
	}
	r.Audit().PrepareOutcome(ctx, callerID(ctx), true)

	out := response.Prepare{JobID: j.JobID, Flow: string(j.Flow), State: string(j.State)}
	if res.AuthorizeURL != "" {
		out.Authorization = &response.Authorization{Type: "redirect", AuthorizeURL: res.AuthorizeURL, ExpiresIn: authorizeExpiresIn}
		for i := range j.Documents {
			out.Documents = append(out.Documents, response.PrepareDocumentRef{DocumentID: j.Documents[i].DocumentID})
		}
	} else {
		out.SignAlgorithm = res.SignAlgo
		for _, d := range res.Digests {
			out.Documents = append(out.Documents, response.PrepareDocumentRef{
				DocumentID: d.DocumentID, Digest: d.Digest, DigestAlgorithm: d.DigestAlgorithm,
			})
		}
	}
	ctx.StatusCode(fasthttp.StatusCreated)
	ctx.JSON(&out)
}

// callback — GET /api/v1/signatures/callback (browser; state + PKCE)
func (r *router) callback(ctx *azugo.Context) {
	state := ctx.Query.StringOptional("state")
	if state == nil || *state == "" {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail("missing state")))
		return
	}
	declined := false
	if e := ctx.Query.StringOptional("error"); e != nil && *e != "" {
		declined = true
	}
	code := ""
	if c := ctx.Query.StringOptional("code"); c != nil {
		code = *c
	}

	j, redirect, err := r.Orchestrator().Callback(ctx, *state, code, declined)
	if err != nil {
		if errors.Is(err, job.ErrNotFound) {
			// Unknown/expired/tampered state — do not redirect.
			ctx.Error(pkerrors.NewProblem("err:signing:invalidState",
				pkerrors.WithStatus(fasthttp.StatusBadRequest),
				pkerrors.WithDetail("unknown or expired state")))
			return
		}
		ctx.Log().Error("callback processing failed", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:signing:internal",
			pkerrors.WithDetail("callback processing failed")))
		return
	}

	r.Audit().Callback(ctx, j, j.State != job.StateFailed)
	if j.State == job.StateSigning && j.SubjectRef != "" {
		r.Audit().SignerAccessed(ctx, j.Caller, j.SubjectRef)
	}

	if redirect == "" {
		// No redirect target configured — return a terminal status instead.
		ctx.StatusCode(fasthttp.StatusOK)
		ctx.Text("authorization " + string(j.State))
		return
	}
	// Configured callback target may be cross-origin — bypass same-origin sanitizing.
	ctx.RedirectUnsafe(redirect)
}

// submit — POST /api/v1/signatures/{jobId}/signatures (eid)
func (r *router) submit(ctx *azugo.Context) {
	jobID := ctx.Params.String("jobId")

	var req request.SubmitSignatures
	if err := ctx.Body.JSON(&req); err != nil { // auto-validates
		ctx.Error(err)
		return
	}

	sigs := make([]signing.SubmittedSignature, len(req.Signatures))
	for i, s := range req.Signatures {
		sigs[i] = signing.SubmittedSignature{DocumentID: s.DocumentID, SignatureValue: s.SignatureValue}
	}

	j, err := r.Orchestrator().SubmitSignatures(ctx, jobID, sigs)
	if err != nil {
		r.mapJobErr(ctx, err)
		return
	}
	ctx.StatusCode(fasthttp.StatusAccepted)
	ctx.JSON(&response.Accepted{JobID: j.JobID, Flow: string(j.Flow), State: string(j.State)})
}

// status — GET /api/v1/signatures/{jobId}/status?wait={seconds}
func (r *router) status(ctx *azugo.Context) {
	jobID := ctx.Params.String("jobId")

	wait := 0
	if w, err := ctx.Query.IntOptional("wait"); err == nil && w != nil {
		wait = *w
	}
	if wait > statusLongPollMax {
		wait = statusLongPollMax
	}

	j, err := r.Orchestrator().Status(ctx, jobID)
	if err != nil {
		r.mapJobErr(ctx, err)
		return
	}

	if wait > 0 && !j.State.Terminal() {
		initial := j.State
		deadline := time.Now().Add(time.Duration(wait) * time.Second)
		for time.Now().Before(deadline) {
			if ctx.Err() != nil {
				break
			}
			time.Sleep(time.Second)
			j2, err := r.Orchestrator().Status(ctx, jobID)
			if err != nil {
				break
			}
			j = j2
			if j.State != initial || j.State.Terminal() {
				break
			}
		}
	}

	// One-shot terminal eIDAS-audit / C audit (request path; the worker has no ctx).
	if j.State.Terminal() && !j.AuditFinalEmitted {
		if j.State == job.StateReady {
			r.Audit().Applied(ctx, j)
		} else {
			r.Audit().Failed(ctx, j)
		}
		j.AuditFinalEmitted = true
		_ = r.Orchestrator().Store().Save(ctx, j)
	}

	ctx.JSON(buildStatus(j))
}

// download — GET /api/v1/signatures/{jobId}/documents/{documentId}?container=edoc|asice
func (r *router) download(ctx *azugo.Context) {
	jobID := ctx.Params.String("jobId")
	docID := ctx.Params.String("documentId")
	asice := false
	if c := ctx.Query.StringOptional("container"); c != nil && *c == "asice" {
		asice = true
	}

	data, contentType, filename, err := r.Orchestrator().Download(ctx, jobID, docID, asice)
	if err != nil {
		switch {
		case errors.Is(err, job.ErrNotFound):
			ctx.Error(pkerrors.NewProblem("err:signing:notFound",
				pkerrors.WithDetail("unknown job or document")))
		case errors.Is(err, signing.ErrWrongState):
			ctx.Error(pkerrors.NewProblem("err:signing:notReady",
				pkerrors.WithStatus(fasthttp.StatusConflict),
				pkerrors.WithDetail("document is not ready")))
		default:
			ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
				pkerrors.WithStatus(fasthttp.StatusBadGateway),
				pkerrors.WithDetail("could not fetch signed container")))
		}
		return
	}
	ctx.ContentType(contentType)
	ctx.Header.Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	ctx.Raw(data)
}

// deleteJob — DELETE /api/v1/signatures/{jobId}
func (r *router) deleteJob(ctx *azugo.Context) {
	jobID := ctx.Params.String("jobId")
	if err := r.Orchestrator().DeleteJob(ctx, jobID); err != nil {
		if errors.Is(err, job.ErrNotFound) {
			ctx.Error(pkerrors.NewProblem("err:signing:notFound",
				pkerrors.WithDetail("unknown job")))
			return
		}
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway),
			pkerrors.WithDetail("could not delete job")))
		return
	}
	ctx.StatusCode(fasthttp.StatusNoContent)
}

// --- helpers -----------------------------------------------------------------

// parsePrepare reads the prepare metadata + file parts (multipart) or the
// hash-only JSON body.
func parsePrepare(ctx *azugo.Context) (request.PrepareMetadata, map[string][]byte, error) {
	var meta request.PrepareMetadata
	files := map[string][]byte{}

	if strings.HasPrefix(ctx.Header.Get("Content-Type"), "multipart/") {
		metaStr, err := ctx.Form.String("metadata")
		if err != nil {
			return meta, nil, err
		}
		if err := json.Unmarshal([]byte(metaStr), &meta); err != nil {
			return meta, nil, err
		}
		if err := meta.Validate(ctx); err != nil {
			return meta, nil, err
		}
		for _, d := range meta.Documents {
			if d.FileRef == "" {
				continue
			}
			fh := ctx.Form.FileOptional(d.FileRef)
			if fh == nil {
				continue
			}
			f, err := fh.Open()
			if err != nil {
				return meta, nil, err
			}
			b, err := io.ReadAll(f)
			_ = f.Close()
			if err != nil {
				return meta, nil, err
			}
			files[d.FileRef] = b
		}
		return meta, files, nil
	}

	if err := ctx.Body.JSON(&meta); err != nil { // auto-validates
		return meta, nil, err
	}
	return meta, files, nil
}

func buildStatus(j *job.Job) *response.Status {
	out := &response.Status{
		JobID:     j.JobID,
		Flow:      string(j.Flow),
		State:     string(j.State),
		UpdatedAt: j.UpdatedAt.UTC().Format(time.RFC3339),
	}
	if j.State == job.StateSigning && j.Flow == job.FlowEIDScan {
		out.VerificationCode = j.VerificationCode
		out.VerificationMessage = j.VerificationMessage
		out.SigningDeadline = j.SigningDeadline
	}
	for i := range j.Documents {
		d := &j.Documents[i]
		sd := response.StatusDocument{DocumentID: d.DocumentID, State: string(d.State)}
		if d.State == job.DocReady {
			sd.DownloadURL = "/api/v1/signatures/" + j.JobID + "/documents/" + d.DocumentID
		}
		if d.Error != nil {
			sd.Error = &response.Error{Code: d.Error.Code, Message: d.Error.Message}
		}
		out.Documents = append(out.Documents, sd)
	}
	return out
}

func operationOf(op string) job.Operation {
	if op == string(job.OpParallel) {
		return job.OpParallel
	}
	return job.OpCreate
}

func (r *router) mapPrepareErr(ctx *azugo.Context, err error) {
	switch {
	case errors.Is(err, signing.ErrCSCNotEnabled):
		ctx.Error(pkerrors.NewProblem("err:signing:cscNotEnabled",
			pkerrors.WithStatus(fasthttp.StatusNotImplemented),
			pkerrors.WithDetail(err.Error())))
	case errors.Is(err, signing.ErrUnknownFlow):
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
	case errors.Is(err, signing.ErrMixedFormat):
		ctx.Error(pkerrors.NewProblem("err:signing:mixedFormat",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
	case errors.Is(err, signing.ErrBatchUnsupport):
		ctx.Error(pkerrors.NewProblem("err:signing:batchNotSupported",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
	case errors.Is(err, signing.ErrBadSignatureEncoding):
		ctx.Error(pkerrors.NewProblem("err:signing:badSignatureEncoding",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
	default:
		// A failed upstream call (SignAPI / TrustedX introspect): log the cause off
		// the wire and return a uniform gateway error.
		ctx.Log().Error("prepare upstream error", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))
	}
}

func (r *router) mapJobErr(ctx *azugo.Context, err error) {
	switch {
	case errors.Is(err, job.ErrNotFound):
		ctx.Error(pkerrors.NewProblem("err:signing:notFound",
			pkerrors.WithDetail("unknown job")))
	case errors.Is(err, signing.ErrNotClientFlow):
		ctx.Error(pkerrors.NewProblem("err:signing:conflict",
			pkerrors.WithDetail("this flow does not accept client signatures")))
	case errors.Is(err, signing.ErrWrongState):
		ctx.Error(pkerrors.NewProblem("err:signing:conflict",
			pkerrors.WithDetail("job is not in the required state")))
	default:
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
	}
}
