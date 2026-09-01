package routes

import (
	"errors"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	docgate "github.com/gmb-lib/go-docgate"
	"github.com/gmb-lib/go-platform-kit/correlation"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"

	"github.com/signbyte/eparaksts-signer/job"
	"github.com/signbyte/eparaksts-signer/signing"
)

// archive — POST /api/v1/archive-timestamps (multipart: file [+ authCertificate])
//
// Adds an ARCHIVE_TIMESTAMP to an uploaded already-signed document (B-LT → B-LTA)
// and returns the archived container bytes. The `authCertificate` form field
// (the signed-in user's cert) is required — the timestamp request is made in
// the acting user's name, never a configured stand-in identity's.
func (r *router) archive(ctx *azugo.Context) {
	fileName, mimeType, data, err := readSingleUpload(ctx)
	if err != nil {
		ctx.Error(pkerrors.NewProblem("err:signing:invalidRequest",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
		return
	}
	if !r.gateUpload(ctx, docgate.ModeVerify, fileName, data) {
		return
	}
	authCert := ""
	if v := ctx.Form.StringOptional("authCertificate"); v != nil {
		authCert = *v
	}

	cid := correlation.FromContext(ctx).CorrelationID
	archived, contentType, outName, err := r.Orchestrator().ArchiveUpload(ctx, cid, fileName, mimeType, authCert, data)
	if err != nil {
		ctx.Log().Warn("archive failed", zap.Error(err))
		r.Audit().ArchiveOutcome(ctx, callerID(ctx), false)
		r.mapArchiveErr(ctx, err)
		return
	}

	r.Audit().ArchiveOutcome(ctx, callerID(ctx), true)
	r.writeContainer(ctx, contentType, outName, archived)
}

// archiveJobDoc — POST /api/v1/signatures/{jobId}/documents/{documentId}/archive
//
// Adds an ARCHIVE_TIMESTAMP to a single READY document of an existing job (no
// re-upload) and returns the archived container bytes. The auth certificate is
// the one captured on the job at signing time.
func (r *router) archiveJobDoc(ctx *azugo.Context) {
	jobID := ctx.Params.String("jobId")
	docID := ctx.Params.String("documentId")
	asice := false
	if c := ctx.Query.StringOptional("container"); c != nil && *c == "asice" {
		asice = true
	}

	archived, contentType, outName, err := r.Orchestrator().ArchiveJobDocument(ctx, jobID, docID, asice)
	if err != nil {
		ctx.Log().Warn("archive job document failed", zap.String("job", jobID), zap.Error(err))
		r.Audit().ArchiveOutcome(ctx, callerID(ctx), false)
		r.mapArchiveErr(ctx, err)
		return
	}

	r.Audit().ArchiveOutcome(ctx, callerID(ctx), true)
	// GDPR-audit: archiving accesses the signer's auth cert/identity on the job.
	if j, e := r.Orchestrator().Status(ctx, jobID); e == nil && j.SubjectRef != "" {
		r.Audit().SignerAccessed(ctx, j.Caller, j.SubjectRef)
	}
	r.writeContainer(ctx, contentType, outName, archived)
}

// writeContainer streams a container/PDF as a downloadable attachment.
func (r *router) writeContainer(ctx *azugo.Context, contentType, filename string, data []byte) {
	ctx.ContentType(contentType)
	ctx.Header.Set("Content-Disposition", `attachment; filename="`+filename+`"`)
	ctx.Raw(data)
}

// mapArchiveErr maps archive errors onto the right problem envelope.
func (r *router) mapArchiveErr(ctx *azugo.Context, err error) {
	switch {
	case errors.Is(err, signing.ErrNoAuthCert):
		ctx.Error(pkerrors.NewProblem("err:signing:missingAuthCertificate",
			pkerrors.WithStatus(fasthttp.StatusBadRequest),
			pkerrors.WithDetail(err.Error())))
	case errors.Is(err, job.ErrNotFound):
		ctx.Error(pkerrors.NewProblem("err:signing:notFound",
			pkerrors.WithDetail("unknown job or document")))
	case errors.Is(err, signing.ErrWrongState):
		ctx.Error(pkerrors.NewProblem("err:signing:notReady",
			pkerrors.WithStatus(fasthttp.StatusConflict),
			pkerrors.WithDetail("document is not ready")))
	case errors.Is(err, signing.ErrDocumentRejected):
		// The signing provider gave a definitive rejection of the supplied document
		// (a 4xx — not a valid signed document to archive). Client-actionable, so a
		// 422 with a public-safe reason, NOT a 502: reserve that for a genuinely
		// unreachable upstream. The full provider cause is already logged at Warn on
		// the handler ("archive failed") + correlated by trace id.
		ctx.Error(pkerrors.NewProblem("err:signing:invalidDocument",
			pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
			pkerrors.WithPublicDetail("This document can't be archived — it isn't a valid signed document.")))
	default:
		// A failed upstream call (transport/5xx): log the cause off the wire and
		// return a uniform gateway error.
		ctx.Log().Error("archive upstream error", zap.Error(err))
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))
	}
}
