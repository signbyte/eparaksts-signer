package routes

import (
	"errors"
	"io"
	"strings"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"
	"go.uber.org/zap"

	docgate "github.com/gmb-lib/go-docgate"
	"github.com/gmb-lib/go-platform-kit/correlation"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
)

// validate — POST /api/v1/validations (multipart: file)
//
// Uploads an already-signed document to a transient SignAPI session and relays the
// SignAPI validation report VERBATIM (the report is opaque to this service). Works
// for self-contained documents, ASiC-E with embedded signed files (not fileless),
// and signed PDFs.
func (r *router) validate(ctx *azugo.Context) {
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

	cid := correlation.FromContext(ctx).CorrelationID
	sid, status, body, err := r.Orchestrator().Validate(ctx, cid, fileName, mimeType, data)
	if sid != "" {
		// The transient provider session the validation ran in — evidence for the
		// caller linking its request to the provider-side processing.
		ctx.Header.Set("X-Validation-Session", sid)
	}
	if err != nil {
		ctx.Log().Warn("validate failed", zap.Error(err))
		r.Audit().ValidateOutcome(ctx, callerID(ctx), false)
		ctx.Error(pkerrors.NewProblem("err:upstream:unavailable",
			pkerrors.WithStatus(fasthttp.StatusBadGateway)))
		return
	}

	r.Audit().ValidateOutcome(ctx, callerID(ctx), status/100 == 2)

	// Pass the SignAPI report (or its error JSON) through unchanged.
	ctx.StatusCode(status)
	ctx.ContentType("application/json")
	ctx.Raw(body)
}

// readSingleUpload reads the single `file` part from a multipart request, returning
// its name, the part's declared content type, and its bytes.
func readSingleUpload(ctx *azugo.Context) (fileName, mimeType string, data []byte, err error) {
	if !strings.HasPrefix(ctx.Header.Get("Content-Type"), "multipart/") {
		return "", "", nil, errors.New("multipart/form-data with a 'file' part is required")
	}
	fh := ctx.Form.FileOptional("file")
	if fh == nil {
		return "", "", nil, errors.New("missing 'file' part")
	}
	f, err := fh.Open()
	if err != nil {
		return "", "", nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(f)
	if err != nil {
		return "", "", nil, err
	}
	return fh.Filename, fh.Header.Get("Content-Type"), b, nil
}
