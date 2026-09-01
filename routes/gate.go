package routes

import (
	"errors"

	"azugo.io/azugo"
	"github.com/valyala/fasthttp"

	docgate "github.com/gmb-lib/go-docgate"
	pkerrors "github.com/gmb-lib/go-platform-kit/errors"
)

// gateUpload runs the document gate on one uploaded file when upload
// hardening is enabled, writing the typed rejection itself. It returns false
// when the request has been answered and the handler must stop.
//
// Verify mode guards the validate/archive uploads (only a signed PDF or a
// signed, well-formed ASiC-E may be forwarded upstream); signing mode guards
// the prepare file parts (any format is admitted, but a checked extension must
// be honest — a .pdf must carry PDF magic and an ASiC-E name must be a
// well-formed container; a PDF that carries the magic yet does not fully parse
// is still admitted, since the signing service is the authority on
// signability). Rejections carry the underlying detector cause in the detail,
// so a parser failure is observable instead of reading as a clean verdict.
func (r *router) gateUpload(ctx *azugo.Context, mode docgate.Mode, filename string, data []byte) bool {
	if !r.Config().UploadHardening {
		return true
	}
	if _, err := docgate.Check(mode, filename, data,
		docgate.WithMaxBytes(r.Config().MaxUploadBytes)); err != nil {
		switch {
		case errors.Is(err, docgate.ErrTooLarge):
			ctx.Error(pkerrors.NewProblem("err:signing:fileTooLarge",
				pkerrors.WithStatus(fasthttp.StatusRequestEntityTooLarge),
				pkerrors.WithTitle("File too large"),
				pkerrors.WithDetail(err.Error())))
		default:
			ctx.Error(pkerrors.NewProblem("err:signing:uploadRejected",
				pkerrors.WithStatus(fasthttp.StatusUnprocessableEntity),
				pkerrors.WithTitle("Upload rejected"),
				pkerrors.WithDetail(err.Error())))
		}

		return false
	}

	return true
}
