package signing

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/job"
)

// This file holds the stateless preservation/inspection operations that ride the
// shared SignAPI spine but own no Job: validate (DSS validation report) and archive
// timestamp (B-LT → B-LTA), via the SignAPI `validate` and `addArchive` operations.

// Validate uploads an already-signed document to a TRANSIENT SignAPI session and
// returns the SignAPI validation report verbatim (upstream status + body), then
// closes the session (data minimization). It works for self-contained documents,
// ASiC-E containers that embed their signed files (not hash-only/"fileless"), and
// signed PDFs — anything whose signed content is present in the uploaded bytes.
// The transient session id is returned alongside the report so the caller can
// keep it as evidence linking its request to the provider-side processing.
func (o *Orchestrator) Validate(ctx context.Context, correlationID, fileName, mimeType string, data []byte) (sessionID string, status int, body []byte, err error) {
	sid, err := o.signapi.StartSession(ctx, correlationID)
	if err != nil {
		return "", 0, nil, fmt.Errorf("start session: %w", err)
	}
	defer o.closeSession(ctx, correlationID, sid)

	up, err := o.signapi.UploadFile(ctx, correlationID, sid, fileName, mimeType, data)
	if err != nil {
		return sid, 0, nil, fmt.Errorf("upload: %w", err)
	}
	// Validate the uploaded document itself (data.id — the ASiC-E CONTAINER, or the
	// PDF), NOT an inner document: validating an inner file yields SignAPI's
	// "Document format not recognized/handled".
	if up.DocumentID == "" {
		return sid, 0, nil, errors.New("validate: upload returned no document id")
	}
	status, body, err = o.signapi.Validate(ctx, correlationID, sid, up.DocumentID)

	return sid, status, body, err
}

// ArchiveUpload uploads an already-signed document to a transient session, adds an
// ARCHIVE_TIMESTAMP (B-LT → B-LTA), downloads the archived container, and closes
// the session. authCert is the signed-in user's authentication certificate,
// supplied by the caller — a timestamp request is made in the acting user's
// name, never a configured stand-in identity's, so there is no config
// fallback; ErrNoAuthCert when absent.
func (o *Orchestrator) ArchiveUpload(ctx context.Context, correlationID, fileName, mimeType, reqAuthCert string, data []byte) (archived []byte, contentType, outName string, err error) {
	authCert := reqAuthCert
	if strings.TrimSpace(authCert) == "" {
		return nil, "", "", ErrNoAuthCert
	}

	sid, err := o.signapi.StartSession(ctx, correlationID)
	if err != nil {
		return nil, "", "", fmt.Errorf("start session: %w", err)
	}
	defer o.closeSession(ctx, correlationID, sid)

	up, err := o.signapi.UploadFile(ctx, correlationID, sid, fileName, mimeType, data)
	if err != nil {
		return nil, "", "", fmt.Errorf("upload: %w", classifyUpstream(err))
	}
	if up.DocumentID == "" {
		return nil, "", "", fmt.Errorf("archive: upload returned no document id")
	}
	if err := o.signapi.AddArchiveTimestamp(ctx, correlationID, sid, authCert); err != nil {
		return nil, "", "", classifyUpstream(err)
	}

	// Download the archived form of the uploaded document itself — its own data.id,
	// now carrying the ARCHIVE_TIMESTAMP — exactly as Validate reads data.id and as
	// the provider's own test flow re-validates the archived result by the upload id.
	// (A prior "last file in the session list" heuristic was fragile: the archived
	// artifact is not guaranteed to be the last-listed file, so it could return the
	// wrong, e.g. a small metadata, file.)
	archived, err = o.signapi.Download(ctx, correlationID, sid, up.DocumentID, false)
	if err != nil {
		return nil, "", "", err
	}
	contentType, ext := archiveContainerType(isPDF(fileName, mimeType))
	outName = strings.TrimSuffix(fileName, fileExt(fileName)) + "-archived" + ext
	return archived, contentType, outName, nil
}

// ArchiveJobDocument adds an ARCHIVE_TIMESTAMP to a single READY document of an
// existing job (B-LT → B-LTA, no re-upload) and returns the archived container
// bytes. The auth certificate is the one captured on the job at signing time
// (the signed-in user's auth cert; for csc, the flow's configured one) — no
// config fallback here: the timestamp request is made in the signer's name.
// ErrNoAuthCert when the job carries none. The job's SignAPI session is left
// open (the job owns its lifecycle); the archived bytes are then also
// re-fetchable via /documents/{id}.
func (o *Orchestrator) ArchiveJobDocument(ctx context.Context, jobID, documentID string, asice bool) (archived []byte, contentType, outName string, err error) {
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
	authCert := j.AuthCert
	if strings.TrimSpace(authCert) == "" {
		return nil, "", "", ErrNoAuthCert
	}
	if err := o.signapi.AddArchiveTimestamp(ctx, jobID, d.SessionID, authCert); err != nil {
		return nil, "", "", classifyUpstream(err)
	}
	// Reuse the download tail for the bytes + media type; recompute the filename so
	// the delivered artifact reads as "-archived" rather than "-signed".
	data, ct, _, err := o.Download(ctx, jobID, documentID, asice)
	if err != nil {
		return nil, "", "", err
	}
	_, ext := containerType(d.Format, asice)
	outName = strings.TrimSuffix(d.FileName, fileExt(d.FileName)) + "-archived" + ext
	return data, ct, outName, nil
}

// closeSession closes a single SignAPI session (best effort).
func (o *Orchestrator) closeSession(ctx context.Context, correlationID, sessionID string) {
	if sessionID == "" {
		return
	}
	if err := o.signapi.CloseSession(ctx, correlationID, sessionID); err != nil {
		o.log.Warn("close session failed", zap.String("session", sessionID), zap.Error(err))
	}
}

// isPDF reports whether the upload is a PDF (PAdES) from its mime type or extension.
func isPDF(fileName, mimeType string) bool {
	if strings.Contains(strings.ToLower(mimeType), "pdf") {
		return true
	}
	return strings.EqualFold(fileExt(fileName), ".pdf")
}

// archiveContainerType maps the archived artifact to its media type + extension.
func archiveContainerType(pdf bool) (contentType, ext string) {
	if pdf {
		return "application/pdf", ".pdf"
	}
	return "application/vnd.etsi.asic-e+zip", ".edoc"
}
