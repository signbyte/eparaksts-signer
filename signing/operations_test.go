package signing

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestValidatePDF drives the validate spine for a PDF: it validates the uploaded
// document's own id (data.id) and relays the report verbatim; the session is
// closed afterwards.
func TestValidatePDF(t *testing.T) {
	const report = `{"data":{"signatureForm":"PAdES","signaturesCount":1,"validSignaturesCount":1}}`
	var validatePath string
	var closed bool
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/start"):
			_, _ = io.WriteString(w, `{"data":{"sessionId":"s1"}}`)
		case strings.HasSuffix(r.URL.Path, "/upload"):
			_, _ = io.WriteString(w, `{"data":{"id":"docX","name":"signed.pdf","includedDocuments":[]}}`)
		case strings.HasSuffix(r.URL.Path, "/validate"):
			validatePath = r.URL.Path
			_, _ = io.WriteString(w, report)
		case strings.HasSuffix(r.URL.Path, "/close"):
			closed = true
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	sid, status, body, err := o.Validate(context.Background(), "corr", "signed.pdf", "application/pdf", []byte("PDF"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sid, "s1"))
	qt.Check(t, qt.Equals(status, http.StatusOK))
	qt.Check(t, qt.Equals(string(body), report))
	qt.Check(t, qt.Equals(validatePath, "/api-validation/v2.0/s1/docX/validate"))
	qt.Check(t, qt.IsTrue(closed))
}

// TestValidateASiCE is the regression test for the documentId fix: for an ASiC-E
// upload the CONTAINER id (data.id) is validated, NOT an inner document id
// (validating the inner file yields SignAPI "Document format not recognized").
func TestValidateASiCE(t *testing.T) {
	var validatePath string
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/start"):
			_, _ = io.WriteString(w, `{"data":{"sessionId":"s1"}}`)
		case strings.HasSuffix(r.URL.Path, "/upload"):
			// data.id = container; includedDocuments = the inner raw.doc.
			_, _ = io.WriteString(w, `{"data":{"id":"container-9","name":"x-1-1.edoc","includedDocuments":[{"id":"inner-1","name":"a.doc"}]}}`)
		case strings.HasSuffix(r.URL.Path, "/validate"):
			validatePath = r.URL.Path
			_, _ = io.WriteString(w, `{"data":{}}`)
		case strings.HasSuffix(r.URL.Path, "/close"):
			w.WriteHeader(http.StatusOK)
		default:
			t.Errorf("unexpected path %s", r.URL.Path)
		}
	})

	sid, _, _, err := o.Validate(context.Background(), "corr", "signed.edoc", "", []byte("EDOC"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(sid, "s1"))
	qt.Check(t, qt.Equals(validatePath, "/api-validation/v2.0/s1/container-9/validate"))
}

// TestArchiveUpload drives the standalone archive spine: upload → addArchive →
// list → download, with the CSC_AUTH_CERT fallback used when no request cert is
// supplied. Asserts the archived bytes, media type, filename, and the auth cert
// forwarded to addArchive.
func TestArchiveUpload(t *testing.T) {
	var gotAuthCert, gotDownloadPath string
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/start"):
			_, _ = io.WriteString(w, `{"data":{"sessionId":"s1"}}`)
		case strings.HasSuffix(r.URL.Path, "/upload"):
			_, _ = io.WriteString(w, `{"data":{"id":"doc-1","includedDocuments":[]}}`)
		case r.URL.Path == "/api-sign/v1.0/addArchive":
			var body struct {
				Sessions []struct {
					SessionID string `json:"sessionId"`
				} `json:"sessions"`
				AuthCertificate string `json:"authCertificate"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotAuthCert = body.AuthCertificate
			_, _ = io.WriteString(w, `{"data":{"results":[{"sessionId":"s1"}]}}`)
		case strings.HasSuffix(r.URL.Path, "/close"):
			w.WriteHeader(http.StatusOK)
		default: // download the archived doc by the upload's data.id
			gotDownloadPath = r.URL.Path
			_, _ = w.Write([]byte("ARCHIVEDBYTES"))
		}
	})
	// The configured csc cert must play no part in an archive: the caller
	// supplies the signed-in user's cert, and without one the call refuses.
	o.cfg = Config{CSCAuthCert: "ENVCERT"}

	_, _, _, err := o.ArchiveUpload(context.Background(), "corr", "signed.edoc", "", "", []byte("EDOC"))
	qt.Assert(t, qt.ErrorIs(err, ErrNoAuthCert))

	archived, ct, name, err := o.ArchiveUpload(context.Background(), "corr", "signed.edoc", "", "USERCERT", []byte("EDOC"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.DeepEquals(archived, []byte("ARCHIVEDBYTES")))
	qt.Check(t, qt.Equals(ct, "application/vnd.etsi.asic-e+zip"))
	qt.Check(t, qt.Equals(name, "signed-archived.edoc"))
	qt.Check(t, qt.Equals(gotAuthCert, "USERCERT")) // the user's cert, never the csc config
	// Regression guard: the archived form is downloaded by the UPLOAD's data.id, not
	// a guessed "last file in the session list" entry.
	qt.Check(t, qt.Equals(gotDownloadPath, "/api-storage/v1.0/s1/doc-1"))
}

// TestArchiveUploadPrefersRequestCert confirms the request-supplied cert (the
// signed-in user's) wins over CSC_AUTH_CERT, and the PDF media type/extension.
func TestArchiveUploadPrefersRequestCert(t *testing.T) {
	var gotAuthCert string
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/start"):
			_, _ = io.WriteString(w, `{"data":{"sessionId":"s1"}}`)
		case strings.HasSuffix(r.URL.Path, "/upload"):
			_, _ = io.WriteString(w, `{"data":{"id":"doc-pdf"}}`)
		case r.URL.Path == "/api-sign/v1.0/addArchive":
			var body struct {
				AuthCertificate string `json:"authCertificate"`
			}
			_ = json.NewDecoder(r.Body).Decode(&body)
			gotAuthCert = body.AuthCertificate
			w.WriteHeader(http.StatusOK)
		case strings.HasSuffix(r.URL.Path, "/close"):
			w.WriteHeader(http.StatusOK)
		default:
			_, _ = w.Write([]byte("PDF"))
		}
	})
	o.cfg = Config{CSCAuthCert: "ENVCERT"}

	_, ct, name, err := o.ArchiveUpload(context.Background(), "corr", "doc.pdf", "application/pdf", "USERCERT", []byte("PDF"))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(gotAuthCert, "USERCERT"))
	qt.Check(t, qt.Equals(ct, "application/pdf"))
	qt.Check(t, qt.Equals(name, "doc-archived.pdf"))
}

// TestArchiveUploadNoAuthCert returns ErrNoAuthCert before touching SignAPI.
func TestArchiveUploadNoAuthCert(t *testing.T) {
	called := false
	o := newSpineOrchestrator(t, func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	})
	// cfg.CSCAuthCert is empty and no request cert supplied.
	_, _, _, err := o.ArchiveUpload(context.Background(), "corr", "x.edoc", "", "", []byte("X"))
	qt.Assert(t, qt.ErrorIs(err, ErrNoAuthCert))
	qt.Check(t, qt.IsFalse(called))
}

// TestIsPDF / TestArchiveContainerType cover the small format helpers.
func TestIsPDF(t *testing.T) {
	qt.Check(t, qt.IsTrue(isPDF("doc.pdf", "")))
	qt.Check(t, qt.IsTrue(isPDF("DOC.PDF", "")))
	qt.Check(t, qt.IsTrue(isPDF("noext", "application/pdf")))
	qt.Check(t, qt.IsFalse(isPDF("doc.edoc", "application/vnd.etsi.asic-e+zip")))
	qt.Check(t, qt.IsFalse(isPDF("doc.asice", "")))
}

func TestArchiveContainerType(t *testing.T) {
	ct, ext := archiveContainerType(true)
	qt.Check(t, qt.Equals(ct, "application/pdf"))
	qt.Check(t, qt.Equals(ext, ".pdf"))

	ct, ext = archiveContainerType(false)
	qt.Check(t, qt.Equals(ct, "application/vnd.etsi.asic-e+zip"))
	qt.Check(t, qt.Equals(ext, ".edoc"))
}
