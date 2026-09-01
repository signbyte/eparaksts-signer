package routes

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"strings"
	"testing"

	"github.com/go-quicktest/qt"
	"github.com/valyala/fasthttp"
)

// --- fixtures: honest byte shapes for the gate ---------------------------------

// samplePDF builds a minimal, valid, unsigned single-page PDF with correct
// cross-reference offsets.
func samplePDF() []byte {
	var buf bytes.Buffer
	offsets := make([]int, 4)

	buf.WriteString("%PDF-1.4\n")
	obj := func(n int, body string) {
		offsets[n] = buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n%s\nendobj\n", n, body)
	}
	obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
	obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")
	xref := buf.Len()
	buf.WriteString("xref\n0 4\n0000000000 65535 f \n")
	for i := 1; i <= 3; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", offsets[i])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size 4 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", xref)

	return buf.Bytes()
}

// signedContainer builds a strict ASiC-E (mimetype first + stored) holding one
// document and one structurally-parseable detached XAdES signature over it.
func signedContainer(t *testing.T) []byte {
	t.Helper()
	docData := []byte("hello world")
	sum := sha256.Sum256(docData)
	digest := base64.StdEncoding.EncodeToString(sum[:])
	sig := fmt.Sprintf(`<?xml version="1.0" encoding="UTF-8"?>`+
		`<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#" Id="S0"><ds:SignedInfo>`+
		`<ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/>`+
		`<ds:SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256"/>`+
		`<ds:Reference Id="r0" URI="doc1.txt">`+
		`<ds:DigestMethod Algorithm="http://www.w3.org/2001/04/xmlenc#sha256"/>`+
		`<ds:DigestValue>%s</ds:DigestValue></ds:Reference>`+
		`</ds:SignedInfo><ds:SignatureValue>Zm9v</ds:SignatureValue></ds:Signature>`, digest)

	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mt, err := zw.CreateHeader(&zip.FileHeader{Name: "mimetype", Method: zip.Store})
	qt.Assert(t, qt.IsNil(err))
	_, err = mt.Write([]byte("application/vnd.etsi.asic-e+zip"))
	qt.Assert(t, qt.IsNil(err))
	dw, err := zw.CreateHeader(&zip.FileHeader{Name: "doc1.txt", Method: zip.Deflate})
	qt.Assert(t, qt.IsNil(err))
	_, err = dw.Write(docData)
	qt.Assert(t, qt.IsNil(err))
	sw, err := zw.CreateHeader(&zip.FileHeader{Name: "META-INF/signatures0.xml", Method: zip.Deflate})
	qt.Assert(t, qt.IsNil(err))
	_, err = sw.Write([]byte(sig))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(zw.Close()))

	return buf.Bytes()
}

// unsignedContainer is strict ASiC-E in shape but holds no signature.
func unsignedContainer(t *testing.T) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	mt, err := zw.CreateHeader(&zip.FileHeader{Name: "mimetype", Method: zip.Store})
	qt.Assert(t, qt.IsNil(err))
	_, err = mt.Write([]byte("application/vnd.etsi.asic-e+zip"))
	qt.Assert(t, qt.IsNil(err))
	dw, err := zw.CreateHeader(&zip.FileHeader{Name: "doc1.txt", Method: zip.Deflate})
	qt.Assert(t, qt.IsNil(err))
	_, err = dw.Write([]byte("hello"))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(zw.Close()))

	return buf.Bytes()
}

// --- verify-mode gate on /validations -------------------------------------------

func TestValidateGateRejections(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)
	tc := app.TestClient()

	cases := []struct {
		name     string
		filename string
		data     []byte
	}{
		{"garbage named pdf", "fake.pdf", []byte{0xde, 0xad}},
		{"disallowed extension", "notes.txt", []byte("text")},
		{"unsigned pdf", "plain.pdf", samplePDF()},
		{"unsigned container", "c.edoc", nil}, // data filled below
		{"plain zip named asice", "fake.asice", nil},
	}
	cases[3].data = unsignedContainer(t)
	z := func() []byte { // a plain zip, not a container
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		w, _ := zw.CreateHeader(&zip.FileHeader{Name: "a.txt", Method: zip.Deflate})
		_, _ = w.Write([]byte("x"))
		_ = zw.Close()
		return buf.Bytes()
	}()
	cases[4].data = z

	for _, tcase := range cases {
		t.Run(tcase.name, func(t *testing.T) {
			body, ct := multipartBody(t, "file", tcase.filename, tcase.data, nil)
			resp, err := tc.Post("/api/v1/validations", body,
				tc.WithHeader("X-Test-Scopes", "signatures:read"),
				tc.WithHeader("Content-Type", ct))
			qt.Assert(t, qt.IsNil(err))
			defer fasthttp.ReleaseResponse(resp)
			qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
			buf, err := resp.BodyUncompressed()
			qt.Assert(t, qt.IsNil(err))
			qt.Check(t, qt.IsTrue(strings.Contains(string(buf), "err:signing:uploadRejected")))
		})
	}
}

// A well-formed SIGNED container passes the gate: the request proceeds to the
// upstream call (which is not configured in tests), so the answer is the
// upstream error — never the gate's 422.
func TestValidateGateAdmitsSignedContainer(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)
	tc := app.TestClient()

	body, ct := multipartBody(t, "file", "signed.edoc", signedContainer(t), nil)
	resp, err := tc.Post("/api/v1/validations", body,
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
		tc.WithHeader("Content-Type", ct))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
}

// With hardening off (an already-gated edge in front), the gate is skipped and
// even opaque bytes reach the upstream call.
func TestValidateGateDisabled(t *testing.T) {
	t.Setenv("UPLOAD_HARDENING", "false")
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)
	tc := app.TestClient()

	body, ct := multipartBody(t, "file", "anything.bin", []byte("opaque"), nil)
	resp, err := tc.Post("/api/v1/validations", body,
		tc.WithHeader("X-Test-Scopes", "signatures:read"),
		tc.WithHeader("Content-Type", ct))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.Equals(resp.StatusCode(), fasthttp.StatusBadGateway))
}

// --- signing-mode gate on /signatures/prepare ------------------------------------

// prepareMultipart builds a bytes-mode prepare request with one file part.
func prepareMultipart(t *testing.T, fileName string, data []byte) ([]byte, string) {
	t.Helper()
	meta := map[string]any{
		"locale": "en",
		"documents": []map[string]any{{
			"documentId":      "doc-1",
			"fileRef":         "f1",
			"fileName":        fileName,
			"mimeType":        "application/octet-stream",
			"signatureFormat": "PAdES",
		}},
	}
	metaJSON, err := json.Marshal(meta)
	qt.Assert(t, qt.IsNil(err))

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	qt.Assert(t, qt.IsNil(w.WriteField("metadata", string(metaJSON))))
	fw, err := w.CreateFormFile("f1", fileName)
	qt.Assert(t, qt.IsNil(err))
	_, err = fw.Write(data)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsNil(w.Close()))

	return buf.Bytes(), w.FormDataContentType()
}

func TestPrepareGateSigningMode(t *testing.T) {
	app := testApp(t)
	app.Start(t)
	t.Cleanup(app.Stop)
	tc := app.TestClient()

	// The gate is still active in signing mode: a file whose extension lies
	// about its content dies at the gate with the typed reason. A ".pdf" that
	// carries no PDF magic is the honest-extension rule that signing mode keeps.
	body, ct := prepareMultipart(t, "fake.pdf", []byte{0xde, 0xad})
	resp, err := tc.Post("/api/v1/signatures/prepare?flow=csc", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("Content-Type", ct))
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(resp.StatusCode(), fasthttp.StatusUnprocessableEntity))
	buf, err := resp.BodyUncompressed()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(strings.Contains(string(buf), "err:signing:uploadRejected")))
	fasthttp.ReleaseResponse(resp)

	// A PDF-shaped upload that does not fully parse is ADMITTED in signing mode:
	// the offset-0 magic already excluded non-PDF content, and the signing
	// service — not this gate — is the authority on signability. It proceeds
	// past the gate (whatever the flow does next, it is not the gate's 422).
	body, ct = prepareMultipart(t, "broken.pdf", []byte("%PDF-1.4 then garbage"))
	resp, err = tc.Post("/api/v1/signatures/prepare?flow=csc", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("Content-Type", ct))
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsTrue(resp.StatusCode() != fasthttp.StatusUnprocessableEntity))
	fasthttp.ReleaseResponse(resp)

	// Any opaque format is admitted in signing mode — the request proceeds
	// past the gate (whatever the flow does next, it is not the gate's 422).
	body, ct = prepareMultipart(t, "notes.txt", []byte("hello"))
	resp, err = tc.Post("/api/v1/signatures/prepare?flow=csc", body,
		tc.WithHeader("X-Test-Scopes", "signatures:create"),
		tc.WithHeader("Content-Type", ct))
	qt.Assert(t, qt.IsNil(err))
	defer fasthttp.ReleaseResponse(resp)
	qt.Check(t, qt.IsTrue(resp.StatusCode() != fasthttp.StatusUnprocessableEntity))
}
