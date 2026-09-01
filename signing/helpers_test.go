package signing

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/signbyte/eparaksts-signer/job"
)

// makeCertB64 builds a self-signed ECDSA certificate carrying the given subject
// serialNumber and returns it base64-DER (the shape certSubject expects).
func makeCertB64(t *testing.T, serialNumber string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	qt.Assert(t, qt.IsNil(err))
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{SerialNumber: serialNumber, CommonName: "Test Signer"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	qt.Assert(t, qt.IsNil(err))
	return base64.StdEncoding.EncodeToString(der)
}

// TestValidateBatch covers the empty/single/batch/format-mix rules.
func TestValidateBatch(t *testing.T) {
	xades := job.FormatXAdES
	pades := job.FormatPAdES
	doc := func(f job.SignatureFormat) InputDocument { return InputDocument{Format: f} }

	t.Run("no documents", func(t *testing.T) {
		err := validateBatch(PrepareInput{}, Capabilities{SupportsBatch: true})
		qt.Assert(t, qt.IsNotNil(err))
	})
	t.Run("single doc always ok", func(t *testing.T) {
		err := validateBatch(PrepareInput{Documents: []InputDocument{doc(xades)}}, Capabilities{})
		qt.Assert(t, qt.IsNil(err))
	})
	t.Run("batch without support", func(t *testing.T) {
		err := validateBatch(PrepareInput{Documents: []InputDocument{doc(xades), doc(xades)}}, Capabilities{SupportsBatch: false})
		qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBatchUnsupport)))
	})
	t.Run("batch with single-session-only", func(t *testing.T) {
		err := validateBatch(PrepareInput{Documents: []InputDocument{doc(xades), doc(xades)}}, Capabilities{SupportsBatch: true, SingleSessionOnly: true})
		qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBatchUnsupport)))
	})
	t.Run("batch mixed format", func(t *testing.T) {
		err := validateBatch(PrepareInput{Documents: []InputDocument{doc(xades), doc(pades)}}, Capabilities{SupportsBatch: true})
		qt.Assert(t, qt.IsTrue(errors.Is(err, ErrMixedFormat)))
	})
	t.Run("batch same format", func(t *testing.T) {
		err := validateBatch(PrepareInput{Documents: []InputDocument{doc(xades), doc(xades)}}, Capabilities{SupportsBatch: true})
		qt.Assert(t, qt.IsNil(err))
	})
}

// TestCertSubject extracts the subject serialNumber from a real cert and returns
// "" for anything that is not a base64-DER certificate.
func TestCertSubject(t *testing.T) {
	nationalID := testIDCode()
	qt.Check(t, qt.Equals(certSubject(makeCertB64(t, nationalID)), nationalID))

	qt.Check(t, qt.Equals(certSubject(""), ""))
	qt.Check(t, qt.Equals(certSubject("!!! not base64 !!!"), ""))
	// Valid base64 but not a DER certificate.
	qt.Check(t, qt.Equals(certSubject(base64.StdEncoding.EncodeToString([]byte("hello"))), ""))
}

// TestContainerType maps (format, asice) to the media type + extension.
func TestContainerType(t *testing.T) {
	ct, ext := containerType(job.FormatPAdES, false)
	qt.Check(t, qt.Equals(ct, "application/pdf"))
	qt.Check(t, qt.Equals(ext, ".pdf"))

	// asice is irrelevant for PAdES.
	ct, ext = containerType(job.FormatPAdES, true)
	qt.Check(t, qt.Equals(ct, "application/pdf"))
	qt.Check(t, qt.Equals(ext, ".pdf"))

	ct, ext = containerType(job.FormatXAdES, false)
	qt.Check(t, qt.Equals(ct, "application/vnd.etsi.asic-e+zip"))
	qt.Check(t, qt.Equals(ext, ".edoc"))

	ct, ext = containerType(job.FormatXAdES, true)
	qt.Check(t, qt.Equals(ct, "application/vnd.etsi.asic-e+zip"))
	qt.Check(t, qt.Equals(ext, ".asice"))
}

// TestFileExt returns the trailing extension or "".
func TestFileExt(t *testing.T) {
	cases := map[string]string{
		"report.pdf": ".pdf",
		"a.tar.gz":   ".gz",
		"noext":      "",
		"":           "",
		".hidden":    ".hidden",
	}
	for in, want := range cases {
		t.Run(in, func(t *testing.T) {
			qt.Check(t, qt.Equals(fileExt(in), want))
		})
	}
}

// TestOrDefault falls back when the value is blank.
func TestOrDefault(t *testing.T) {
	qt.Check(t, qt.Equals(orDefault("", "def"), "def"))
	qt.Check(t, qt.Equals(orDefault("   ", "def"), "def"))
	qt.Check(t, qt.Equals(orDefault("value", "def"), "value"))
}

// TestSignAlgoName maps SignAPI algorithm strings to the caller-facing family.
func TestSignAlgoName(t *testing.T) {
	qt.Check(t, qt.Equals(signAlgoName("ECDSA-SHA384"), "ecdsa"))
	qt.Check(t, qt.Equals(signAlgoName("1.2.840.10045 ECC"), "ecdsa"))
	qt.Check(t, qt.Equals(signAlgoName("RSA-SHA256"), "rsa"))
	// Unknown families pass through unchanged.
	qt.Check(t, qt.Equals(signAlgoName("Ed25519"), "Ed25519"))
}

// TestDigestAlgoFor maps a base64 digest's decoded length to the hash label.
func TestDigestAlgoFor(t *testing.T) {
	b64 := func(n int) string { return base64.StdEncoding.EncodeToString(make([]byte, n)) }
	qt.Check(t, qt.Equals(digestAlgoFor(b64(48)), "sha384"))
	qt.Check(t, qt.Equals(digestAlgoFor(b64(64)), "sha512"))
	qt.Check(t, qt.Equals(digestAlgoFor(b64(32)), "sha256"))
	// Unknown length and bad base64 both default to sha256.
	qt.Check(t, qt.Equals(digestAlgoFor(b64(20)), "sha256"))
	qt.Check(t, qt.Equals(digestAlgoFor("!! not base64 !!"), "sha256"))
}

// TestSignapiDocDigestAlgo normalizes a digest-algorithm label to the bare token
// SignAPI's add-document-digest accepts (it rejects the hyphenated form).
func TestSignapiDocDigestAlgo(t *testing.T) {
	qt.Check(t, qt.Equals(signapiDocDigestAlgo("SHA-256"), "SHA256"))
	qt.Check(t, qt.Equals(signapiDocDigestAlgo("sha-256"), "SHA256"))
	qt.Check(t, qt.Equals(signapiDocDigestAlgo("SHA256"), "SHA256"))
	// Empty defaults to SHA256 (the only value SignAPI supports for the doc digest).
	qt.Check(t, qt.Equals(signapiDocDigestAlgo(""), "SHA256"))
}

// TestPKCE mints a 32-byte verifier and an S256 challenge derived from it, and
// produces a fresh verifier on each call.
func TestPKCE(t *testing.T) {
	v, ch, err := pkce()
	qt.Assert(t, qt.IsNil(err))

	raw, err := base64.RawURLEncoding.DecodeString(v)
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(len(raw), 32))

	sum := sha256.Sum256([]byte(v))
	qt.Check(t, qt.Equals(ch, base64.RawURLEncoding.EncodeToString(sum[:])))

	v2, _, err := pkce()
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.IsFalse(v == v2))
}

// TestSubstituteJobID replaces every {jobId} placeholder.
func TestSubstituteJobID(t *testing.T) {
	qt.Check(t, qt.Equals(substituteJobID("https://x/{jobId}/done", "J123"), "https://x/J123/done"))
	qt.Check(t, qt.Equals(substituteJobID("{jobId}-{jobId}", "J"), "J-J"))
	qt.Check(t, qt.Equals(substituteJobID("no-placeholder", "J"), "no-placeholder"))
	qt.Check(t, qt.Equals(substituteJobID("", "J"), ""))
}
