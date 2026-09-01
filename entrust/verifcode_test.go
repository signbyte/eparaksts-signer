package entrust

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestVerificationCodeFormat checks the code is always exactly 4 digits and in
// the [0000, 9999] range.
func TestVerificationCodeFormat(t *testing.T) {
	inputs := []string{
		base64.StdEncoding.EncodeToString([]byte("digest-one")),
		base64.StdEncoding.EncodeToString([]byte("digest-two")),
		base64.StdEncoding.EncodeToString(make([]byte, 32)),
		base64.StdEncoding.EncodeToString([]byte{0xff, 0xff}),
	}
	for _, in := range inputs {
		code, err := VerificationCode(in)
		qt.Assert(t, qt.IsNil(err))
		qt.Assert(t, qt.Equals(len(code), 4))
		for _, r := range code {
			qt.Assert(t, qt.IsTrue(r >= '0' && r <= '9'))
		}
	}
}

// TestVerificationCodeDeterministic checks the same input always yields the same
// code (it is a pure function of the digest bytes).
func TestVerificationCodeDeterministic(t *testing.T) {
	in := base64.StdEncoding.EncodeToString([]byte("stable-digest"))
	a, err := VerificationCode(in)
	qt.Assert(t, qt.IsNil(err))
	b, err := VerificationCode(in)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(a, b))
}

// TestVerificationCodeMatchesReferenceAlgorithm independently recomputes the
// algorithm (SHA-256 → last 2 bytes big-endian → mod 10000) and asserts the
// implementation agrees, so a refactor cannot silently change the contract.
func TestVerificationCodeMatchesReferenceAlgorithm(t *testing.T) {
	raw := []byte("the-data-to-be-signed")
	in := base64.StdEncoding.EncodeToString(raw)

	sum := sha256.Sum256(raw)
	want := fmt.Sprintf("%04d", binary.BigEndian.Uint16(sum[len(sum)-2:])%10000)

	got, err := VerificationCode(in)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(got, want))
}

// TestVerificationCodeRejectsBadBase64 checks invalid base64 is an error.
func TestVerificationCodeRejectsBadBase64(t *testing.T) {
	_, err := VerificationCode("not!base64!")
	qt.Assert(t, qt.IsNotNil(err))
}
