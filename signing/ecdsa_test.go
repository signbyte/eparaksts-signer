package signing

import (
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"

	"github.com/go-quicktest/qt"
)

// fixedWidth left-pads v's big-endian bytes to width (the P1363 fixed-width
// encoding of one coordinate).
func fixedWidth(v *big.Int, width int) []byte {
	b := v.Bytes()
	out := make([]byte, width)
	copy(out[width-len(b):], b)
	return out
}

// p1363 builds a raw r‖s signature of the given per-coordinate width.
func p1363(r, s *big.Int, width int) []byte {
	return append(fixedWidth(r, width), fixedWidth(s, width)...)
}

// derOf marshals r,s to ECDSA DER.
func derOf(t *testing.T, r, s *big.Int) []byte {
	t.Helper()
	b, err := asn1.Marshal(ecdsaSig{R: r, S: s})
	qt.Assert(t, qt.IsNil(err))
	return b
}

// parseDER parses ECDSA DER back to r,s.
func parseDER(t *testing.T, der []byte) (*big.Int, *big.Int) {
	t.Helper()
	var sig ecdsaSig
	rest, err := asn1.Unmarshal(der, &sig)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.Equals(len(rest), 0))
	return sig.R, sig.S
}

// TestNormalizeP1363RoundTrip converts P1363 → DER for P-256 (64) and P-384 (96)
// and confirms the recovered r,s match the inputs and the branch is flagged.
func TestNormalizeP1363RoundTrip(t *testing.T) {
	cases := []struct {
		name  string
		width int
		r, s  *big.Int
	}{
		{"p256", 32, mustHex("a1b2c3d4e5f6071829384756abcdef00112233445566778899aabbccddeeff01"), mustHex("0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff02")},
		{"p384", 48, big.NewInt(0x1234567890abcdef), big.NewInt(0x0fedcba987654321)},
		{"p256-small-r-leading-zeros", 32, big.NewInt(1), big.NewInt(2)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			raw := p1363(tc.r, tc.s, tc.width)
			der, wasP1363, err := normalizeToDER(raw)
			qt.Assert(t, qt.IsNil(err))
			qt.Assert(t, qt.IsTrue(wasP1363))

			gotR, gotS := parseDER(t, der)
			qt.Assert(t, qt.Equals(gotR.Cmp(tc.r), 0))
			qt.Assert(t, qt.Equals(gotS.Cmp(tc.s), 0))
		})
	}
}

// TestNormalizeDERPassThrough confirms valid DER is returned unchanged and not
// flagged as P1363.
func TestNormalizeDERPassThrough(t *testing.T) {
	r := mustHex("a1b2c3d4e5f6071829384756abcdef00112233445566778899aabbccddeeff01")
	s := mustHex("0f1e2d3c4b5a69788796a5b4c3d2e1f00112233445566778899aabbccddeeff02")
	der := derOf(t, r, s)

	out, wasP1363, err := normalizeToDER(der)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(wasP1363))
	qt.Assert(t, qt.DeepEquals(out, der))
}

// TestNormalizeRejectsUnknown rejects a buffer that is neither valid DER nor a
// known P1363 width.
func TestNormalizeRejectsUnknown(t *testing.T) {
	_, _, err := normalizeToDER(make([]byte, 70)) // not DER, not a P1363 width
	qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBadSignatureEncoding)))

	// A 64-byte all-zero buffer is the right width but r=s=0 → rejected.
	_, _, err = normalizeToDER(make([]byte, 64))
	qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBadSignatureEncoding)))
}

// TestNormalizeSignatureToDERBase64 exercises the base64 wrapper used at the
// finalize boundary.
func TestNormalizeSignatureToDERBase64(t *testing.T) {
	r, s := big.NewInt(0x4242), big.NewInt(0x2424)
	rawB64 := base64.StdEncoding.EncodeToString(p1363(r, s, 32))

	derB64, wasP1363, err := NormalizeSignatureToDER(rawB64)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(wasP1363))

	der, err := base64.StdEncoding.DecodeString(derB64)
	qt.Assert(t, qt.IsNil(err))
	gotR, gotS := parseDER(t, der)
	qt.Assert(t, qt.Equals(gotR.Cmp(r), 0))
	qt.Assert(t, qt.Equals(gotS.Cmp(s), 0))

	_, _, err = NormalizeSignatureToDER("!!not base64!!")
	qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBadSignatureEncoding)))
}

func mustHex(h string) *big.Int {
	n, ok := new(big.Int).SetString(h, 16)
	if !ok {
		panic("bad hex: " + h)
	}
	return n
}
