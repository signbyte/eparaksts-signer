package signing

import (
	"encoding/asn1"
	"errors"
	"math/big"
	"testing"

	"github.com/go-quicktest/qt"
)

// TestNormalizeP521 converts a P-521 width (132) P1363 signature to DER. (The
// helpers p1363/parseDER/mustHex live in ecdsa_test.go, same package.)
func TestNormalizeP521(t *testing.T) {
	r := mustHex("01a2b3c4d5e6f70819")
	s := mustHex("00ffeeddccbbaa9988")
	raw := p1363(r, s, 66) // 66 bytes per coordinate → 132 total

	der, wasP1363, err := normalizeToDER(raw)
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsTrue(wasP1363))

	gotR, gotS := parseDER(t, der)
	qt.Check(t, qt.Equals(gotR.Cmp(r), 0))
	qt.Check(t, qt.Equals(gotS.Cmp(s), 0))
}

// TestNormalizeSeqPrefixNotDER covers a buffer that starts with the SEQUENCE tag
// (0x30) but is not a clean ECDSA SEQUENCE; with a non-P1363 length it must be
// rejected rather than guessed.
func TestNormalizeSeqPrefixNotDER(t *testing.T) {
	// 0x30 prefix, trailing garbage, length 70 (not 64/96/132).
	buf := make([]byte, 70)
	buf[0] = 0x30
	buf[1] = 0x10
	_, _, err := normalizeToDER(buf)
	qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBadSignatureEncoding)))
}

// TestNormalizeDERZeroComponentRejected confirms a structurally valid SEQUENCE
// whose r (or s) is zero is not accepted as pass-through DER. Length 70 is not a
// P1363 width either, so it falls through to a hard error.
func TestNormalizeDERZeroComponentRejected(t *testing.T) {
	der, err := asn1.Marshal(ecdsaSig{R: big.NewInt(0), S: big.NewInt(5)})
	qt.Assert(t, qt.IsNil(err))
	qt.Assert(t, qt.IsFalse(p1363Widths[len(der)])) // guard: not accidentally a P1363 width

	_, _, err = normalizeToDER(der)
	qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBadSignatureEncoding)))
}

// TestNormalizeEmptyRejected rejects an empty buffer.
func TestNormalizeEmptyRejected(t *testing.T) {
	_, _, err := normalizeToDER(nil)
	qt.Assert(t, qt.IsTrue(errors.Is(err, ErrBadSignatureEncoding)))
}
