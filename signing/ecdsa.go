package signing

import (
	"encoding/asn1"
	"encoding/base64"
	"errors"
	"fmt"
	"math/big"
)

// ErrBadSignatureEncoding is the hard failure for a signature value that is
// neither valid DER nor a recognized P1363 width — never guessed.
var ErrBadSignatureEncoding = errors.New("signing: bad signature encoding")

// p1363Widths are the valid raw r‖s total widths for P-256 / P-384 / P-521.
var p1363Widths = map[int]bool{64: true, 96: true, 132: true}

// ecdsaSig is the ASN.1 DER shape SEQUENCE{ INTEGER r, INTEGER s }.
type ecdsaSig struct {
	R, S *big.Int
}

// NormalizeSignatureToDER normalizes a base64 signature value to base64 DER at
// the finalize boundary, regardless of flow (the normative encoding rule at the
// signing/DSS boundary):
//
// - first byte 0x30 AND parses as a complete ASN.1 SEQUENCE{INTEGER,INTEGER}
// → already DER, passed through;
// - total length ∈ {64, 96, 132} → P1363 raw r‖s → split, strip leading zeros,
// ASN.1-marshal to DER;
// - anything else → ErrBadSignatureEncoding (never guess).
//
// wasP1363 reports whether the input was the P1363 branch — the orchestrator
// logs it at info level when a TrustedX response unexpectedly lands there
// (telemetry for that residual encoding-ambiguity case).
func NormalizeSignatureToDER(sigB64 string) (derB64 string, wasP1363 bool, err error) {
	raw, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", false, fmt.Errorf("%w: invalid base64: %w", ErrBadSignatureEncoding, err)
	}
	der, p1363, err := normalizeToDER(raw)
	if err != nil {
		return "", false, err
	}
	return base64.StdEncoding.EncodeToString(der), p1363, nil
}

// normalizeToDER does the detect-and-convert on raw bytes.
func normalizeToDER(raw []byte) ([]byte, bool, error) {
	// DER pass-through: starts with SEQUENCE tag and round-trips exactly.
	if len(raw) > 0 && raw[0] == 0x30 {
		var sig ecdsaSig
		rest, err := asn1.Unmarshal(raw, &sig)
		if err == nil && len(rest) == 0 && sig.R != nil && sig.S != nil &&
			sig.R.Sign() > 0 && sig.S.Sign() > 0 {
			return raw, false, nil
		}
		// 0x30 prefix but not a clean ECDSA SEQUENCE — fall through to width check
		// (which will reject it unless it happens to be a valid P1363 width).
	}

	// P1363 raw r‖s of a known width.
	if p1363Widths[len(raw)] {
		half := len(raw) / 2
		r := new(big.Int).SetBytes(raw[:half])
		s := new(big.Int).SetBytes(raw[half:])
		if r.Sign() == 0 || s.Sign() == 0 {
			return nil, false, fmt.Errorf("%w: P1363 r or s is zero", ErrBadSignatureEncoding)
		}
		der, err := asn1.Marshal(ecdsaSig{R: r, S: s})
		if err != nil {
			return nil, false, fmt.Errorf("%w: DER marshal: %w", ErrBadSignatureEncoding, err)
		}
		return der, true, nil
	}

	return nil, false, fmt.Errorf("%w: length %d is neither DER nor a P1363 width", ErrBadSignatureEncoding, len(raw))
}
