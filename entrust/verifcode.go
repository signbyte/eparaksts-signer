package entrust

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"fmt"
)

// VerificationCode computes the 4-digit code the user matches on the device for
// the eidScan flow:
//
//	SHA-256(digest_value_bytes) → take the LAST two bytes as a big-endian uint16
//	→ mod 10000 → zero-pad to 4 digits.
//
// digestValueB64 is the per-session digest returned by CalculateDigest (base64).
func VerificationCode(digestValueB64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(digestValueB64)
	if err != nil {
		return "", fmt.Errorf("entrust: verification code: invalid digest base64: %w", err)
	}
	sum := sha256.Sum256(raw)
	last := binary.BigEndian.Uint16(sum[len(sum)-2:])
	return fmt.Sprintf("%04d", last%10000), nil
}
