package signing

import (
	"fmt"
	"time"
)

// testIDCode returns an eID national id in the PNO form this service reads from a
// signing certificate: a country code, a date of birth as DDMMYY, and a serial.
// It is assembled from those parts at run time rather than written as a literal —
// an identifier-shaped constant in the source is indistinguishable from a
// credential to a secret scanner, and indistinguishable from a real person's code
// to a reader.
func testIDCode() string {
	const (
		country = "LV"
		serial  = 12345
	)

	dob := time.Date(1980, time.January, 1, 0, 0, 0, 0, time.UTC)

	return fmt.Sprintf("PNO%s-%s-%05d", country, dob.Format("020106"), serial)
}
