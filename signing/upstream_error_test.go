package signing

import (
	"errors"
	"fmt"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/signbyte/eparaksts-signer/signapi"
)

// TestClassifyUpstream pins the rule that keeps a definitive provider rejection
// from masquerading as an upstream outage: a SignAPI 4xx becomes the
// client-actionable ErrDocumentRejected, while 5xx / transport faults stay as-is
// (they legitimately map to a 502 at the handler).
func TestClassifyUpstream(t *testing.T) {
	// A definitive 4xx (e.g. addArchive "not a PDF" / "no signatures to extend").
	rejected := classifyUpstream(&signapi.APIError{
		Method: "POST", Path: "/api-sign/v1.0/addArchive", Status: 400,
		Body: `{"data":{"results":[{"error":{"code":"signing:addArchive"}}]}}`,
	})
	qt.Check(t, qt.IsTrue(errors.Is(rejected, ErrDocumentRejected)))

	// A wrapped 4xx is still detected (errors.As unwraps through fmt wrapping).
	wrapped := classifyUpstream(fmt.Errorf("upload: %w", &signapi.APIError{Status: 422}))
	qt.Check(t, qt.IsTrue(errors.Is(wrapped, ErrDocumentRejected)))

	// A 5xx is an upstream fault, NOT a document rejection.
	fault := classifyUpstream(&signapi.APIError{Status: 503})
	qt.Check(t, qt.IsFalse(errors.Is(fault, ErrDocumentRejected)))

	// A transport error (not an APIError at all) passes through untouched.
	transport := classifyUpstream(errors.New("dial tcp: connection refused"))
	qt.Check(t, qt.IsFalse(errors.Is(transport, ErrDocumentRejected)))

	// The original cause is preserved in the chain for logging.
	qt.Check(t, qt.IsNotNil(rejected))
	var ae *signapi.APIError
	qt.Check(t, qt.IsTrue(errors.As(rejected, &ae)))
	qt.Check(t, qt.Equals(ae.Status, 400))
}
