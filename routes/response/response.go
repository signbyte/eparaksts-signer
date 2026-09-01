// Package response holds the outbound response DTOs for the eParaksts Signing
// Service API.
package response

// Error is the per-document sub-status carried inside a (successful) status
// response when one document in a batch failed while others succeeded. It is not
// an error response envelope — those are the uniform problem+json rendered by the
// platform error handler.
type Error struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Authorization is the redirect action returned by remote flows.
type Authorization struct {
	Type         string `json:"type"` // "redirect"
	AuthorizeURL string `json:"authorizeUrl"`
	ExpiresIn    int    `json:"expiresIn,omitempty"`
}

// PrepareDocumentRef is the per-document element of a prepare response. For eid it
// carries the digest to sign; for remote flows only the id.
type PrepareDocumentRef struct {
	DocumentID      string `json:"documentId"`
	Digest          string `json:"digest,omitempty"`
	DigestAlgorithm string `json:"digestAlgorithm,omitempty"`
}

// Prepare is the /prepare response.
type Prepare struct {
	JobID         string               `json:"jobId"`
	Flow          string               `json:"flow"`
	State         string               `json:"state"`
	Authorization *Authorization       `json:"authorization,omitempty"`
	SignAlgorithm string               `json:"signAlgorithm,omitempty"`
	Documents     []PrepareDocumentRef `json:"documents,omitempty"`
}

// Accepted is the /signatures (eid submit) 202 response.
type Accepted struct {
	JobID string `json:"jobId"`
	Flow  string `json:"flow"`
	State string `json:"state"`
}

// StatusDocument is the per-document element of a status response.
type StatusDocument struct {
	DocumentID  string `json:"documentId"`
	State       string `json:"state"`
	DownloadURL string `json:"downloadUrl,omitempty"`
	Error       *Error `json:"error,omitempty"`
}

// Status is the /status response.
type Status struct {
	JobID               string           `json:"jobId"`
	Flow                string           `json:"flow"`
	State               string           `json:"state"`
	VerificationCode    string           `json:"verificationCode,omitempty"`    // eidScan
	VerificationMessage string           `json:"verificationMessage,omitempty"` // eidScan — the device prompt, for code+text matching
	SigningDeadline     int64            `json:"signingDeadline,omitempty"`     // eidScan (epoch ms)
	Documents           []StatusDocument `json:"documents"`
	UpdatedAt           string           `json:"updatedAt"`
}
