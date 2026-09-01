// Package signapi is the typed client for the eParaksts SignAPI — the shared
// document spine under every flow: session create + upload, CalculateDigest,
// finalizeSigning, list/download, and close. The real surface was captured from
// verified manual traces. All calls carry the TrustedX introspect token as the
// Bearer and an X-Correlation-ID.
//
// Integrity contract (SCAL2): the digest / digests_summary returned by
// CalculateDigest are OPAQUE — echoed back verbatim into the signer and into
// finalizeSigning, never recomputed.
package signapi

// SessionRef references a SignAPI session in a CalculateDigest / finalize call.
type SessionRef struct {
	SessionID string `json:"sessionId"`
}

// startResponse is the api-session/start envelope: {data:{sessionId}}.
type startResponse struct {
	Data struct {
		SessionID string `json:"sessionId"`
	} `json:"data"`
}

// uploadResponse is the api-storage upload envelope. The top-level data.id/name
// identify the UPLOADED document itself — for ASiC-E the container (the signed
// .edoc), for a PDF the file. includedDocuments[] are the inner files of an
// ASiC-E container (the raw documents inside it).
type uploadResponse struct {
	Data struct {
		ID                string `json:"id"`
		Name              string `json:"name"`
		IncludedDocuments []struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"includedDocuments"`
	} `json:"data"`
}

// UploadResult is the parsed outcome of an upload: the uploaded document's own id
// (data.id — the ASiC-E CONTAINER or the PDF, which is what validation runs on)
// plus the inner document ids for an ASiC-E container.
type UploadResult struct {
	DocumentID        string   // data.id — the uploaded document/container
	FileName          string   // data.name
	IncludedDocuments []string // inner document ids (ASiC-E)
}

// HashFile is one hashed document for the confidential (addDocumentDigest) path.
type HashFile struct {
	Name            string `json:"name"`
	Digest          string `json:"digest"`
	DigestAlgorithm string `json:"digest_algorithm"`
}

type addDocumentDigestRequest struct {
	Files          []HashFile `json:"files"`
	SignatureIndex int        `json:"signatureIndex"`
}

// CalculateDigestRequest asks SignAPI to compute the data-to-be-signed for a set
// of sessions using the given signing certificate (base64-DER).
//
// - SignAsPdf ← signatureFormat == PAdES
// - CreateNewEdoc ← the format/operation matrix (a new ASiC-E container vs.
// adding a parallel signature into an existing one). "edoc" ≡ ASiC-E.
type CalculateDigestRequest struct {
	Sessions      []SessionRef `json:"sessions"`
	Certificate   string       `json:"certificate"`
	SignAsPdf     bool         `json:"signAsPdf"`
	CreateNewEdoc bool         `json:"createNewEdoc"`
}

// DigestResult is the per-session output of CalculateDigest. Treat Digest,
// DigestsSummary, Algorithm and SignatureAlgorithm as opaque — echo them back
// verbatim (SCAL2).
type DigestResult struct {
	SessionID          string `json:"sessionId"`
	Digest             string `json:"digest"`
	DigestsSummary     string `json:"digests_summary"`
	Algorithm          string `json:"algorithm"`
	SignatureAlgorithm string `json:"signature_algorithm"`
}

// calculateDigestResponse matches the LIVE SignAPI shape (verified trace from
// the Entrust mobile flow): `data` is an object holding
// sessionDigests[] (per session) plus the shared digests_summary / algorithm /
// signature_algorithm. CalculateDigest flattens it into []DigestResult.
type calculateDigestResponse struct {
	Data struct {
		SessionDigests []struct {
			SessionID string `json:"sessionId"`
			Digest    string `json:"digest"`
		} `json:"sessionDigests"`
		DigestsSummary     string `json:"digests_summary"`
		Algorithm          string `json:"algorithm"`
		SignatureAlgorithm string `json:"signature_algorithm"`
	} `json:"data"`
}

// SessionSignatureValue pairs a session with its (DER-normalized) signature
// value for finalizeSigning.
type SessionSignatureValue struct {
	SessionID      string `json:"sessionId"`
	SignatureValue string `json:"signatureValue"`
}

// FinalizeRequest finalizes one or more sessions into B-LT containers using the
// person's authentication certificate (base64-DER).
type FinalizeRequest struct {
	SessionSignatureValues []SessionSignatureValue `json:"sessionSignatureValues"`
	AuthCertificate        string                  `json:"authCertificate"`
}

// addArchiveRequest adds an ARCHIVE_TIMESTAMP to the already-signed document(s) in
// the given session(s), authenticated with the end-user's auth certificate
// (base64-DER) — the TSA client identifier, exactly as for finalize. B-LT → B-LTA.
type addArchiveRequest struct {
	Sessions        []SessionRef `json:"sessions"`
	AuthCertificate string       `json:"authCertificate"`
}

// FileInfo is one entry of the api-storage list response.
type FileInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Size int64  `json:"size,omitempty"`
}

type listResponse struct {
	Data []FileInfo `json:"data"`
}
