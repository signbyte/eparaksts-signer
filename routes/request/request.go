// Package request holds the inbound request DTOs for the eParaksts Signing
// Service API.
package request

import "azugo.io/azugo"

// PrepareDocument is one document of a prepare batch. Bytes mode supplies FileRef
// (the multipart part name holding the bytes); hash mode supplies DocumentHash
// (confidential, no bytes); a container being co-signed supplies Files (its inner
// data objects, signed together under one signature).
type PrepareDocument struct {
	DocumentID      string `json:"documentId" validate:"required"`
	FileRef         string `json:"fileRef"`
	DocumentHash    string `json:"documentHash"`
	DigestAlgorithm string `json:"digestAlgorithm"`
	FileName        string `json:"fileName" validate:"required"`
	MimeType        string `json:"mimeType"`
	SignatureFormat string `json:"signatureFormat" validate:"required,oneof=PAdES XAdES"`
	Operation       string `json:"operation" validate:"omitempty,oneof=create parallel"`
	// Files carries the inner data objects when the document is an ASiC-E container
	// being co-signed (hash-only, all registered under one signature).
	Files []PrepareFile `json:"files" validate:"omitempty,dive"`
}

// PrepareFile is one inner data object of a container being co-signed: the
// in-container filename and its digest.
type PrepareFile struct {
	Name            string `json:"name" validate:"required"`
	Digest          string `json:"digest" validate:"required"`
	DigestAlgorithm string `json:"digestAlgorithm"`
}

// PrepareMetadata is the JSON metadata part of a prepare request (the `metadata`
// multipart part, or the whole JSON body in hash-only mode).
type PrepareMetadata struct {
	Documents          []PrepareDocument `json:"documents" validate:"required,min=1,dive"`
	SignatureQualifier string            `json:"signatureQualifier"`
	SigningCertificate string            `json:"signingCertificate"` // REQUIRED for eid (card SIGNING cert → CalculateDigest); optional for remote flows (a login-captured identity cert)
	AuthCertificate    string            `json:"authCertificate"`    // eid: the card AUTH cert → SignAPI finalize authCertificate (TSA access); optional for remote flows
	SignIdentityID     string            `json:"signIdentityId"`     // remote flows: the sign identity the supplied certs belong to — with both certs, skips the identity-resolution leg
	SealID             string            `json:"sealId"`             // seal selector (the e-seal flow)
	PostAuthRedirect   string            `json:"postAuthRedirect"`
	AuthErrorRedirect  string            `json:"authErrorRedirect"`
	Locale             string            `json:"locale"`
}

// Validate implements azugo.Validator.
func (m *PrepareMetadata) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(m)
}

// SubmitSignature is one client-side signature value (eid).
type SubmitSignature struct {
	DocumentID     string `json:"documentId" validate:"required"`
	SignatureValue string `json:"signatureValue" validate:"required"`
}

// SubmitSignatures is the body of the eid client-signature submit endpoint.
type SubmitSignatures struct {
	Signatures []SubmitSignature `json:"signatures" validate:"required,min=1,dive"`
}

// Validate implements azugo.Validator.
func (s *SubmitSignatures) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(s)
}
