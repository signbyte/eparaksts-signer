package entrust

import (
	"fmt"
	"strings"
)

// Label / description fragments used for sign-identity selection.
const (
	labelServerID          = "serverid"
	labelEID               = "eid"
	labelMobileID          = "mobileid"
	labelQSealC            = "qsealc"
	labelESealC            = "esealc" // official guidance lists this in one place — match defensively
	labelContentCommitment = "x509:keyUsage:contentCommitment"
	labelDigitalSignature  = "x509:keyUsage:digitalSignature"

	descEIDSign      = "eparaksts:eid:sign"
	descEIDAuth      = "eparaksts:eid:auth"
	descMobileIDAuth = "eparaksts:mobileid:auth"
)

// statusEnabled is the active identity status.
const statusEnabled = "enabled"

// ErrIdentityNotFound is returned when the required sign/auth identity is absent.
type ErrIdentityNotFound struct{ Purpose string }

func (e ErrIdentityNotFound) Error() string {
	return "signing: identity not found: " + e.Purpose
}

// SealCandidate is a {id, CN-label} pair offered to the portal seal picker.
type SealCandidate struct {
	ID    string `json:"id"`
	Label string `json:"label"`
}

// ErrSealAmbiguous is returned when several qsealc identities match and no sealId
// was supplied — the portal must let the user pick one.
type ErrSealAmbiguous struct{ Candidates []SealCandidate }

func (e ErrSealAmbiguous) Error() string {
	return fmt.Sprintf("signing: seal ambiguous (%d candidates)", len(e.Candidates))
}

// hasAccess reports whether the identity grants the given access (e.g. "sign").
// A missing access array is treated permissively (some traces omit it) — the
// server enforces the grant on the actual sign call regardless.
func hasAccess(id SignIdentity, access string) bool {
	if len(id.Access) == 0 {
		return true
	}
	for _, e := range id.Access {
		for _, p := range e.Permissions {
			if strings.EqualFold(p, access) {
				return true
			}
		}
	}
	return false
}

// SelectMobileSigning selects the serverid signing identity (mobile).
func SelectMobileSigning(ids []SignIdentity) (SignIdentity, error) {
	for _, id := range ids {
		if hasLabel(id.Labels, labelServerID, labelContentCommitment) &&
			id.Enabled() && hasAccess(id, "sign") {
			return id, nil
		}
	}
	return SignIdentity{}, ErrIdentityNotFound{Purpose: "mobile:serverid:sign"}
}

// SelectEIDScanSigning selects the eid:sign signing identity (eidScan).
func SelectEIDScanSigning(ids []SignIdentity) (SignIdentity, error) {
	for _, id := range ids {
		if strings.EqualFold(id.Description, descEIDSign) ||
			(hasLabel(id.Labels, labelEID, labelContentCommitment) && id.Enabled()) {
			return id, nil
		}
	}
	return SignIdentity{}, ErrIdentityNotFound{Purpose: "eidScan:eid:sign"}
}

// SelectSealSigning selects the qsealc seal identity (cloudEseal). sealId, when
// given, picks a specific seal (the qsealc sign-identity id); otherwise a single
// enabled match is used, and several matches yield ErrSealAmbiguous.
func SelectSealSigning(ids []SignIdentity, sealID string) (SignIdentity, error) {
	var seals []SignIdentity
	for _, id := range ids {
		if (hasLabel(id.Labels, labelQSealC) || hasLabel(id.Labels, labelESealC)) &&
			id.Enabled() {
			seals = append(seals, id)
		}
	}
	switch {
	case len(seals) == 0:
		return SignIdentity{}, ErrIdentityNotFound{Purpose: "cloudEseal:qsealc"}
	case sealID != "":
		for _, s := range seals {
			if s.ID == sealID {
				return s, nil
			}
		}
		return SignIdentity{}, ErrIdentityNotFound{Purpose: "cloudEseal:qsealc:" + sealID}
	case len(seals) == 1:
		return seals[0], nil
	default:
		cands := make([]SealCandidate, 0, len(seals))
		for _, s := range seals {
			cands = append(cands, SealCandidate{ID: s.ID, Label: cnLabel(s.Labels)})
		}
		return SignIdentity{}, ErrSealAmbiguous{Candidates: cands}
	}
}

// SelectAuthIdentity selects the person's authentication identity whose cert is
// used as the SignAPI finalize authCertificate. mobile/cloudEseal use the
// mobileid:auth identity; eidScan uses eid:auth. Finalize tolerates either, so a
// missing primary falls back to whichever auth identity is present.
func SelectAuthIdentity(ids []SignIdentity, eidScan bool) (SignIdentity, error) {
	primaryDesc, primaryLabel := descMobileIDAuth, labelMobileID
	if eidScan {
		primaryDesc, primaryLabel = descEIDAuth, labelEID
	}
	for _, id := range ids {
		if strings.EqualFold(id.Description, primaryDesc) ||
			hasLabel(id.Labels, primaryLabel, labelDigitalSignature) {
			return id, nil
		}
	}
	// Fallback: any auth identity (finalize accepts mobileid:auth or eid:auth).
	for _, id := range ids {
		if strings.EqualFold(id.Description, descMobileIDAuth) ||
			strings.EqualFold(id.Description, descEIDAuth) ||
			hasLabel(id.Labels, labelDigitalSignature) {
			return id, nil
		}
	}
	return SignIdentity{}, ErrIdentityNotFound{Purpose: "auth"}
}

// cnLabel returns the dynamic "CN:<name> : eZīmogs" label of a seal identity, or
// the joined labels when no CN label is present.
func cnLabel(labels []string) string {
	for _, l := range labels {
		if strings.HasPrefix(strings.ToUpper(l), "CN:") {
			return l
		}
	}
	return strings.Join(labels, ",")
}
