package entrust

import (
	"errors"
	"testing"

	"github.com/go-quicktest/qt"
)

// ident is a terse SignIdentity constructor for the selection tests.
func ident(id, desc, status string, labels []string, access ...AccessEntry) SignIdentity {
	return SignIdentity{
		ID:          id,
		Description: desc,
		Status:      IdentityStatus{Value: status},
		Labels:      labels,
		Access:      access,
	}
}

func TestEnabled(t *testing.T) {
	qt.Check(t, qt.IsTrue(ident("", "", "enabled", nil).Enabled()))
	qt.Check(t, qt.IsTrue(ident("", "", "ENABLED", nil).Enabled()))
	qt.Check(t, qt.IsFalse(ident("", "", "disabled", nil).Enabled()))
	qt.Check(t, qt.IsFalse(ident("", "", "", nil).Enabled()))
}

func TestHasLabel(t *testing.T) {
	labels := []string{"serverid", "x509:keyUsage:contentCommitment"}
	qt.Check(t, qt.IsTrue(hasLabel(labels, "serverid", "x509:keyUsage:contentCommitment")))
	// Case-insensitive.
	qt.Check(t, qt.IsTrue(hasLabel(labels, "ServerID")))
	// Missing one of the wanted labels.
	qt.Check(t, qt.IsFalse(hasLabel(labels, "serverid", "mobileid")))
	// Empty want set is vacuously true.
	qt.Check(t, qt.IsTrue(hasLabel(labels)))
}

func TestHasAccess(t *testing.T) {
	// Missing access array is treated permissively.
	qt.Check(t, qt.IsTrue(hasAccess(ident("", "", "enabled", nil), "sign")))
	withSign := ident("", "", "enabled", nil, AccessEntry{Permissions: []string{"read", "sign"}})
	qt.Check(t, qt.IsTrue(hasAccess(withSign, "sign")))
	qt.Check(t, qt.IsTrue(hasAccess(withSign, "SIGN"))) // case-insensitive
	readOnly := ident("", "", "enabled", nil, AccessEntry{Permissions: []string{"read"}})
	qt.Check(t, qt.IsFalse(hasAccess(readOnly, "sign")))
}

func TestSelectMobileSigning(t *testing.T) {
	want := ident("srv-1", "", "enabled",
		[]string{labelServerID, labelContentCommitment},
		AccessEntry{Permissions: []string{"sign"}})
	got, err := SelectMobileSigning([]SignIdentity{
		ident("other", "", "enabled", []string{labelEID}),
		want,
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.ID, "srv-1"))

	// A disabled serverid identity does not match.
	_, err = SelectMobileSigning([]SignIdentity{
		ident("srv-2", "", "disabled", []string{labelServerID, labelContentCommitment}),
	})
	qt.Assert(t, qt.IsNotNil(err))
	var nf ErrIdentityNotFound
	qt.Check(t, qt.IsTrue(errors.As(err, &nf)))
}

func TestSelectEIDScanSigning(t *testing.T) {
	// Matched by description.
	got, err := SelectEIDScanSigning([]SignIdentity{ident("eid-1", descEIDSign, "enabled", nil)})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.ID, "eid-1"))

	// Matched by labels.
	got, err = SelectEIDScanSigning([]SignIdentity{
		ident("eid-2", "", "enabled", []string{labelEID, labelContentCommitment}),
	})
	qt.Assert(t, qt.IsNil(err))
	qt.Check(t, qt.Equals(got.ID, "eid-2"))

	_, err = SelectEIDScanSigning([]SignIdentity{ident("nope", "", "enabled", []string{labelServerID})})
	qt.Assert(t, qt.IsNotNil(err))
}

func TestSelectSealSigning(t *testing.T) {
	seal1 := ident("seal-1", "", "enabled", []string{labelQSealC, "CN:Acme : eZīmogs"})
	seal2 := ident("seal-2", "", "enabled", []string{labelESealC, "CN:Beta : eZīmogs"})

	t.Run("none", func(t *testing.T) {
		_, err := SelectSealSigning([]SignIdentity{ident("x", "", "enabled", []string{labelEID})}, "")
		qt.Assert(t, qt.IsNotNil(err))
	})
	t.Run("single, no sealID", func(t *testing.T) {
		got, err := SelectSealSigning([]SignIdentity{seal1}, "")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.ID, "seal-1"))
	})
	t.Run("ambiguous", func(t *testing.T) {
		_, err := SelectSealSigning([]SignIdentity{seal1, seal2}, "")
		var amb ErrSealAmbiguous
		qt.Assert(t, qt.IsTrue(errors.As(err, &amb)))
		qt.Check(t, qt.Equals(len(amb.Candidates), 2))
		qt.Check(t, qt.Equals(amb.Candidates[0].Label, "CN:Acme : eZīmogs"))
	})
	t.Run("sealID picks one", func(t *testing.T) {
		got, err := SelectSealSigning([]SignIdentity{seal1, seal2}, "seal-2")
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.ID, "seal-2"))
	})
	t.Run("sealID no match", func(t *testing.T) {
		_, err := SelectSealSigning([]SignIdentity{seal1, seal2}, "seal-9")
		qt.Assert(t, qt.IsNotNil(err))
	})
}

func TestSelectAuthIdentity(t *testing.T) {
	t.Run("mobile primary by description", func(t *testing.T) {
		got, err := SelectAuthIdentity([]SignIdentity{ident("a", descMobileIDAuth, "enabled", nil)}, false)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.ID, "a"))
	})
	t.Run("eidScan primary by label", func(t *testing.T) {
		got, err := SelectAuthIdentity([]SignIdentity{
			ident("b", "", "enabled", []string{labelEID, labelDigitalSignature}),
		}, true)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.ID, "b"))
	})
	t.Run("fallback to other auth identity", func(t *testing.T) {
		// eidScan=false ⇒ primary is mobileid:auth; only an eid:auth is present, so
		// the fallback loop must accept it.
		got, err := SelectAuthIdentity([]SignIdentity{ident("c", descEIDAuth, "enabled", nil)}, false)
		qt.Assert(t, qt.IsNil(err))
		qt.Check(t, qt.Equals(got.ID, "c"))
	})
	t.Run("not found", func(t *testing.T) {
		_, err := SelectAuthIdentity([]SignIdentity{ident("d", "", "enabled", []string{labelServerID})}, false)
		var nf ErrIdentityNotFound
		qt.Assert(t, qt.IsTrue(errors.As(err, &nf)))
		qt.Check(t, qt.Equals(nf.Purpose, "auth"))
	})
}

func TestCNLabel(t *testing.T) {
	qt.Check(t, qt.Equals(cnLabel([]string{"qsealc", "CN:Acme : eZīmogs"}), "CN:Acme : eZīmogs"))
	// No CN label ⇒ joined labels.
	qt.Check(t, qt.Equals(cnLabel([]string{"qsealc", "x509"}), "qsealc,x509"))
}

func TestErrorMessages(t *testing.T) {
	qt.Check(t, qt.Equals(ErrIdentityNotFound{Purpose: "auth"}.Error(), "signing: identity not found: auth"))
	qt.Check(t, qt.Equals(
		ErrSealAmbiguous{Candidates: []SealCandidate{{}, {}}}.Error(),
		"signing: seal ambiguous (2 candidates)"))
}
