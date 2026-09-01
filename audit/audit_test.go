package audit

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/go-quicktest/qt"

	"github.com/gmb-lib/go-eidas-audit/eidas"

	"github.com/signbyte/eparaksts-signer/job"
)

func TestNewPseudonymizerRejectsEmptyKey(t *testing.T) {
	_, err := NewPseudonymizer(nil)
	qt.Check(t, qt.IsNotNil(err))
	_, err = NewPseudonymizer([]byte{})
	qt.Check(t, qt.IsNotNil(err))
}

// TestPseudonymizerCopiesKey confirms the key is copied, so mutating the caller's
// slice afterwards does not change subsequent refs.
func TestPseudonymizerCopiesKey(t *testing.T) {
	key := []byte("super-secret-key")
	p, err := NewPseudonymizer(key)
	qt.Assert(t, qt.IsNil(err))

	id := testIDCode()
	before := p.Ref(id)
	for i := range key { // mutate the original slice
		key[i] = 'x'
	}
	after := p.Ref(id)
	qt.Check(t, qt.Equals(before, after))
}

// TestPseudonymizerRef checks the ref is the "psn:" prefixed hex HMAC-SHA256 of
// the id, is deterministic, and empties on nil/empty input.
func TestPseudonymizerRef(t *testing.T) {
	key := []byte("k")
	p, err := NewPseudonymizer(key)
	qt.Assert(t, qt.IsNil(err))

	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("id-1"))
	want := "psn:" + hex.EncodeToString(mac.Sum(nil))
	qt.Check(t, qt.Equals(p.Ref("id-1"), want))

	// Deterministic + distinct.
	qt.Check(t, qt.Equals(p.Ref("id-1"), p.Ref("id-1")))
	qt.Check(t, qt.IsFalse(p.Ref("id-1") == p.Ref("id-2")))

	// Empty id and nil pseudonymizer return "".
	qt.Check(t, qt.Equals(p.Ref(""), ""))
	var nilP *Pseudonymizer
	qt.Check(t, qt.Equals(nilP.Ref("id-1"), ""))
}

// TestPseudonymizerDifferentKeys confirms the key actually salts the output.
func TestPseudonymizerDifferentKeys(t *testing.T) {
	p1, _ := NewPseudonymizer([]byte("key-one"))
	p2, _ := NewPseudonymizer([]byte("key-two"))
	qt.Check(t, qt.IsFalse(p1.Ref("id") == p2.Ref("id")))
}

func TestLevelForFlow(t *testing.T) {
	qt.Check(t, qt.Equals(levelForFlow(job.FlowEParakstsMobileEseal), eidas.LevelSeal))
	qt.Check(t, qt.Equals(levelForFlow(job.FlowWebEID), eidas.LevelQES))
	qt.Check(t, qt.Equals(levelForFlow(job.FlowEParakstsMobile), eidas.LevelQES))
}

func TestFormatOf(t *testing.T) {
	qt.Check(t, qt.Equals(formatOf(job.FormatPAdES), eidas.FormatPAdES))
	qt.Check(t, qt.Equals(formatOf(job.FormatXAdES), eidas.FormatXAdES))
}

func TestInputType(t *testing.T) {
	qt.Check(t, qt.Equals(inputType(&job.Job{}), eidas.InputFile))
	qt.Check(t, qt.Equals(inputType(&job.Job{Documents: []job.Document{{HashOnly: true}}}), eidas.InputHash))
	qt.Check(t, qt.Equals(inputType(&job.Job{Documents: []job.Document{{Format: job.FormatPAdES}}}), eidas.InputPDF))
	qt.Check(t, qt.Equals(inputType(&job.Job{Documents: []job.Document{{Format: job.FormatXAdES}}}), eidas.InputFile))
}

func TestRefOf(t *testing.T) {
	qt.Check(t, qt.Equals(refOf("0123456789abcdef"), "0123456789ab")) // truncated to 12
	qt.Check(t, qt.Equals(refOf("short"), "short"))
	qt.Check(t, qt.Equals(refOf(""), ""))
}

// TestRecorderNilSafe confirms a Recorder with no emitters wired (GDPR-audit / NIS2-audit off)
// and a nil *Recorder both no-op rather than panic — the documented "optional"
// behaviour. A nil request context is fine because every method guards before it
// would be dereferenced.
func TestRecorderNilSafe(t *testing.T) {
	j := &job.Job{
		JobID:     "j1",
		Caller:    "svc:test",
		Flow:      job.FlowWebEID,
		Documents: []job.Document{{DocumentID: "d1", State: job.DocReady, Format: job.FormatXAdES}},
	}

	exercise := func(r *Recorder) {
		r.Initiated(nil, j)
		r.Redirect(nil, j)
		r.Callback(nil, j, true)
		r.Callback(nil, j, false)
		r.Applied(nil, j)
		r.Failed(nil, j)
		r.SignerAccessed(nil, "svc:test", "PNOLV-1")
		r.PrepareOutcome(nil, "svc:test", true)
		r.Denied(nil, "svc:test", "signatures:create")
	}

	// All emitters nil (GDPR-audit / NIS2-audit not configured).
	exercise(New(nil, nil, nil, nil, nil))
	// Nil receiver.
	exercise((*Recorder)(nil))
}
