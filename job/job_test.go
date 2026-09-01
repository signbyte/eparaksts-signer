package job

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

// TestFlowValid checks the known flows are accepted and everything else
// (including case variants) is rejected.
func TestFlowValid(t *testing.T) {
	for _, f := range []Flow{FlowCSC, FlowWebEID, FlowEParakstsMobile, FlowEIDScan, FlowEParakstsMobileEseal} {
		t.Run("valid/"+string(f), func(t *testing.T) {
			qt.Check(t, qt.IsTrue(f.Valid()))
		})
	}
	for _, f := range []Flow{"", "CSC", "eidscan", "EID", "bogus"} {
		t.Run("invalid/"+string(f), func(t *testing.T) {
			qt.Check(t, qt.IsFalse(f.Valid()))
		})
	}
}

// TestStateTerminal checks only READY and FAILED are terminal.
func TestStateTerminal(t *testing.T) {
	terminal := map[State]bool{StateReady: true, StateFailed: true}
	all := []State{
		StatePreparing, StateAwaitingAuthorization, StateAwaitingClientSig,
		StateSigning, StateFinalizing, StateReady, StateFailed,
	}
	for _, s := range all {
		t.Run(string(s), func(t *testing.T) {
			qt.Check(t, qt.Equals(s.Terminal(), terminal[s]))
		})
	}
}

// TestCanTransition exercises the full state-machine matrix: every allowed edge,
// the same-state identity rule, and a representative set of rejected edges.
func TestCanTransition(t *testing.T) {
	allowed := map[State][]State{
		StatePreparing:             {StateAwaitingAuthorization, StateAwaitingClientSig, StateFailed},
		StateAwaitingAuthorization: {StateSigning, StateFailed},
		StateAwaitingClientSig:     {StateFinalizing, StateFailed},
		StateSigning:               {StateFinalizing, StateFailed},
		StateFinalizing:            {StateReady, StateFailed},
	}
	all := []State{
		StatePreparing, StateAwaitingAuthorization, StateAwaitingClientSig,
		StateSigning, StateFinalizing, StateReady, StateFailed,
	}

	allow := func(from, to State) bool {
		for _, t := range allowed[from] {
			if t == to {
				return true
			}
		}
		return false
	}

	for _, from := range all {
		for _, to := range all {
			from, to := from, to
			t.Run(string(from)+"->"+string(to), func(t *testing.T) {
				want := from == to || allow(from, to)
				qt.Check(t, qt.Equals(CanTransition(from, to), want))
			})
		}
	}
}

// TestTransitionValid moves through a legal edge and confirms the state changes
// and UpdatedAt is stamped.
func TestTransitionValid(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC()
	j := &Job{State: StatePreparing, UpdatedAt: past}

	ok := j.Transition(StateAwaitingClientSig)
	qt.Assert(t, qt.IsTrue(ok))
	qt.Check(t, qt.Equals(j.State, StateAwaitingClientSig))
	qt.Check(t, qt.IsTrue(j.UpdatedAt.After(past)))
}

// TestTransitionInvalid rejects an illegal edge and leaves state + UpdatedAt
// untouched.
func TestTransitionInvalid(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC()
	j := &Job{State: StatePreparing, UpdatedAt: past}

	ok := j.Transition(StateSigning) // PREPARING cannot go straight to SIGNING
	qt.Assert(t, qt.IsFalse(ok))
	qt.Check(t, qt.Equals(j.State, StatePreparing))
	qt.Check(t, qt.IsTrue(j.UpdatedAt.Equal(past)))
}

// TestTransitionSameState is always allowed and is idempotent on the state.
func TestTransitionSameState(t *testing.T) {
	j := &Job{State: StateSigning}
	qt.Assert(t, qt.IsTrue(j.Transition(StateSigning)))
	qt.Check(t, qt.Equals(j.State, StateSigning))
}

// TestFail moves the job to FAILED, records the job error, fails every
// not-yet-ready document (without clobbering a doc that already has an error),
// and leaves READY documents alone.
func TestFail(t *testing.T) {
	past := time.Now().Add(-time.Hour).UTC()
	j := &Job{
		State:     StateSigning,
		UpdatedAt: past,
		Documents: []Document{
			{DocumentID: "pending", State: DocPending},
			{DocumentID: "ready", State: DocReady},
			{DocumentID: "pre-failed", State: DocPending, Error: &Error{Code: "orig", Message: "earlier"}},
		},
	}

	j.Fail("signing:boom", "it broke")

	qt.Assert(t, qt.Equals(j.State, StateFailed))
	qt.Assert(t, qt.IsNotNil(j.Err))
	qt.Check(t, qt.Equals(j.Err.Code, "signing:boom"))
	qt.Check(t, qt.IsTrue(j.UpdatedAt.After(past)))

	// pending → failed, error filled from the job error.
	pending := j.Doc("pending")
	qt.Assert(t, qt.IsNotNil(pending))
	qt.Check(t, qt.Equals(pending.State, DocFailed))
	qt.Assert(t, qt.IsNotNil(pending.Error))
	qt.Check(t, qt.Equals(pending.Error.Code, "signing:boom"))

	// ready stays ready and keeps no error.
	ready := j.Doc("ready")
	qt.Assert(t, qt.IsNotNil(ready))
	qt.Check(t, qt.Equals(ready.State, DocReady))
	qt.Check(t, qt.IsNil(ready.Error))

	// pre-failed → failed but the original error is preserved.
	pre := j.Doc("pre-failed")
	qt.Assert(t, qt.IsNotNil(pre))
	qt.Check(t, qt.Equals(pre.State, DocFailed))
	qt.Assert(t, qt.IsNotNil(pre.Error))
	qt.Check(t, qt.Equals(pre.Error.Code, "orig"))
}

// TestDoc finds a document by id and returns nil for an unknown id.
func TestDoc(t *testing.T) {
	j := &Job{Documents: []Document{{DocumentID: "a"}, {DocumentID: "b"}}}

	qt.Check(t, qt.IsNotNil(j.Doc("a")))
	qt.Check(t, qt.Equals(j.Doc("b").DocumentID, "b"))
	qt.Check(t, qt.IsNil(j.Doc("missing")))

	empty := &Job{}
	qt.Check(t, qt.IsNil(empty.Doc("a")))
}
