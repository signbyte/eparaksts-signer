package signing

import (
	"errors"
	"fmt"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
)

// What the deployment says it offers and what prepare accepts are one answer: a
// flow missing from the list is refused, with or without a CSC client, with
// legacyEid switched on or off.
func TestOfferedFlowsAgreeWithPrepare(t *testing.T) {
	for _, csc := range []bool{false, true} {
		for _, legacy := range []bool{false, true} {
			var ecfg entrust.Config
			if csc {
				ecfg.CSCClientID = "the-csc-client"
			}
			t.Run(fmt.Sprintf("csc=%t/legacyEid=%t", csc, legacy), func(t *testing.T) {
				o := New(nil, nil, entrust.New(ecfg, zap.NewNop()), Config{LegacyEIDEnabled: legacy}, nil)
				offered := map[job.Flow]bool{}
				for _, f := range o.OfferedFlows() {
					offered[f] = true
				}
				for _, f := range job.Flows() {
					qt.Check(t, qt.Equals(o.Offered(f), offered[f]), qt.Commentf("%s", f))
					switch {
					case f.IsCSC():
						qt.Check(t, qt.Equals(offered[f], csc), qt.Commentf("%s", f))
					case f == job.FlowLegacyEID:
						qt.Check(t, qt.Equals(offered[f], legacy), qt.Commentf("%s", f))
					default:
						qt.Check(t, qt.IsTrue(offered[f]), qt.Commentf("%s", f))
					}
					if offered[f] {
						continue
					}
					_, err := o.Prepare(&azugo.Context{}, PrepareInput{
						Flow: f, Documents: []InputDocument{{DocumentID: "d1", Format: job.FormatXAdES}},
					})
					want := ErrFlowNotOffered
					if f.IsCSC() {
						want = ErrCSCNotEnabled
					}
					qt.Check(t, qt.IsTrue(errors.Is(err, want)), qt.Commentf("%s: %v", f, err))
				}
				qt.Check(t, qt.IsFalse(o.Offered(job.Flow("csc"))))
			})
		}
	}
}

// legacyEid is off unless the deployment switches it on, and when on it is listed
// right after webEid; every other flow is listed as before.
func TestLegacyEIDOfferedOnlyWhenSwitchedOn(t *testing.T) {
	off := New(nil, nil, entrust.New(entrust.Config{}, zap.NewNop()), Config{}, nil)
	qt.Check(t, qt.DeepEquals(off.OfferedFlows(),
		[]job.Flow{job.FlowWebEID, job.FlowEParakstsMobile, job.FlowEIDScan, job.FlowEParakstsMobileEseal}))

	on := New(nil, nil, entrust.New(entrust.Config{}, zap.NewNop()), Config{LegacyEIDEnabled: true}, nil)
	qt.Check(t, qt.DeepEquals(on.OfferedFlows(),
		[]job.Flow{job.FlowWebEID, job.FlowLegacyEID, job.FlowEParakstsMobile, job.FlowEIDScan, job.FlowEParakstsMobileEseal}))
}

// The two card flows are one strategy under two names: the same client-side
// capabilities, each answering its own name.
func TestLegacyEIDIsTheCardStrategyUnderItsOwnName(t *testing.T) {
	o := New(nil, nil, entrust.New(entrust.Config{}, zap.NewNop()), Config{LegacyEIDEnabled: true}, nil)
	web, legacy := o.Flow(job.FlowWebEID), o.Flow(job.FlowLegacyEID)
	qt.Assert(t, qt.IsNotNil(legacy))
	qt.Check(t, qt.Equals(web.Type(), job.FlowWebEID))
	qt.Check(t, qt.Equals(legacy.Type(), job.FlowLegacyEID))
	qt.Check(t, qt.Equals(legacy.Capabilities(), web.Capabilities()))
	qt.Check(t, qt.IsTrue(legacy.Capabilities().ClientSide))
}
