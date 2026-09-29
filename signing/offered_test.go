package signing

import (
	"errors"
	"testing"

	"azugo.io/azugo"
	"github.com/go-quicktest/qt"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/entrust"
	"github.com/signbyte/eparaksts-signer/job"
)

// What the deployment says it offers and what prepare accepts are one answer: a
// flow missing from the list is refused, with or without a CSC client.
func TestOfferedFlowsAgreeWithPrepare(t *testing.T) {
	for name, cfg := range map[string]entrust.Config{
		"no CSC client":   {},
		"with CSC client": {CSCClientID: "the-csc-client"},
	} {
		t.Run(name, func(t *testing.T) {
			o := New(nil, nil, entrust.New(cfg, zap.NewNop()), Config{}, nil)
			offered := map[job.Flow]bool{}
			for _, f := range o.OfferedFlows() {
				offered[f] = true
			}
			for _, f := range job.Flows() {
				qt.Check(t, qt.Equals(o.Offered(f), offered[f]), qt.Commentf("%s", f))
				wantCSC := cfg.CSCClientID != ""
				if f.IsCSC() {
					qt.Check(t, qt.Equals(offered[f], wantCSC), qt.Commentf("%s", f))
				} else {
					qt.Check(t, qt.IsTrue(offered[f]), qt.Commentf("%s", f))
				}
				if offered[f] {
					continue
				}
				_, err := o.Prepare(&azugo.Context{}, PrepareInput{
					Flow: f, Documents: []InputDocument{{DocumentID: "d1", Format: job.FormatXAdES}},
				})
				qt.Check(t, qt.IsTrue(errors.Is(err, ErrCSCNotEnabled)), qt.Commentf("%s: %v", f, err))
			}
			qt.Check(t, qt.IsFalse(o.Offered(job.Flow("csc"))))
		})
	}
}
