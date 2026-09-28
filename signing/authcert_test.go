package signing

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/VictoriaMetrics/metrics"
	"go.uber.org/zap"

	"github.com/signbyte/eparaksts-signer/job"
)

func TestParseFlowSetSelectsOnlyTheNamedFlows(t *testing.T) {
	set := ParseFlowSet("cscEidScan, webEid")

	for _, f := range []job.Flow{job.FlowCSCEidScan, job.FlowWebEID} {
		if !set.Has(f) {
			t.Errorf("Has(%q) = false, want true", f)
		}
	}
	for _, f := range []job.Flow{job.FlowEParakstsMobile, job.FlowEIDScan, job.FlowEParakstsMobileEseal} {
		if set.Has(f) {
			t.Errorf("Has(%q) = true, want false — it was not named", f)
		}
	}
}

func TestParseFlowSetAllSelectsEveryFlow(t *testing.T) {
	set := ParseFlowSet("all")
	for _, name := range KnownFlowNames() {
		if !set.Has(job.Flow(name)) {
			t.Errorf("Has(%q) = false under \"all\"", name)
		}
	}
}

func TestParseFlowSetEmptySelectsNothing(t *testing.T) {
	set := ParseFlowSet("")
	for _, name := range KnownFlowNames() {
		if set.Has(job.Flow(name)) {
			t.Errorf("Has(%q) = true for an empty list", name)
		}
	}
}

func TestDefaultFlowListSelectsNoFlow(t *testing.T) {
	set := ParseFlowSet(DefaultTSAAccessCertFlows)
	for _, f := range []job.Flow{job.FlowWebEID, job.FlowEIDScan, job.FlowEParakstsMobile, job.FlowEParakstsMobileEseal,
		job.FlowCSCEidScan, job.FlowCSCEidPlugin} {
		if set.Has(f) {
			t.Errorf("the default selects %s — by default every flow requests the timestamp with the signer's own login certificate", f)
		}
	}
}

func TestUnknownFlowNamesReportsTyposAndNothingElse(t *testing.T) {
	got := UnknownFlowNames(" all , cscEidScan , webeid , cscc , ")
	// "webeid" differs in case from the flow name and is a typo like any other:
	// the list is matched exactly so a misspelling can never silently select.
	want := map[string]bool{"webeid": true, "cscc": true}
	if len(got) != len(want) {
		t.Fatalf("UnknownFlowNames = %v, want the two unrecognized entries", got)
	}
	for _, name := range got {
		if !want[name] {
			t.Errorf("reported %q, which is a valid flow name or \"all\"", name)
		}
	}
}

// authCertFor is where the whole decision lands, so each branch is asserted
// against a job rather than against the set alone.
func TestAuthCertForPicksTheConfiguredCertificateOnlyForSelectedFlows(t *testing.T) {
	const deploymentCert, signerCert = "deployment-cert", "signer-cert"

	cases := []struct {
		name       string
		flows      string
		flow       job.Flow
		jobCert    string
		wantCert   string
		wantSource CertSource
		wantOK     bool
	}{
		{"selected flow uses the deployment certificate", "webEid", job.FlowWebEID, signerCert, deploymentCert, SourceDeployment, true},
		{"unselected flow uses the signer's own", "cscEidScan", job.FlowWebEID, signerCert, signerCert, SourceSigner, true},
		{"unselected flow with no certificate is refused", "cscEidScan", job.FlowWebEID, "", "", SourceSigner, false},
		{"all selects every flow", "all", job.FlowEIDScan, signerCert, deploymentCert, SourceDeployment, true},
		{"a selected flow needs no signer certificate", "cscEidScan", job.FlowCSCEidScan, "", deploymentCert, SourceDeployment, true},
		{"blank signer certificate is not a certificate", "cscEidScan", job.FlowWebEID, "   ", "", SourceSigner, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := &Orchestrator{cfg: Config{
				TSAAccessCert:      deploymentCert,
				TSAAccessCertFlows: ParseFlowSet(tc.flows),
			}}
			got, source, ok := o.authCertFor(&job.Job{Flow: tc.flow, AuthCert: tc.jobCert})
			if ok != tc.wantOK || got != tc.wantCert || source != tc.wantSource {
				t.Fatalf("authCertFor = (%q, %q, %v), want (%q, %q, %v)",
					got, source, ok, tc.wantCert, tc.wantSource, tc.wantOK)
			}
		})
	}
}

func TestAuthCertForRefusesASelectedFlowWhenNothingIsConfigured(t *testing.T) {
	o := &Orchestrator{cfg: Config{TSAAccessCertFlows: ParseFlowSet("all")}}

	// The signer sent one, but this flow was configured to use the deployment's
	// certificate and there is none: that is a misconfiguration, and silently
	// billing the signer instead would hide it.
	if got, source, ok := o.authCertFor(&job.Job{Flow: job.FlowWebEID, AuthCert: "signer-cert"}); ok {
		t.Fatalf("authCertFor = (%q, %q, true), want a refusal", got, source)
	}
}

// The signing certificate is never a substitute for the authentication one.
// A card signing prepared without an authentication certificate is refused at
// finalize, before any upstream call — it is not quietly finalized with the
// signing certificate, which would request the timestamp against the wrong
// certificate and look correct until it reached a real timestamping service.
func TestFinalizeRefusesRatherThanSubstitutingTheSigningCertificate(t *testing.T) {
	o := newSpineOrchestrator(t, func(http.ResponseWriter, *http.Request) {
		t.Error("the provider was called; the refusal must happen before any upstream traffic")
	})
	o.cfg = Config{TSAAccessCert: "deployment-cert", TSAAccessCertFlows: ParseFlowSet("cscEidScan")}

	j := &job.Job{
		JobID:       "j1",
		Flow:        job.FlowWebEID,
		SigningCert: "signing-cert-that-must-not-be-used",
		AuthCert:    "",
		Documents:   []job.Document{{DocumentID: "d1", SessionID: "s1", SignatureValue: "irrelevant"}},
	}
	if err := o.finalize(context.Background(), j); !errors.Is(err, ErrNoTimestampCert) {
		t.Fatalf("finalize err = %v, want ErrNoTimestampCert", err)
	}
}

// counterValue reads one series out of the metrics registry the service exposes
// at /metrics, so the assertion is on what a scraper would actually see rather
// than on an internal call having happened.
func counterValue(t *testing.T, name string, labels map[string]string) float64 {
	t.Helper()
	var buf bytes.Buffer
	metrics.WritePrometheus(&buf, false)

	keys := make([]string, 0, len(labels))
	for k := range labels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(name)
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		fmt.Fprintf(&b, "%s=%q", k, labels[k])
	}
	b.WriteByte('}')
	want := b.String()

	for _, line := range strings.Split(buf.String(), "\n") {
		series, value, found := strings.Cut(line, " ")
		if !found || series != want {
			continue
		}
		v, err := strconv.ParseFloat(value, 64)
		if err != nil {
			t.Fatalf("metric %s has unparseable value %q", want, value)
		}

		return v
	}

	return 0
}

// The counters are what a deployment reads to know what it owes, and what the
// end-to-end suite will assert, so they are checked as deltas over a baseline —
// the registry is process-wide and other tests share it.
func TestTimestampCountersSeparateWhoPaid(t *testing.T) {
	o := &Orchestrator{log: zap.NewNop(), cfg: Config{
		TSAAccessCert:      "deployment-cert",
		TSAAccessCertFlows: ParseFlowSet("cscEidScan"),
	}}

	paid := map[string]string{"source": "deployment", "flow": "cscEidScan", "op": "sign"}
	free := map[string]string{"source": "signer", "flow": "webEid", "op": "sign"}
	refused := map[string]string{"flow": "webEid", "op": "archive"}

	basePaid := counterValue(t, MetricTimestampRequests, paid)
	baseFree := counterValue(t, MetricTimestampRequests, free)
	baseRefused := counterValue(t, MetricTimestampRefused, refused)

	cert, source, ok := o.authCertFor(&job.Job{JobID: "j1", Flow: job.FlowCSCEidScan})
	if !ok {
		t.Fatal("the configured flow found no certificate")
	}
	o.recordTimestampRequest(&job.Job{JobID: "j1", Flow: job.FlowCSCEidScan}, source, OpSign, cert)

	o.recordTimestampRequest(&job.Job{JobID: "j2", Flow: job.FlowWebEID}, SourceSigner, OpSign, "signer-cert")
	o.recordTimestampRefused(&job.Job{JobID: "j3", Flow: job.FlowWebEID}, OpArchive)

	if got := counterValue(t, MetricTimestampRequests, paid) - basePaid; got != 1 {
		t.Errorf("deployment-paid timestamps moved by %v, want 1", got)
	}
	if got := counterValue(t, MetricTimestampRequests, free) - baseFree; got != 1 {
		t.Errorf("signer-paid timestamps moved by %v, want 1", got)
	}
	if got := counterValue(t, MetricTimestampRefused, refused) - baseRefused; got != 1 {
		t.Errorf("refusals moved by %v, want 1", got)
	}
	// A refusal is not a request: it must not inflate what the deployment owes.
	if got := counterValue(t, MetricTimestampRequests, map[string]string{"source": "deployment", "flow": "webEid", "op": "archive"}); got != 0 {
		t.Errorf("the refused archive was counted as a request (%v)", got)
	}
}

// The fingerprint identifies a configured certificate without carrying it.
func TestCertFingerprintIdentifiesWithoutDisclosing(t *testing.T) {
	a := certFingerprint(base64.StdEncoding.EncodeToString([]byte("certificate-one")))
	b := certFingerprint(base64.StdEncoding.EncodeToString([]byte("certificate-two")))

	if a == b {
		t.Error("two different certificates share a fingerprint")
	}
	if a != certFingerprint(base64.StdEncoding.EncodeToString([]byte("certificate-one"))) {
		t.Error("the same certificate fingerprints differently twice")
	}
	if strings.Contains(a, "certificate") {
		t.Error("the fingerprint carries the certificate")
	}
}
