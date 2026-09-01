package eparakstssigner

import (
	"testing"
	"time"

	"github.com/go-quicktest/qt"
)

func TestCallbackPath(t *testing.T) {
	t.Run("empty redirect uses default", func(t *testing.T) {
		c := &Configuration{}
		qt.Check(t, qt.Equals(c.CallbackPath(), DefaultCallbackPath))
	})
	t.Run("derived from redirect path", func(t *testing.T) {
		c := &Configuration{TXRedirectURI: "https://host/Sign/Complete"}
		qt.Check(t, qt.Equals(c.CallbackPath(), "/Sign/Complete"))
	})
	t.Run("redirect without path uses default", func(t *testing.T) {
		c := &Configuration{TXRedirectURI: "https://host"}
		qt.Check(t, qt.Equals(c.CallbackPath(), DefaultCallbackPath))
	})
	t.Run("unparseable redirect uses default", func(t *testing.T) {
		c := &Configuration{TXRedirectURI: "://no-scheme"}
		qt.Check(t, qt.Equals(c.CallbackPath(), DefaultCallbackPath))
	})
}

func TestAccessAuditEnabled(t *testing.T) {
	qt.Check(t, qt.IsFalse((&Configuration{}).AccessAuditEnabled()))
	qt.Check(t, qt.IsFalse((&Configuration{AccessAuditURL: "   "}).AccessAuditEnabled()))
	qt.Check(t, qt.IsTrue((&Configuration{AccessAuditURL: "https://access-audit"}).AccessAuditEnabled()))
}

func TestPseudonymKeyBytes(t *testing.T) {
	c := &Configuration{PseudonymKey: "secret"}
	qt.Check(t, qt.DeepEquals(c.PseudonymKeyBytes(), []byte("secret")))
}

func TestEntrustConfigMapping(t *testing.T) {
	c := &Configuration{
		TXBaseURL:            "https://tx",
		TXASPath:             "/as",
		TXClientID:           "tx-cid",
		TXClientSecret:       "tx-secret",
		TXRedirectURI:        "https://signer/cb",
		TXACRMobile:          "acr-m",
		TXACREIDScan:         "acr-e",
		TXACRCloudEseal:      "acr-c",
		CSCBaseURL:           "https://csc",
		CSCClientID:          "csc-cid",
		CSCClientSecret:      "csc-secret",
		IdentityFetchRetries: 7,
		IdentityFetchDelay:   3 * time.Second,
	}
	ec := c.EntrustConfig()
	qt.Check(t, qt.Equals(ec.BaseURL, "https://tx"))
	qt.Check(t, qt.Equals(ec.ClientID, "tx-cid"))
	qt.Check(t, qt.Equals(ec.RedirectURI, "https://signer/cb"))
	qt.Check(t, qt.Equals(ec.CSCClientID, "csc-cid"))
	qt.Check(t, qt.Equals(ec.ACREIDScan, "acr-e"))
	qt.Check(t, qt.Equals(ec.IdentityFetchRetries, 7))
	qt.Check(t, qt.Equals(ec.IdentityFetchDelay, 3*time.Second))
}

func TestOrchestratorConfigMapping(t *testing.T) {
	c := &Configuration{
		DefaultSignatureQualifier: "eu_eidas_qes",
		EIDScanPollInterval:       time.Second,
		EIDScanDeadline:           90 * time.Second,
		CSCAuthCert:               "base64-cert",
	}
	oc := c.OrchestratorConfig()
	qt.Check(t, qt.Equals(oc.DefaultSignatureQualifier, "eu_eidas_qes"))
	qt.Check(t, qt.Equals(oc.EIDScanPollInterval, time.Second))
	qt.Check(t, qt.Equals(oc.EIDScanDeadline, 90*time.Second))
	qt.Check(t, qt.Equals(oc.CSCAuthCert, "base64-cert"))
}

func TestNewConfiguration(t *testing.T) {
	c := NewConfiguration()
	qt.Assert(t, qt.IsNotNil(c))
	qt.Check(t, qt.IsNotNil(c.BaseConfiguration))
}
