package entrust

import (
	"encoding/json"
	"strings"
	"testing"
)

// TestCSCSignHashRequest_UsesHashesField pins the CSC v2 wire contract: the
// signatures/signHash body field is "hashes" ([CSC API V2.2.0.0 §11.13]), not the
// CSC v1 "hash". The hash-sign mock accepts both, so only this test (and the real
// LVRTC/Entrust platform) catches a regression to the v1 field name.
func TestCSCSignHashRequest_UsesHashesField(t *testing.T) {
	b, err := json.Marshal(cscSignHashRequest{
		CredentialID: "cred-1",
		Hashes:       []string{"aGFzaDE=", "aGFzaDI="},
		SignAlgo:     "1.2.840.10045.4.3.2",
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	got := string(b)

	if !strings.Contains(got, `"hashes":[`) {
		t.Errorf("CSC v2 signHash body must carry the \"hashes\" array; got: %s", got)
	}
	// Guard against a regression to the CSC v1 "hash" key. ("hashes": does not
	// contain the substring "hash": so this match is unambiguous.)
	if strings.Contains(got, `"hash":`) {
		t.Errorf("CSC v1 \"hash\" field must not be present (CSC v2 §11.13); got: %s", got)
	}
}
