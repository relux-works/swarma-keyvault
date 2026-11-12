package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
	"strings"
	"testing"
	"time"
)

// Native configuration has one exact canonical representation and a valid
// linked sidecar. This establishes syntax only, never independent pin custody.
// Unknown/duplicate keys, omitted fields, NULL, extra JSON and invalid bindings
// cannot create an alternative selected policy interpretation.
func TestNativeSelectionClosedCanonicalRepresentation(t *testing.T) {
	session, _, _ := newSessionFixture(t)
	config := NativeSelection{Schema: "keyvault-namecoin-native-selection/1", Selection: session.attempt.Selection(), Sidecar: session.sidecar}
	raw, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := DecodeNativeSelection(raw)
	if err != nil || actual.Sidecar != config.Sidecar {
		t.Fatal("valid native config refused", err)
	}
	for _, bad := range [][]byte{
		nil, []byte("null"), append(bytes.Clone(raw), ' '), append(bytes.Clone(raw), []byte("{}")...),
		bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"unknown":0,"schema":`), 1),
		bytes.Replace(raw, []byte(`{"schema":`), []byte(`{"schema":"wrong","schema":`), 1),
		bytes.Replace(raw, []byte(`"sidecar":{`), []byte(`"sidecar":null,"unused":{`), 1),
		bytes.Replace(raw, []byte(`"Account":"`), []byte(`"Account":"other/`), 1),
	} {
		_, err := DecodeNativeSelection(bad)

		if err == nil {
			t.Fatal("ambiguous or invalid native configuration accepted")
		}
	}
}

// Four literal independently selected disposable profiles admit their frozen
// reservation/reveal controls at the explicit fixture clock. Zero sidecar hashes
// are syntax-only placeholders, not a live retained pair or custody receipt.
// A wrong/malformed/non-lowercase trusted hash or changed file is rejected even
// when the JSON remains otherwise valid. Actual profile provenance is external.
func TestLiteralSelectedNativeProfiles(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, phase := range []string{"reservation", "reveal"} {
			raw := fixture(t, "native-selection", mode+"-"+phase+".json")
			hash := sha256.Sum256(raw)
			expected := hex.EncodeToString(hash[:])
			selected, err := SelectNativeProfile(raw, expected)
			if err != nil {
				t.Fatal("canonical literal profile", mode, phase, err)
			}
			slot := "A"
			if phase == "reveal" {
				slot = "C"
			}
			request, _ := json.Marshal(requestFixture(t, mode, slot))
			a, err := PrepareAttempt(request, fixture(t, mode, "account-pin.json"), selected.Selection, time.Unix(int64(selected.Selection.Policy.CreatedAt)+1, 0))
			if err != nil {
				t.Fatal(err)
			}
			if err = sessionBinding(a, selected.Sidecar); err != nil {
				t.Fatal(err)
			}
			for _, badHash := range []string{"", expected[:63], strings.ToUpper(expected), strings.Repeat("g", 64), strings.Repeat("0", 64)} {
				_, err := SelectNativeProfile(raw, badHash)
				requireCode(t, err, namecoinwire.PolicyRefused)
			}
			changed := bytes.Replace(raw, []byte(`"Policy":`), []byte(`"policy":`), 1)
			_, err = SelectNativeProfile(changed, expected)
			requireCode(t, err, namecoinwire.PolicyRefused)
		}
	}
}
