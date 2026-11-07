package mugrant

import (
	"errors"
	"testing"
)

// Lab-only issuance controls. Existing until-expiry grants retain their scope;
// every once grant must produce exactly one action and exactly one target.
func TestGrantOnceSingleRight(t *testing.T) {
	for _, shape := range []string{"single", "actions", "targets", "both", "empty", "duplicate", "malformed"} {
		for _, use := range []string{UseOnce, UseUntilExpiry} {
			t.Run(shape+"/"+use, func(t *testing.T) {
				s := metaSpec(t)
				s.Use = use
				s.Entries = s.Entries[:1]
				switch shape {
				case "actions":
					s.Entries = append(s.Entries, Entry{"work.require", s.Entries[0].Target})
				case "targets":
					s.Entries = append(s.Entries, Entry{s.Entries[0].Action, Target{"product", "another-product"}})
				case "both":
					s.Entries = append(s.Entries, Entry{"work.require", Target{"product", "another-product"}})
				case "empty":
					s.Entries = nil
				case "duplicate":
					s.Entries = append(s.Entries, s.Entries[0])
				case "malformed":
					s.Entries[0].Target.Kind = "account-scope"
				}
				g, err := BuildGrant(s)
				valid := shape == "single" || use == UseUntilExpiry && (shape == "actions" || shape == "targets" || shape == "both")
				if valid {
					if err != nil || g == nil {
						t.Fatal("valid neighboring scope refused", err)
					}
				} else if !errors.Is(err, ErrGrantSpec) || g != nil {
					t.Fatal("invalid once/spec issued", err)
				}
			})
		}
	}
}
