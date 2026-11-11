package keyvault

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

type recoveryDeleteTerminal struct {
	recoveryFakeTerminal
	onConfirm func(RecoveryPlan) error
}

func (t *recoveryDeleteTerminal) ConfirmIdentities(p RecoveryPlan) error {
	if err := t.recoveryFakeTerminal.ConfirmIdentities(p); err != nil {
		return err
	}
	if t.onConfirm != nil {
		return t.onConfirm(p)
	}
	return nil
}

// The Nostr anchor and group pin select a public snapshot with both identities.
// Wrong pin, absent terminal, mismatch/EOF and a changed snapshot cause
// no deletion. A matching unequal-identity positive removes only that group.
func TestRecoveryDeleteBothIdentities(t *testing.T) {
	for _, mode := range []string{"wrong-pin", "no-terminal", "mismatch", "eof", "changed", "ok"} {
		t.Run(mode, func(t *testing.T) {
			m, f, _ := recoveryTestManager(t)
			q := RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south", Version: 1, NostrVersion: 2, NamecoinVersion: 3}
			r, err := m.Create(q, &recoveryFakeTerminal{}, false)
			if err != nil {
				t.Fatal(err)
			}
			parent := filepath.Join(t.TempDir(), "absent")
			m.lock = FileLock{Path: filepath.Join(parent, "lock")}
			d := RecoveryDeleteRequest{NostrIdentity: "north", Version: 1, ExpectedGroupID: r.GroupID}
			term := &recoveryDeleteTerminal{}
			var terminal RecoveryTerminal = term
			want := "public_pin_mismatch"
			switch mode {
			case "wrong-pin":
				d.ExpectedGroupID = "11111111111111111111111111111111"
			case "no-terminal":
				terminal = nil
				want = "identity_confirmation_failed"
			case "mismatch":
				term.identityRefuse = true
				want = "identity_confirmation_failed"
			case "eof":
				term.onConfirm = func(RecoveryPlan) error { return errors.New("EOF") }
				want = "identity_confirmation_failed"
			case "changed":
				term.onConfirm = func(RecoveryPlan) error {
					created, err := time.Parse(time.RFC3339, r.Created)
					if err != nil {
						return err
					}
					f.groups[0].Created = created.Add(time.Second).UTC().Format(time.RFC3339)
					return nil
				}
			case "ok":
				want = ""
			}
			got, err := m.Delete(d, terminal)
			if want != "" {
				recoveryCode(t, err, want)
				if f.deletes != 0 || len(f.groups) != 1 || len(f.data) != 1 {
					t.Fatal("refusal deleted or lost a record")
				}
				if mode != "changed" {
					if _, e := os.Stat(parent); !os.IsNotExist(e) {
						t.Fatal("refusal created lock prerequisites")
					}
				}
				return
			}
			if err != nil || got.PurposeAccount(got.Nostr) != "north/nostr@2" || got.PurposeAccount(got.Namecoin) != "south/namecoin@3" || f.deletes != 1 || len(f.groups) != 0 || len(f.data) != 0 {
				t.Fatal("confirmed deletion failed", err)
			}
			if term.identityConfirmation != 1 || len(term.plans) != 1 || term.plans[0].NostrRecord != "north/nostr@2" || term.plans[0].NamecoinRecord != "south/namecoin@3" {
				t.Fatal("confirmation lost one identity")
			}
		})
	}
}
