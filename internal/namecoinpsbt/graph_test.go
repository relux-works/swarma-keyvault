package namecoinpsbt

import (
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Coherent, individually valid account-owned transactions with the same fee
// cannot replace the committed A->B / C->D change chain. Inspect rejects the
// whole phase before any private lifecycle is called. No native effect is tested.
func TestPhaseGraphRefusesIndependentAccountSpends(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, phase := range []string{"reservation", "reveal"} {
			t.Run(mode+"/"+phase, func(t *testing.T) {
				slot := "A"
				if phase == "reveal" {
					slot = "C"
				}
				r := requestFixture(t, mode, slot)
				if _, err := Inspect(snapshot(t, r), fixture(t, mode, "account-pin.json")); err != nil {
					t.Fatal("positive phase", err)
				}
				var templates []namecoinwire.Transaction
				var encode func() []byte
				if phase == "reservation" {
					var plan namecoinwire.ReservationPlan
					if err := json.Unmarshal([]byte(r.ManifestUTF8), &plan); err != nil {
						t.Fatal(err)
					}
					templates = plan.Transactions
					encode = func() []byte {
						raw, err := json.Marshal(plan)
						if err != nil {
							t.Fatal(err)
						}
						return raw
					}
				} else {
					var plan namecoinwire.RevealPlan
					if err := json.Unmarshal([]byte(r.ManifestUTF8), &plan); err != nil {
						t.Fatal(err)
					}
					templates = plan.Transactions
					encode = func() []byte {
						raw, err := json.Marshal(plan)
						if err != nil {
							t.Fatal(err)
						}
						return raw
					}
				}
				// B reuses A's funding, or D reuses C's B-change input. Both are
				// valid own-account prevouts, but conflict with the earlier slot.
				inputIndex := 0
				if phase == "reveal" {
					inputIndex = 1
				}
				previousMeta := templates[0].Inputs[inputIndex]
				oldMeta := templates[1].Inputs[inputIndex]
				newParent, err := parseTransaction(decodeHex(previousMeta.PreviousTransactionHex), true)
				if err != nil {
					t.Fatal(err)
				}
				oldParent, err := parseTransaction(decodeHex(oldMeta.PreviousTransactionHex), true)
				if err != nil {
					t.Fatal(err)
				}
				tx, err := parseTransaction(decodeHex(templates[1].UnsignedHex), false)
				if err != nil {
					t.Fatal(err)
				}
				newAmount := newParent.outputs[previousMeta.Vout].amount
				oldAmount := oldParent.outputs[oldMeta.Vout].amount
				if newAmount <= oldAmount {
					t.Fatal("fixture no longer provides the larger valid own prevout")
				}
				change, ok := changeIndex(templates[1], true)
				if !ok {
					t.Fatal("change fixture")
				}
				tx.outputs[change].amount += newAmount - oldAmount
				tx.inputs[inputIndex].hash = newParent.hash()
				tx.inputs[inputIndex].index = previousMeta.Vout
				templates[1].Inputs[inputIndex] = previousMeta
				templates[1].UnsignedHex = hex.EncodeToString(tx.serialize(false))
				templates[1].UnsignedTxID = rpcHash(tx.hash())
				r.ManifestUTF8 = string(encode())
				r.PlanSHA256 = namecoinwire.PlanDigest([]byte(r.ManifestUTF8))
				if phase == "reservation" {
					r.ReservationPlanSHA256 = r.PlanSHA256
				}
				s := snapshot(t, r)
				pin, err := namecoinwire.DecodeAccountPin(fixture(t, mode, "account-pin.json"))
				if err != nil {
					t.Fatal(err)
				}
				account, err := parseAccount(pin)
				if err != nil {
					t.Fatal(err)
				}
				// This positive control distinguishes graph refusal from a bad
				// amount, wrong derived key, malformed body or fee-cap rejection.
				view, _, err := inspectTemplate(s.Plan().Transactions[1], s.Plan(), account)
				if err != nil {
					t.Fatal("mutant not independently valid", err)
				}
				fee, _ := namecoinwire.Decimal(templates[1].Fee)
				if view.Fee != fee {
					t.Fatal("mutant fee changed")
				}
				_, err = Inspect(s, fixture(t, mode, "account-pin.json"))
				requireCode(t, err, namecoinwire.IntentMismatch)
			})
		}
	}
}

// Closed shape checks preserve a last reveal without change, but do not allow
// extra name/change outputs or undeclared output kinds in this restricted graph.
func TestPhaseGraphOutputShape(t *testing.T) {
	for _, test := range []struct {
		kinds        []string
		required, ok bool
	}{
		{[]string{"name", "change"}, true, true}, {[]string{"change", "name"}, true, true}, {[]string{"name"}, false, true},
		{[]string{"name"}, true, false}, {[]string{"change"}, false, false}, {[]string{"name", "name"}, false, false},
		{[]string{"name", "change", "change"}, false, false}, {[]string{"name", "payment"}, false, false},
	} {
		var meta namecoinwire.Transaction
		for i, kind := range test.kinds {
			meta.Outputs = append(meta.Outputs, namecoinwire.Output{Vout: uint32(i), Kind: kind})
		}
		_, ok := changeIndex(meta, test.required)
		if ok != test.ok {
			t.Fatal(test.kinds, test.required, ok)
		}
	}
}
