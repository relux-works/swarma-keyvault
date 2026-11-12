package namecoinpsbt

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

func fixtureSelection(t *testing.T, c Candidate) Selection {
	t.Helper()
	p := c.snapshot.Plan()
	var reveal []byte
	if p.Kind == "reveal" {
		raw, err := json.Marshal(namecoinwire.RevealValuesPin{Schema: "keyvault-namecoin-reveal-values/1", ReservationPlanSHA256: p.ReservationPlanSHA256, Registrations: []namecoinwire.RevealValue{
			{NameHex: p.Registrations[0].NameHex, ValueHex: p.Registrations[0].ValueHex, ValueSHA256: p.Registrations[0].ValueSHA256},
			{NameHex: p.Registrations[1].NameHex, ValueHex: p.Registrations[1].ValueHex, ValueSHA256: p.Registrations[1].ValueSHA256},
		}})
		if err != nil {
			t.Fatal(err)
		}
		reveal = raw
	}
	// Explicit neutral fixture authority only, not a production rule allowing
	// untrusted manifests to select their own caps, clock or reveal values.
	return Selection{Network: p.Network, Genesis: p.Genesis, Group: p.Group, Account: p.Account, AccountPinSHA256: p.AccountPinSHA256, Policy: p.Policy, RevealValuesPin: reveal}
}

// Actual fixture fees/dust/rates pass with independently chosen fixture facts.
// Untrusted changes, expired approvals, overlong approvals and missing final
// value pins refuse before an engine may reach private dispatch.
func TestSelectedPolicyClockAndFinalValues(t *testing.T) {
	for _, slot := range []string{"A", "C"} {
		c := candidate(t, "all-four-before-release", slot)
		selected := fixtureSelection(t, c)
		now := time.Unix(int64(selected.Policy.CreatedAt)+1, 0)
		if err := c.Admit(selected, now); err != nil {
			t.Fatal("fixture admission refused", err)
		}
		sigs, err := c.VerifySignedPSBT(signedFixture(t, "all-four-before-release", slot))
		if err != nil {
			t.Fatal(err)
		}
		if err = c.CheckFinalFeeRate(sigs, selected); err != nil {
			t.Fatal(err)
		}
		for _, change := range []func(*Selection){func(s *Selection) { s.Genesis = "00" }, func(s *Selection) { s.Account = "other/namecoin@1" }, func(s *Selection) { s.Policy.PerTxFeeCap = "100001" }, func(s *Selection) { s.Policy.Revision += "x" }, func(s *Selection) { s.Policy.TotalFeeCap = "400001" }} {
			bad := selected
			change(&bad)
			requireCode(t, c.Admit(bad, now), namecoinwire.PolicyRefused)
		}
		requireCode(t, c.Admit(selected, time.Unix(int64(c.snapshot.Request().ExpiresAt), 0)), namecoinwire.RequestExpired)
		requireCode(t, c.Admit(selected, time.Unix(int64(c.snapshot.Request().ExpiresAt)-601, 0)), namecoinwire.RequestExpired)
		if slot == "C" {
			bad := selected
			bad.RevealValuesPin = nil
			requireCode(t, c.Admit(bad, now), namecoinwire.IntentMismatch)
			bad.RevealValuesPin = bytes.Replace(selected.RevealValuesPin, []byte(`"reservation_plan_sha256":"`), []byte(`"reservation_plan_sha256":"0`), 1)
			requireCode(t, c.Admit(bad, now), namecoinwire.IntentMismatch)
		}
	}
}

func encodePacket(p packet) []byte {
	raw := appendSection([]byte{'p', 's', 'b', 't', 255}, p.globals)
	for _, in := range p.inputs {
		raw = appendSection(raw, in.entries)
	}
	for _, out := range p.outputMaps {
		raw = appendSection(raw, out)
	}
	return raw
}
func clonePacket(t *testing.T, c Candidate) packet {
	t.Helper()
	p, err := parsePacket(encodePacket(c.packet))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// Each forged input reaches a specific public rejection with an empty
// candidate. No rejected parse can leave an admitted digest or partial view.
func TestPSBTInputAndMapRefusals(t *testing.T) {
	c := candidate(t, "all-four-before-release", "A")
	for _, test := range []struct {
		name   string
		code   namecoinwire.Code
		mutate func(*packet)
	}{
		{"full-parent", namecoinwire.PrevoutMismatch, func(p *packet) { p.inputs[0].entries[0].value[0] ^= 1 }},
		{"witness-amount", namecoinwire.PrevoutMismatch, func(p *packet) { p.inputs[0].entries[1].value[0] ^= 1 }},
		{"fingerprint", namecoinwire.AccountMismatch, func(p *packet) { p.inputs[0].entries[2].value[0] ^= 1 }},
		{"hardened-path", namecoinwire.PathRefused, func(p *packet) { p.inputs[0].entries[2].value[7] ^= 0x80 }},
		{"partial-signature", namecoinwire.UnsupportedPSBT, func(p *packet) {
			p.inputs[0].entries = append(p.inputs[0].entries, entry{append([]byte{2}, p.inputs[0].origin.key[:]...), []byte{0}})
		}},
		{"final-script", namecoinwire.UnsupportedPSBT, func(p *packet) { p.inputs[0].entries = append(p.inputs[0].entries, entry{[]byte{7}, []byte{0}}) }},
		{"redeem-script", namecoinwire.UnsupportedPSBT, func(p *packet) { p.inputs[0].entries = append(p.inputs[0].entries, entry{[]byte{4}, []byte{0}}) }},
		{"taproot", namecoinwire.UnsupportedPSBT, func(p *packet) {
			p.inputs[0].entries = append(p.inputs[0].entries, entry{[]byte{0x17}, make([]byte, 32)})
		}},
		{"proprietary", namecoinwire.UnsupportedPSBT, func(p *packet) { p.globals = append(p.globals, entry{[]byte{0xfc, 1}, nil}) }},
		{"non-ALL", namecoinwire.SighashRefused, func(p *packet) {
			p.inputs[0].entries = append(p.inputs[0].entries, entry{[]byte{3}, []byte{0x81, 0, 0, 0}})
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			p := clonePacket(t, c)
			test.mutate(&p)
			r := requestFixture(t, "all-four-before-release", "A")
			r.PSBT = base64.StdEncoding.EncodeToString(encodePacket(p))
			got, err := Inspect(snapshot(t, r), fixture(t, "all-four-before-release", "account-pin.json"))
			requireCode(t, err, test.code)
			if len(got.digests) != 0 || len(got.view.Inputs) != 0 {
				t.Fatal("refusal left partial admitted candidate")
			}
		})
	}
}

// Core's actual finalized A is a legitimate witness-bearing full parent for B;
// the unsigned parent's stripped bytes remain exactly the frozen template.
func TestWitnessBearingActualCoreParent(t *testing.T) {
	c := candidate(t, "all-four-before-release", "B")
	p := clonePacket(t, c)
	final, err := hex.DecodeString(string(bytes.TrimSpace(fixture(t, "all-four-before-release", "A-final.hex"))))
	if err != nil {
		t.Fatal(err)
	}
	for i := range p.inputs[0].entries {
		if bytes.Equal(p.inputs[0].entries[i].key, []byte{0}) {
			p.inputs[0].entries[i].value = final
		}
	}
	r := requestFixture(t, "all-four-before-release", "B")
	r.PSBT = base64.StdEncoding.EncodeToString(encodePacket(p))
	if _, err := Inspect(snapshot(t, r), fixture(t, "all-four-before-release", "account-pin.json")); err != nil {
		t.Fatal("actual witness-bearing Core parent refused", err)
	}
}

// Recommitting a lie about a public fee does not make it match independently
// recomputed amounts. Pin-byte changes also cannot borrow a manifest's binding.
func TestManifestFeeAndPinByteRefusals(t *testing.T) {
	r := requestFixture(t, "all-four-before-release", "A")
	var p namecoinwire.ReservationPlan
	if err := json.Unmarshal([]byte(r.ManifestUTF8), &p); err != nil {
		t.Fatal(err)
	}
	p.Transactions[0].Fee = "99999"
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	r.ManifestUTF8 = string(raw)
	r.PlanSHA256 = namecoinwire.PlanDigest(raw)
	r.ReservationPlanSHA256 = r.PlanSHA256
	_, err = Inspect(snapshot(t, r), fixture(t, "all-four-before-release", "account-pin.json"))
	requireCode(t, err, namecoinwire.FeeRefused)
	r = requestFixture(t, "all-four-before-release", "A")
	pin := append(fixture(t, "all-four-before-release", "account-pin.json"), ' ')
	_, err = Inspect(snapshot(t, r), pin)
	requireCode(t, err, namecoinwire.AccountMismatch)
}

// 128-bit multiplication compares extreme public rates without uint64 wrap;
// an unrepresentable quotient is a policy refusal, never a small dust value.
func TestCheckedPublicFeeArithmetic(t *testing.T) {
	max := ^uint64(0)
	if compareProducts(max, max, max, max) != 0 || compareProducts(max, max, max, max-1) != 1 || compareProducts(max-1, max, max, max) != -1 {
		t.Fatal("128-bit rate comparison wrapped")
	}
	if q, overflow := mulDiv(3000, 98, 1000); overflow || q != 294 {
		t.Fatal("native witness dust fixture differs")
	}
	if _, overflow := mulDiv(max, max, 1000); !overflow {
		t.Fatal("dust overflow was admitted")
	}
}
