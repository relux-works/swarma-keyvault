package registration_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

var modes = []string{"all-four-before-release", "two-stage"}

var frozenPins = map[string][4][2]string{
	"all-four-before-release": {
		{"c05e7b14a109d1aec7a2a95e13543fc5ad846220996f1d65e6b100a935ae1ca7", "ef24dcde9bad069c632e66980252172859a0de5d39bd0ebaeb513f72478eec52"},
		{"605378cc2283e1dae29b2f4bfaa65a6502b65368b0ce408c923fa9e81a0149b0", "b72f10ff7ef17ab76822bc96704c93f2420ef0fcc6615d6c1cff948e064be1e0"},
		{"1c66de7121b03a551ee00faeecd76cbba5549a4cb21f69d84edbd95ac45fa85a", "e30e14c0516e652336ecd73ae9314f1592b1f5ed55d420383f062820a76d9016"},
		{"a2d68edeeba3545e40575d85fa970113249da9bc4d83ce591d08fe342ec980ae", "e95384a3bf656eb4a8269b67f6039e064f64212e1e835ff8e412c8f0a54b4ca4"},
	},
	"two-stage": {
		{"36f95e2085cad2defd1955b2a709d6c9cee4e52ed48e4868cbe74c90320ecdf8", "bd10299aaf522d405d00df76802dfb8b1d7e7fc4c74b4bfa080cc368509e0cce"},
		{"c3fee5907b241e6e549e6b1067fd5fa2cd1ef19b92f60efd2ba994937281924b", "7be18e68c342e5bd2e0a17045969fdd5e4fbfd1ad7707488d28614578f56a986"},
		{"88db6fc538a392ed98ec71729fd7588af15c4a9309bf19940b40b501c891f239", "0820dc1ef3c13cacf86c802142150f76b9fde5623d2ca181849cdf32e12a32b2"},
		{"b1e1d8754f913cd45d9a89689e8227957ba16c77a0e3c22438ea1e6a82668a9b", "d1540c83a9d2b09b6ab3f53e7615dff0c797958b5c851ddf737a48911fa55947"},
	},
}

func selected(t *testing.T, p namecoinwire.Plan, pin []byte) namecoinpsbt.Selection {
	t.Helper()
	var account namecoinwire.AccountPin
	decode(t, pin, &account)
	return namecoinpsbt.Selection{Network: p.Network, Genesis: p.Genesis, Group: account.Group, Account: account.Account,
		AccountPinSHA256: digest(pin), Policy: p.Policy}
}
func code(t *testing.T, err error, want namecoinwire.Code) {
	t.Helper()
	var failure namecoinwire.Failure
	if !errors.As(err, &failure) || failure.Code() != want {
		t.Fatalf("want %s, got %v", want, err)
	}
}
func publicCandidate(t *testing.T, raw, pin []byte) (namecoinwire.Snapshot, namecoinpsbt.Candidate) {
	t.Helper()
	s, err := namecoinwire.Decode(raw)
	if err != nil {
		t.Fatal(err)
	}
	c, err := namecoinpsbt.Inspect(s, pin)
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

// All eight original public requests/frames are fixed external oracles. Core's
// signatures and final bytes establish public compatibility, never native custody.
func TestRegistrationFrozenPublicWire(t *testing.T) {
	for _, mode := range modes {
		for i, slot := range []string{"A", "B", "C", "D"} {
			t.Run(mode+"/"+slot, func(t *testing.T) {
				raw := wireFixture(t, mode, slot+"-request.json")
				if digest(raw) != frozenPins[mode][i][0] {
					t.Fatal("frozen request pin differs")
				}
				pin := psbtFixture(t, mode, "account-pin.json")
				s, c := publicCandidate(t, raw, pin)
				selection := selected(t, s.Plan(), pin)
				selection.RevealValuesPin = wireFixture(t, mode, "trusted-reveal-values-pin.json")
				context, err := c.ReviewContext(selection)
				if err != nil {
					t.Fatal(err)
				}
				frame, err := s.ReviewFrame(context)
				if err != nil {
					t.Fatal(err)
				}
				original, err := hex.DecodeString(strings.TrimSpace(string(wireFixture(t, mode, slot+"-review-frame.hex"))))
				if err != nil {
					t.Fatal(err)
				}
				if digest(original) != frozenPins[mode][i][1] || !bytes.Equal(frame, original) {
					t.Fatal("frozen frame pin differs")
				}
				if _, err := c.VerifyResult(wireFixture(t, mode, slot+"-result.json"), sha256.Sum256(frame)); err != nil {
					t.Fatal(err)
				}
				signed := strings.TrimSpace(string(psbtFixture(t, mode, slot+"-signed.psbt")))
				sigs, err := c.VerifySignedPSBT(decodePSBT(t, signed))
				if err != nil {
					t.Fatal(err)
				}
				_, final, err := c.Assemble(sigs)
				if err != nil {
					t.Fatal(err)
				}
				if hex.EncodeToString(final) != strings.TrimSpace(string(psbtFixture(t, mode, slot+"-final.hex"))) {
					t.Fatal("Core finalized bytes differ")
				}
			})
		}
	}
}

// The real CLI reconstructs each complete retained DAG after actual expiry,
// including both A/B parent results behind C/D. Fresh emission still refuses.
func TestRegistrationCLIHistorical(t *testing.T) {
	identityCLI(t)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			e := frozen(t, mode)
			for _, slot := range []string{"A", "B", "C", "D"} {
				t.Run(slot, func(t *testing.T) {
					var req namecoinwire.Request
					decode(t, read(t, filepath.Join(filepath.Dir(e.parents[slot].Bundle), "request.json")), &req)
					var p profile
					decode(t, e.profile, &p)
					if time.Now().Unix() <= int64(req.ExpiresAt) || time.Now().Unix() <= int64(p.Policy.ReleaseNotAfter) {
						t.Fatal("historical fixture has not actually expired; not an expiry witness")
					}
					out, en, exit := e.run(t, "check-result", "checked-"+slot, checkInput(e.parents[slot]))
					requireSuccess(t, out, en, exit, "checked-result")
					want := strings.TrimSpace(string(psbtFixture(t, mode, slot+"-final.hex")))
					if string(read(t, filepath.Join(out, "verified-transaction.hex"))) != want {
						t.Fatal("CLI returned different finalized bytes")
					}
					checkedFacts(t, out, read(t, filepath.Join(filepath.Dir(e.parents[slot].Bundle), "request.json")), read(t, e.parents[slot].Result))
				})
			}
			out, en, exit := e.run(t, "request", "expired-fresh", map[string]any{"schema": prefix + "request/1", "plan_bundle": e.reservation,
				"plan_bundle_sha256": digest(read(t, e.reservation)), "slot": "A", "valid_for_seconds": 600})
			requireRefusal(t, out, en, exit, "REGISTRATION_POLICY_REFUSED", 3)
		})
	}
}

func editRequestState(t *testing.T, p *parent, edit func(*requestState)) {
	t.Helper()
	path := filepath.Join(filepath.Dir(p.Bundle), "request-state.json")
	var state requestState
	decode(t, read(t, path), &state)
	edit(&state)
	write(t, path, canonical(t, state))
	p.BundleHash = reseal(t, p.Bundle)
}
func editResult(t *testing.T, p *parent, edit func(*namecoinwire.Result)) {
	t.Helper()
	r, err := namecoinwire.DecodeResult(read(t, p.Result))
	if err != nil {
		t.Fatal(err)
	}
	edit(&r)
	raw := canonical(t, r)
	write(t, p.Result, raw)
	p.ResultHash = digest(raw)
	ack := []byte("{\"schema\":\"keyvault-namecoin-psbt-ack/2\",\"status\":\"SIGNED\",\"result_sha256\":\"" + p.ResultHash + "\"}\n")
	write(t, p.Stdout, ack)
	p.StdoutHash = digest(ack)
}

// Each mutation has a neighboring complete CLI success. Byte hashes are renewed
// so semantic substitutions reach restoration/result checks rather than FILES.
// Refusals emit no checked-result directory or usable transaction.
func TestRegistrationCLIHistoricalRefusals(t *testing.T) {
	identityCLI(t)
	rows := []struct {
		name, slot, want string
		exit             int
		edit             func(*testing.T, *fixtureEnv, *parent)
	}{
		{"request-id", "A", "REGISTRATION_PARENT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			editRequestState(t, p, func(s *requestState) { s.RequestID = strings.Repeat("f", 64) })
		}},
		{"sitting-id", "A", "REGISTRATION_PARENT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			editRequestState(t, p, func(s *requestState) { s.SittingID = strings.Repeat("e", 64) })
		}},
		{"expiry", "A", "REGISTRATION_PARENT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			editRequestState(t, p, func(s *requestState) { s.ExpiresAt-- })
		}},
		{"frame", "A", "REGISTRATION_PARENT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			path := filepath.Join(filepath.Dir(p.Bundle), "review-frame.bin")
			raw := read(t, path)
			raw[len(raw)-1] ^= 1
			write(t, path, raw)
			editRequestState(t, p, func(s *requestState) { s.ReviewHash = digest(raw) })
		}},
		{"plan-opening", "A", "REGISTRATION_PARENT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			path := filepath.Join(filepath.Dir(e.reservation), "reservation-state.json")
			var state reservationState
			decode(t, read(t, path), &state)
			state.Names[0].Rand = strings.Repeat("a", 40)
			write(t, path, canonical(t, state))
			hash := reseal(t, e.reservation)
			editRequestState(t, p, func(s *requestState) { s.PlanHash = hash })
		}},
		{"missing-plan", "A", "REGISTRATION_FILES", 1, func(t *testing.T, e *fixtureEnv, p *parent) {
			editRequestState(t, p, func(s *requestState) { s.Plan = filepath.Join(e.dir, "missing", "bundle.json") })
		}},
		{"stale-bundle-hash", "A", "REGISTRATION_FILES", 1, func(t *testing.T, e *fixtureEnv, p *parent) { p.BundleHash = strings.Repeat("0", 64) }},
		{"independent-pin", "A", "REGISTRATION_PARENT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			var pin namecoinwire.AccountPin
			decode(t, e.pin, &pin)
			pin.Group = "different/recovery@1"
			e.pin = jsonBytes(t, pin)
			write(t, e.pinPath, e.pin)
		}},
		{"nonzero-exit", "A", "REGISTRATION_RESULT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) { p.Exit = 1 }},
		{"ack-extra-line", "A", "REGISTRATION_RESULT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			raw := append(read(t, p.Stdout), '\n')
			write(t, p.Stdout, raw)
			p.StdoutHash = digest(raw)
		}},
		{"receipt-request-id", "A", "REGISTRATION_RESULT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			editResult(t, p, func(r *namecoinwire.Result) { r.Receipt.RequestID = strings.Repeat("f", 64) })
		}},
		{"receipt-signature", "A", "REGISTRATION_RESULT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			editResult(t, p, func(r *namecoinwire.Result) {
				s := r.Receipt.InputSignatures[0].Signature
				b, err := hex.DecodeString(s)
				if err != nil {
					t.Fatal(err)
				}
				b[len(b)-1] ^= 1
				r.Receipt.InputSignatures[0].Signature = hex.EncodeToString(b)
			})
		}},
		{"parent-A-result", "C", "REGISTRATION_RESULT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) { substituteParent(t, e, p, 0) }},
		{"parent-B-result", "D", "REGISTRATION_RESULT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) { substituteParent(t, e, p, 1) }},
		{"reveal-pin", "C", "REGISTRATION_PARENT_REFUSED", 3, func(t *testing.T, e *fixtureEnv, p *parent) {
			path := filepath.Join(filepath.Dir(e.reveal), "reveal-values-pin.json")
			var pin namecoinwire.RevealValuesPin
			decode(t, read(t, path), &pin)
			pin.ReservationPlanSHA256 = strings.Repeat("f", 64)
			raw := jsonBytes(t, pin)
			write(t, path, raw)
			updateReveal(t, e, p, func(s *revealState) { s.PinHash = digest(raw) })
		}},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := frozen(t, "two-stage")
			p := e.parents[row.slot]
			out, en, exit := e.run(t, "check-result", "valid", checkInput(p))
			requireSuccess(t, out, en, exit, "checked-result")
			row.edit(t, e, &p)
			out, en, exit = e.run(t, "check-result", "refused", checkInput(p))
			requireRefusal(t, out, en, exit, row.want, row.exit)
		})
	}
}

func updateReveal(t *testing.T, e *fixtureEnv, p *parent, edit func(*revealState)) {
	t.Helper()
	path := filepath.Join(filepath.Dir(e.reveal), "reveal-state.json")
	var state revealState
	decode(t, read(t, path), &state)
	edit(&state)
	write(t, path, canonical(t, state))
	hash := reseal(t, e.reveal)
	editRequestState(t, p, func(s *requestState) { s.PlanHash = hash })
}
func substituteParent(t *testing.T, e *fixtureEnv, p *parent, index int) {
	t.Helper()
	updateReveal(t, e, p, func(s *revealState) {
		editResult(t, &s.Parents[index], func(r *namecoinwire.Result) { r.Receipt.SittingID = strings.Repeat("a", 64) })
	})
}

// Fresh actual-clock reserve/request output docks into the separate vault wire,
// pin and frame boundary. Expired/short/override requests fail before output.
func TestRegistrationCLIFresh(t *testing.T) {
	identityCLI(t)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			e := frozen(t, mode)
			var prof profile
			decode(t, e.profile, &prof)
			prof.Policy.CreatedAt = uint64(time.Now().Unix()) - 60
			prof.Policy.ReleaseNotAfter = prof.Policy.CreatedAt + 86400
			e.profile = jsonBytes(t, prof)
			write(t, e.profilePath, e.profile)
			var state reservationState
			decode(t, read(t, filepath.Join(filepath.Dir(e.reservation), "reservation-state.json")), &state)
			type nameInput struct {
				Name  string `json:"name"`
				Path  string `json:"name_output_path"`
				Value string `json:"fixed_value_hex"`
			}
			names := []nameInput{}
			for _, n := range state.Names {
				names = append(names, nameInput{n.Name, n.Path, n.Value})
			}
			state.Funding.Hex = filepath.Join(filepath.Dir(e.reservation), "funding.hex")
			input := map[string]any{"schema": prefix + "reserve/1", "funding": state.Funding, "registrations": names, "change_paths": state.Change, "fees_atoms": state.Fees}
			out, en, exit := e.run(t, "reserve", "fresh-reserve", input)
			requireSuccess(t, out, en, exit, "reservation")
			plan := filepath.Join(out, "bundle.json")
			request := map[string]any{"schema": prefix + "request/1", "plan_bundle": plan, "plan_bundle_sha256": digest(read(t, plan)), "slot": "A", "valid_for_seconds": 600}
			for _, slot := range []string{"A", "B"} {
				request["slot"] = slot
				out, en, exit = e.run(t, "request", "fresh-request-"+slot, request)
				requireSuccess(t, out, en, exit, "request")
				raw := read(t, filepath.Join(out, "request.json"))
				s, c := publicCandidate(t, raw, e.pin)
				if len(raw) > 2097152 || len(s.PSBTBytes()) > 1048576 {
					t.Fatal("fresh request exceeds dispatch limits")
				}
				p := s.Plan()
				sel := selected(t, p, e.pin)
				sel.Network, sel.Genesis, sel.Policy = prof.Network, prof.Genesis, prof.Policy
				attempt, err := namecoinpsbt.PrepareAttempt(raw, e.pin, sel, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(attempt.ReviewFrame(), read(t, filepath.Join(out, "review-frame.bin"))) {
					t.Fatal("CLI/vault frame bytes differ")
				}
				dockFreshProcess(t, mode, slot, out, e.pin, sel)
				if p.Policy != prof.Policy || p.AccountPinSHA256 != digest(e.pin) || c.View().Slot != slot {
					t.Fatal("profile/pin/slot projection differs")
				}
				wrong := sel
				wrong.Policy.Revision += "-other"
				_, err = namecoinpsbt.PrepareAttempt(raw, e.pin, wrong, time.Now())
				code(t, err, namecoinwire.PolicyRefused)
			}
			request["valid_for_seconds"] = 29
			out, en, exit = e.run(t, "request", "short-request", request)
			requireRefusal(t, out, en, exit, "REGISTRATION_POLICY_REFUSED", 3)
			request["valid_for_seconds"] = 600
			out, en, exit = e.run(t, "request", "clock-override", request, "--now", "1")
			requireRefusal(t, out, en, exit, "BAD_INPUT", 2)
		})
	}
}

// Fresh reveal construction uses complete independently checked A/B public
// contexts and the selected reveal pin. Existing Core signatures stay unchanged;
// these synthetic receipt correlations do not prove native journal authenticity.
func TestRegistrationCLIFreshReveal(t *testing.T) {
	identityCLI(t)
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			e := frozenAt(t, mode, true)
			var state revealState
			decode(t, read(t, filepath.Join(filepath.Dir(e.reveal), "reveal-state.json")), &state)
			input := map[string]any{}
			decode(t, jsonBytes(t, state), &input)
			delete(input, "prepared_at")
			input["schema"] = prefix + "reveal/1"
			input["reveal_values_pin"] = filepath.Join(filepath.Dir(e.reveal), "reveal-values-pin.json")
			out, en, exit := e.run(t, "reveal", "fresh-reveal", input)
			requireSuccess(t, out, en, exit, "reveal")
			if !bytes.Equal(read(t, filepath.Join(out, "reveal-manifest.json")), read(t, filepath.Join(filepath.Dir(e.reveal), "reveal-manifest.json"))) {
				t.Fatal("fresh reveal differs from public source-grounded plan")
			}
			plan := filepath.Join(out, "bundle.json")
			for _, slot := range []string{"C", "D"} {
				request := map[string]any{"schema": prefix + "request/1", "plan_bundle": plan, "plan_bundle_sha256": digest(read(t, plan)), "slot": slot, "valid_for_seconds": 600}
				out, en, exit = e.run(t, "request", "fresh-reveal-request-"+slot, request)
				requireSuccess(t, out, en, exit, "request")
				raw := read(t, filepath.Join(out, "request.json"))
				s, c := publicCandidate(t, raw, e.pin)
				var prof profile
				decode(t, e.profile, &prof)
				sel := selected(t, s.Plan(), e.pin)
				sel.Network, sel.Genesis, sel.Policy = prof.Network, prof.Genesis, prof.Policy
				sel.RevealValuesPin = read(t, input["reveal_values_pin"].(string))
				attempt, err := namecoinpsbt.PrepareAttempt(raw, e.pin, sel, time.Now())
				if err != nil {
					t.Fatal(err)
				}
				dockFreshProcess(t, mode, slot, out, e.pin, sel)
				frame := read(t, filepath.Join(out, "review-frame.bin"))
				if !bytes.Equal(frame, attempt.ReviewFrame()) {
					t.Fatal("fresh reveal frame differs at vault boundary")
				}
				// Only public request/receipt correlation changes. The original
				// signed Core PSBT and its transaction sighashes remain untouched.
				var result namecoinwire.Result
				decode(t, wireFixture(t, mode, slot+"-result.json"), &result)
				r := s.Request()
				result.Receipt.RequestID = r.RequestID
				result.Receipt.SittingID = r.SittingID
				result.Receipt.PlanSHA256 = r.PlanSHA256
				result.Receipt.ReservationPlanSHA256 = r.ReservationPlanSHA256
				result.Receipt.ReviewSHA256 = digest(frame)
				resultRaw := canonical(t, result)
				if _, err := c.VerifyResult(resultRaw, sha256.Sum256(frame)); err != nil {
					t.Fatal(err)
				}
				resultPath, ackPath := filepath.Join(e.dir, "fresh-"+slot+"-result.json"), filepath.Join(e.dir, "fresh-"+slot+"-ack.stdout")
				write(t, resultPath, resultRaw)
				ack := acknowledgement(resultRaw)
				write(t, ackPath, ack)
				bundle := filepath.Join(out, "bundle.json")
				p := parent{bundle, digest(read(t, bundle)), resultPath, digest(resultRaw), ackPath, digest(ack), 0}
				out, en, exit = e.run(t, "check-result", "fresh-reveal-checked-"+slot, checkInput(p))
				requireSuccess(t, out, en, exit, "checked-result")
				if string(read(t, filepath.Join(out, "verified-transaction.hex"))) != strings.TrimSpace(string(psbtFixture(t, mode, slot+"-final.hex"))) {
					t.Fatal("fresh checked Core transaction differs")
				}
				checkedFacts(t, out, raw, resultRaw)
				wrong := sel
				var pin namecoinwire.RevealValuesPin
				decode(t, sel.RevealValuesPin, &pin)
				pin.ReservationPlanSHA256 = strings.Repeat("f", 64)
				wrong.RevealValuesPin = jsonBytes(t, pin)
				_, err = namecoinpsbt.PrepareAttempt(raw, e.pin, wrong, time.Now())
				code(t, err, namecoinwire.IntentMismatch)
			}
			// A new fresh reveal with a substituted parent must refuse before
			// creating any output, even with recomputed result and ACK hashes.
			parents := append([]parent(nil), state.Parents...)
			editResult(t, &parents[1], func(r *namecoinwire.Result) { r.Receipt.SittingID = strings.Repeat("f", 64) })
			input["parents"] = parents
			out, en, exit = e.run(t, "reveal", "fresh-parent-refused", input)
			requireRefusal(t, out, en, exit, "REGISTRATION_RESULT_REFUSED", 3)
		})
	}
}

// A create-only CLI refusal preserves existing bytes. This is a filesystem
// invariant for the exercised bundle path, not a hostile same-user atomicity proof.
func TestRegistrationCLIExistingOutput(t *testing.T) {
	identityCLI(t)
	e := frozen(t, "two-stage")
	out := filepath.Join(e.dir, "existing")
	if err := os.Mkdir(out, 0700); err != nil {
		t.Fatal(err)
	}
	marker := []byte("retain existing output\n")
	path := filepath.Join(out, "marker")
	write(t, path, marker)
	_, en, exit := e.run(t, "check-result", "existing", checkInput(e.parents["A"]))
	if exit != 1 || en.OK || en.Result != nil || en.Error == nil || en.Error.Code != "REGISTRATION_FILES" {
		t.Fatal("existing output was not refused")
	}
	if !bytes.Equal(read(t, path), marker) {
		t.Fatal("existing bytes changed")
	}
	entries, err := os.ReadDir(out)
	if err != nil || len(entries) != 1 {
		t.Fatal("existing output acquired partial payloads", err)
	}
}

type checkedPublicResult struct {
	Schema     string `json:"schema"`
	TxID       string `json:"txid"`
	SignedHash string `json:"signed_psbt_sha256"`
	ResultHash string `json:"result_sha256"`
	Fee        string `json:"fee_atoms"`
	Weight     uint32 `json:"weight"`
	VSize      uint32 `json:"vsize"`
	Sequence   uint64 `json:"reported_journal_sequence"`
	Head       string `json:"reported_journal_head_sha256"`
}

func checkedFacts(t *testing.T, out string, request, resultRaw []byte) {
	t.Helper()
	var req namecoinwire.Request
	decode(t, request, &req)
	var plan struct {
		Transactions []namecoinwire.Transaction `json:"transactions"`
	}
	decode(t, []byte(req.ManifestUTF8), &plan)
	var tx namecoinwire.Transaction
	for _, candidate := range plan.Transactions {
		if candidate.Slot == req.Slot {
			tx = candidate
		}
	}
	unsigned := mustHex(t, tx.UnsignedHex)
	first := sha256.Sum256(unsigned)
	id := sha256.Sum256(first[:])
	for i := 0; i < len(id)/2; i++ {
		id[i], id[len(id)-1-i] = id[len(id)-1-i], id[i]
	}
	final := mustHex(t, string(read(t, filepath.Join(out, "verified-transaction.hex"))))
	weight := uint32(3*len(unsigned) + len(final))
	var result namecoinwire.Result
	decode(t, resultRaw, &result)
	want := checkedPublicResult{prefix + "public-result/1", hex.EncodeToString(id[:]), digest(decodePSBT(t, result.SignedPSBT)), digest(resultRaw),
		"100000", weight, (weight + 3) / 4, result.Receipt.JournalSequence, result.Receipt.JournalHeadSHA256}
	if !bytes.Equal(read(t, filepath.Join(out, "public-result.json")), canonical(t, want)) {
		t.Fatal("closed checked-result facts differ from Core transaction and original result")
	}
}

// Closed-input and independently expected-digest errors have distinct fixed
// codes. Every row first proves that its complete original context is accepted.
func TestRegistrationCLIAdmissionRefusals(t *testing.T) {
	identityCLI(t)
	rows := []struct {
		name, code string
		exit       int
		edit       func(*fixtureEnv, map[string]any)
	}{
		{"null-exit", "BAD_INPUT", 2, func(e *fixtureEnv, in map[string]any) { in["process_exit"] = nil }},
		{"quoted-exit", "BAD_INPUT", 2, func(e *fixtureEnv, in map[string]any) { in["process_exit"] = "0" }},
		{"unknown-field", "BAD_INPUT", 2, func(e *fixtureEnv, in map[string]any) { in["unrecognized"] = true }},
		{"profile-expected-digest", "REGISTRATION_POLICY_REFUSED", 3, func(e *fixtureEnv, in map[string]any) { e.profile = append(bytes.Clone(e.profile), '\n') }},
		{"pin-expected-digest", "REGISTRATION_FILES", 1, func(e *fixtureEnv, in map[string]any) { e.pin = append(bytes.Clone(e.pin), '\n') }},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			e := frozen(t, "two-stage")
			input := checkInput(e.parents["A"])
			out, en, exit := e.run(t, "check-result", "valid", input)
			requireSuccess(t, out, en, exit, "checked-result")
			row.edit(e, input)
			out, en, exit = e.run(t, "check-result", "refused", input)
			requireRefusal(t, out, en, exit, row.code, row.exit)
		})
	}
}
