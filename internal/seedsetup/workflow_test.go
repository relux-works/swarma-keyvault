package seedsetup

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"reflect"
	"strings"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func successReply(t *testing.T, family string, result any) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"ok": true, "command": family, "result": result})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func failedReply(t *testing.T, family, code string, status int) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"ok": false, "command": family, "error": map[string]any{"code": code, "message": "diagnostic not for forwarding", "hint": "ignored", "os_status": status}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// Change both fixture public authorities without constructing any live
// keys. These are structurally valid fake public receipts, not custody proof.
func differentFixtureRecord(t *testing.T, target publicTarget) record {
	t.Helper()
	r := fixtureRecord(t, target)
	r.Nostr.PublicKey = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
	x, _ := hex.DecodeString(r.Nostr.PublicKey)
	words, err := bech32.ConvertBits(x, 8, 5, true)
	if err != nil {
		t.Fatal(err)
	}
	r.Nostr.NPub, err = bech32.Encode("npub", words)
	if err != nil {
		t.Fatal(err)
	}
	b := base58.Decode(r.Namecoin.XPub)
	b[45] = 2
	copy(b[46:78], x)
	check := sha256.Sum256(b[:78])
	sum := sha256.Sum256(check[:])
	copy(b[78:], sum[:4])
	r.Namecoin.XPub = base58.Encode(b)
	return r
}

// A positive run reports only independently matched public outputs. A lost
// mutation response, wrong purpose, bad readback or output failure does not
// issue a second create, switch targets or delete.
func TestActualMutationAndReadback(t *testing.T) {
	target := publicTarget{"north", "south", 3, 5, 7}
	r := differentFixtureRecord(t, target)
	for _, mode := range []string{"success", "same-public-fixture", "lost", "wrong-target", "wrong-readback", "bad-export", "bad-writer", "acl-denied"} {
		t.Run(mode, func(t *testing.T) {
			var out bytes.Buffer
			var requests [][]string
			w := workflow{
				out: &out,
				prompt: func(s string, _ int) (string, error) {
					if !strings.Contains(s, target.group()) {
						t.Fatal("ACL prompt addressed another target")
					}
					if mode == "acl-denied" {
						return "", nil
					}
					return "ACL-ONE", nil
				},
				run: func(binary string, args ...string) invocation {
					if binary != "/pinned/vault" {
						t.Fatal("runner changed the binary")
					}
					requests = append(requests, args)
					switch args[1] + "/" + args[2] {
					case "recovery/generate":
						if !reflect.DeepEqual(args[3:], target.mutationArguments()) {
							t.Fatal("did not send exact confirmed addresses")
						}
						switch mode {
						case "same-public-fixture":
							return invocation{raw: successReply(t, "recovery", fixtureRecord(t, target)), exit: 0, started: true}
						case "lost":
							return invocation{raw: []byte("unexpected terminal material"), exit: -1, started: true}
						case "wrong-target":
							other := r
							other.Namecoin.Service = "swapped"
							return invocation{raw: successReply(t, "recovery", other), exit: 0, started: true}
						}
						return invocation{raw: successReply(t, "recovery", r), exit: 0, started: true}
					case "recovery/pub":
						current := r
						if mode == "wrong-readback" {
							current.GroupID = strings.Repeat("02", 16)
						}
						return invocation{raw: successReply(t, "recovery", current), exit: 0, started: true}
					case "nostr/pub":
						format := args[len(args)-1]
						value := r.Nostr.PublicKey
						if format == "npub" {
							value = r.Nostr.NPub
						}
						if mode == "bad-export" {
							value = "unexpected private marker"
						}
						return invocation{raw: successReply(t, "nostr", map[string]any{"format": format, "public_key": value}), exit: 0, started: true}
					default:
						t.Fatalf("unexpected command %s/%s", args[1], args[2])
						return invocation{raw: nil, exit: -1, started: true}
					}
				},
			}
			if mode == "bad-writer" {
				w.out = errorWriter{}
			}
			err := w.createActual("/pinned/vault", target)
			want := map[string]string{"same-public-fixture": "actual_matches_public_fixture_keep_do_not_use_or_retry", "lost": unknownMutation, "wrong-target": unknownMutation,
				"wrong-readback": "public_record_readback_mismatch_keep_do_not_retry", "bad-export": "public_export_mismatch_keep_do_not_retry",
				"bad-writer": "public_receipt_unavailable_keep_do_not_retry", "acl-denied": "acl_confirmation_missing_keep_do_not_retry"}[mode]
			wantCalls := map[string]int{"success": 4, "same-public-fixture": 1, "lost": 1, "wrong-target": 1, "wrong-readback": 2, "bad-export": 3, "bad-writer": 4, "acl-denied": 1}[mode]
			if len(requests) != wantCalls {
				t.Fatal("wrong bounded request count", len(requests), wantCalls)
			}
			if mode == "success" {
				if err != nil || !strings.Contains(out.String(), "npub="+r.Nostr.NPub+"\n") || !strings.Contains(out.String(), "namecoin_identity="+target.NamecoinIdentity+"\n") {
					t.Fatal("validated public output unavailable", err)
				}
			} else if err == nil || err.Error() != want || out.Len() != 0 {
				t.Fatal("failed run emitted success or wrong error", err, out.Len())
			}
		})
	}
}

type errorWriter struct{}

func (errorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

// Only an exact typed UNCONFIRMED reference is displayed, and the result
// remains an error. A wrong target, unexpected private field, or wrong phase
// cannot be reflected to the caller as public evidence.
func TestMutationUnconfirmedPublicReference(t *testing.T) {
	target := publicTarget{"north", "south", 3, 5, 7}
	good := fixtureRecord(t, target)
	for _, mode := range []string{"exact", "wrong-target", "bad-op", "bad-exit", "private-field", "broken-writer"} {
		t.Run(mode, func(t *testing.T) {
			ref := good
			u := unknownRecovery{"unknown", "generate", ref}
			code := 1
			switch mode {
			case "wrong-target":
				u.Reference.Nostr.Service = "other"
			case "bad-op":
				u.Operation = "restore"
			case "bad-exit":
				code = 3
			}
			raw, err := json.Marshal(map[string]any{"ok": false, "command": "recovery", "result": u, "error": map[string]string{
				"code": "recovery_outcome_unknown", "message": "Recovery mutation outcome is unknown; public reference is UNCONFIRMED",
				"hint": "reconcile the UNCONFIRMED public reference; do not retry or delete",
			}})
			if err != nil {
				t.Fatal(err)
			}
			if mode == "private-field" {
				raw = bytes.Replace(raw, []byte(`"group_id":`), []byte(`"secret":"do not expose","group_id":`), 1)
			}
			var out bytes.Buffer
			w := workflow{out: &out}
			want := unknownMutation
			if mode == "broken-writer" {
				w.out = errorWriter{}
				want = "recovery_outcome_unknown_public_reference_unavailable_do_not_retry_or_delete"
			}
			_, err = w.mutationReply(invocation{raw: raw, exit: code, started: true}, target, "generate")
			if err == nil || err.Error() != want {
				t.Fatal("lost stop classification", err)
			}
			if mode == "exact" && !strings.HasPrefix(out.String(), "UNCONFIRMED public reference;") || mode != "exact" && out.Len() != 0 {
				t.Fatal("wrong public outcome projection", out.Len())
			}
		})
	}
}

// A second identity refusal (including EOF) happens after its own prompt;
// the plan shown with the first prompt uses both exact, different addresses.
func TestConfirmBothIdentities(t *testing.T) {
	actual, qual := publicTarget{"north", "south", 3, 5, 7}, publicTarget{"disposable-north", "disposable-south", 1, 1, 1}
	p := installation{paths: Paths{InstallDirectory: "/example/release"}}
	for _, mode := range []string{"right", "first-wrong", "second-wrong", "second-eof"} {
		t.Run(mode, func(t *testing.T) {
			calls := 0
			w := workflow{prompt: func(prompt string, _ int) (string, error) {
				calls++
				if calls == 1 {
					for _, text := range []string{actual.group(), actual.nostr(), actual.namecoin(), qual.group(), qual.namecoin(), "/example/release", "Retype Nostr identity:"} {
						if !strings.Contains(prompt, text) {
							t.Fatal("plan omission", text)
						}
					}
					if mode == "first-wrong" {
						return "south", nil
					}
					return "north", nil
				}
				if prompt != "Retype Namecoin identity: " {
					t.Fatal("separate second prompt missing")
				}
				switch mode {
				case "second-wrong":
					return "north", nil
				case "second-eof":
					return "", io.EOF
				}
				return "south", nil
			}}
			err := w.confirm(p, actual, qual)
			if (err == nil) != (mode == "right") || calls != map[string]int{"right": 2, "first-wrong": 1, "second-wrong": 2, "second-eof": 2}[mode] {
				t.Fatal("wrong confirmation outcome", err, calls)
			}
		})
	}
}

// Exact no-effect replies preserve their classes. The same apparent failure
// after dispatch or with contradictory exit/status remains uncertain.
func TestMutationRefusalClasses(t *testing.T) {
	target := publicTarget{"north", "south", 1, 1, 1}
	for _, tc := range []struct {
		code, want   string
		exit, status int
	}{
		{"recovery_duplicate", "recovery_duplicate_no_change", 3, 0},
		{"recovery_identity_confirmation_failed", "recovery_identity_confirmation_failed", 3, 0},
		{"recovery_generation_exhausted", "recovery_generation_exhausted", 3, 0},
		{"recovery_lock_unavailable", "recovery_lock_unavailable", 3, 0},
		{"recovery_identity_confirmation_failed", unknownMutation, 3, -1},
		{"recovery_identity_confirmation_failed", unknownMutation, 1, 0},
		{"security", unknownMutation, 1, -25293},
		{"recovery_duplicate", unknownMutation, 1, 0},
		{"recovery_duplicate", unknownMutation, 4, 0},
	} {
		var out bytes.Buffer
		w := workflow{out: &out}
		_, err := w.mutationReply(invocation{raw: failedReply(t, "recovery", tc.code, tc.status), exit: tc.exit, started: true}, target, "generate")
		if err == nil || err.Error() != tc.want || out.Len() != 0 {
			t.Fatal("wrong refusal class", err)
		}
	}
	w := workflow{out: errorWriter{}}
	for _, op := range []string{"generate", "restore"} {
		for _, started := range []bool{false, true} {
			_, err := w.mutationReply(invocation{exit: -1, started: started}, target, op)
			want := "vault_child_not_started"
			if started {
				want = unknownMutation
			}
			if err == nil || err.Error() != want {
				t.Fatal("failed start and lost child reply were conflated", err)
			}
		}
	}
}

// The in-process planner preserves a definite exhaustion refusal. An opaque
// inventory failure cannot become an actionable no-change policy code.
func TestPlanGenerationExhaustion(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{&keyvault.Refusal{Code: "recovery_generation_exhausted"}, "recovery_generation_exhausted"},
		{errors.New("private diagnostic"), "vault_plan_refused"},
	} {
		w := workflow{planner: plannerFunc(func(keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) {
			return keyvault.RecoveryPlan{}, tc.err
		})}
		_, err := w.plan(Config{NostrIdentity: "north", NamecoinIdentity: "south"})
		if err == nil || err.Error() != tc.want {
			t.Fatal("incorrect advisory refusal", err)
		}
	}
}
