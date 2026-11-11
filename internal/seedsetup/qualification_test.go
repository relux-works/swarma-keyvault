package seedsetup

import (
	"bytes"
	"reflect"
	"testing"
)

// Fixed public BIP-340 witness for the published fixture key, zero digest
// and zero auxiliary randomness. It contains no secret key.
const publicFixtureSignature = "87d54f8013af9b165175fa45900a67015995e66b292e225a1ac865928bd8bc9e458fe60eea771387b17e1a926135a11da653d87083d42ba7eec1bf05e14e7efa"

// The qualification must use the exact disposable pair, validate its published
// fixture signature, and obtain each intended refusal. The duplicate probe is
// read-only. These fakes never execute signed binaries or touch a Keychain.
func TestQualificationChecks(t *testing.T) {
	target := publicTarget{"qual-north", "qual-south", 1, 1, 1}
	r := fixtureRecord(t, target)
	sig := publicFixtureSignature
	for _, mode := range []string{"success", "wrong-pins", "foreign-accepted", "wrong-status", "duplicate-accepted", "digest-accepted", "private-export-accepted"} {
		t.Run(mode, func(t *testing.T) {
			restores, calls := 0, 0
			var out bytes.Buffer
			w := workflow{
				out:    &out,
				prompt: func(_ string, _ int) (string, error) { return "ACL-ONE", nil },
				restore: func(binary string, got publicTarget) invocation {
					restores++
					if binary != "installed-vault" || got != target {
						t.Fatal("different disposable target")
					}
					if mode == "wrong-pins" {
						return invocation{raw: successReply(t, "recovery", differentFixtureRecord(t, got)), exit: 0, started: true}
					}
					return invocation{raw: successReply(t, "recovery", r), exit: 0, started: true}
				},
				run: func(binary string, args ...string) invocation {
					calls++
					if len(args) < 3 || args[0] != "--json" || args[2] == "generate" {
						t.Fatal("qualification attempted unexpected mutation")
					}
					switch args[1] + "/" + args[2] {
					case "nostr/sign":
						if args[3] != target.NostrIdentity+"/nostr" || args[4] != "--version" || args[5] != "1" || args[6] != "--digest" {
							t.Fatal("wrong Nostr qualification address or arguments")
						}
						digest := args[7]
						if binary == "foreign" {
							if digest != qualificationDigest {
								t.Fatal("foreign probe was not the fixed digest")
							}
							if mode != "foreign-accepted" {
								status := -25293
								if mode == "wrong-status" {
									status = -25308
								}
								return invocation{raw: failedReply(t, "nostr", "security", status), exit: 1, started: true}
							}
						} else if digest == "00" && mode != "digest-accepted" {
							return invocation{raw: failedReply(t, "nostr", "usage", 0), exit: 2, started: true}
						}
						return invocation{raw: successReply(t, "nostr", map[string]string{"algorithm": "secp256k1-bip340", "signature": sig}), exit: 0, started: true}
					case "recovery/plan":
						if !reflect.DeepEqual(args[3:], target.mutationArguments()) {
							t.Fatal("read-only duplicate probe changed target")
						}
						if mode != "duplicate-accepted" {
							return invocation{raw: failedReply(t, "recovery", "recovery_duplicate", 0), exit: 3, started: true}
						}
						return invocation{raw: successReply(t, "recovery", struct{}{}), exit: 0, started: true}
					case "nostr/pub":
						if mode == "private-export-accepted" {
							return invocation{raw: successReply(t, "nostr", map[string]string{"bogus": "not public evidence"}), exit: 0, started: true}
						}
						return invocation{raw: failedReply(t, "nostr", "usage", 0), exit: 2, started: true}
					case "recovery/pub":
						return invocation{raw: successReply(t, "recovery", r), exit: 0, started: true}
					default:
						t.Fatal("unexpected qualification operation")
						return invocation{raw: nil, exit: -1, started: true}
					}
				},
			}
			err := w.qualify("installed-vault", "foreign", target)
			wantCalls := map[string]int{"success": 6, "wrong-pins": 0, "foreign-accepted": 2, "wrong-status": 2,
				"duplicate-accepted": 3, "digest-accepted": 4, "private-export-accepted": 5}[mode]
			if restores != 1 || calls != wantCalls || (err == nil) != (mode == "success") || (out.Len() != 0) != (mode == "success") {
				t.Fatal("qualification did not stop at its control", restores, calls, wantCalls, err)
			}
		})
	}
}
