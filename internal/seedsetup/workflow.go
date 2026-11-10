package seedsetup

import (
	"encoding/json"
	"fmt"
	"io"
	"reflect"
	"strings"
)

const qualificationDigest = "0000000000000000000000000000000000000000000000000000000000000000"

// Published known-public qualification fixture. The PTY driver accepts no
// secret input and cannot start a generate command.
const publicFixturePhrase = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"

const (
	publicFixtureNPub   = "npub16sdj9zv4f8sl85e45vgq9n7nsgt5qphpvmf7vk8r5hhvmdjxx4es8rq74h"
	publicFixtureXPub   = "xpub6CABQFHfXJj3tKAbMDiDhKAkZoGV3PX3Nt5dso2UY9Hymf6kXKiwze3yJUFBrpqq7iDFyV4EgNuxG5tLvxVSqnZ3EkQyK4VrYmPFzUyB1es"
	publicFixtureOrigin = "[57471a66/84h/7h/0h]"
)

type runner func(string, ...string) ([]byte, int)
type fixtureRestorer func(string, publicTarget) ([]byte, int)
type promptFunc func(string, int) (string, error)

type envelope struct {
	OK      bool            `json:"ok"`
	Command string          `json:"command"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
		Hint    string `json:"hint"`
		Status  int    `json:"os_status,omitempty"`
	} `json:"error,omitempty"`
}

type workflow struct {
	run     runner
	restore fixtureRestorer
	prompt  promptFunc
	out     io.Writer
}

func writePublic(w io.Writer, message string) error {
	if w == nil {
		return refused("public_output_unavailable")
	}
	n, err := io.WriteString(w, message)
	if err != nil || n != len(message) {
		return refused("public_output_unavailable")
	}
	return nil
}

func readReply(raw []byte, exit int, family string) (envelope, error) {
	var e envelope
	if decode(raw, &e) != nil || e.Command != family {
		return envelope{}, refused("response_schema")
	}
	if e.OK {
		if exit != 0 || e.Error != nil || len(e.Result) == 0 {
			return envelope{}, refused("response_consistency")
		}
	} else if exit < 1 || exit > 3 || e.Error == nil || e.Error.Code == "" ||
		(len(e.Result) != 0 && (family != "recovery" || e.Error.Code != "recovery_outcome_unknown")) {
		return envelope{}, refused("response_consistency")
	}
	return e, nil
}

func (w workflow) call(binary, family, op string, args ...string) (envelope, int, error) {
	raw, exit := w.run(binary, append([]string{"--json", family, op}, args...)...)
	defer clear(raw)
	e, err := readReply(raw, exit, family)
	return e, exit, err
}

func (w workflow) requireRefusal(binary, family, op, code string, exitCode, status int, args ...string) error {
	e, exit, err := w.call(binary, family, op, args...)
	if err != nil || e.OK || exit != exitCode || e.Error.Code != code || e.Error.Status != status || len(e.Result) != 0 {
		return refused("qualification_expected_refusal_missing")
	}
	return nil
}

func (w workflow) plan(binary string, c Config) (publicTarget, error) {
	args := []string{"--nostr-identity", c.NostrIdentity, "--namecoin-identity", c.NamecoinIdentity}
	for _, opt := range []struct {
		flag string
		n    int
	}{{"--version", c.Version}, {"--nostr-version", c.NostrVersion}, {"--namecoin-version", c.NamecoinVersion}} {
		if opt.n != 0 {
			args = append(args, opt.flag, fmt.Sprint(opt.n))
		}
	}
	e, _, err := w.call(binary, "recovery", "plan", args...)
	if err != nil || !e.OK {
		return publicTarget{}, refused("vault_plan_refused")
	}
	return acceptPlan(e.Result, c)
}

func (w workflow) confirm(p installation, actual, qualification publicTarget) error {
	if actual.validate() != nil || qualification.validate() != nil || actual.NostrIdentity == qualification.NostrIdentity || actual.NamecoinIdentity == qualification.NamecoinIdentity {
		return refused("plan_identity_collision")
	}
	var summary strings.Builder
	fmt.Fprintf(&summary, "Nostr identity: %s\nNamecoin identity: %s\n", actual.NostrIdentity, actual.NamecoinIdentity)
	fmt.Fprintf(&summary, "Actual: %s; %s; %s\nDisposable public fixture: %s; %s; %s\n",
		actual.group(), actual.nostr(), actual.namecoin(), qualification.group(), qualification.nostr(), qualification.namecoin())
	fmt.Fprintf(&summary, "Install and verify a matched release at %s\n", p.paths.InstallDirectory)
	for _, path := range p.writePaths() {
		fmt.Fprintln(&summary, "  "+path)
	}
	fmt.Fprintln(&summary, "Keychain service: works.relux.mac-keyvault.nostr.v1; one item for each displayed group, including sealed purpose keys. Existing keys and the disposable record are kept.")
	fmt.Fprintln(&summary, "Allow two Touch ID checks, one for the public fixture and one for the actual pair. Decline a password prompt. Prepare two offline backups; the vault alone displays the actual words.")
	for _, check := range []struct{ label, want string }{{"Nostr", actual.NostrIdentity}, {"Namecoin", actual.NamecoinIdentity}} {
		message := "Retype " + check.label + " identity: "
		if summary.Len() != 0 {
			message = summary.String() + message
			summary.Reset()
		}
		answer, err := w.prompt(message, 40)
		if err != nil || answer != check.want {
			return refused("identity_confirmation_refused")
		}
	}
	return nil
}

func pinnedFixture(r record) bool {
	return r.Nostr.NPub == publicFixtureNPub && r.Namecoin.XPub == publicFixtureXPub && r.Namecoin.Origin == publicFixtureOrigin
}

type unknownRecovery struct {
	Outcome   string `json:"outcome"`
	Operation string `json:"operation"`
	Reference record `json:"reference"`
}

const unknownMutation = "recovery_outcome_unknown_reconcile_do_not_retry_or_delete"

func (w workflow) mutationReply(raw []byte, exit int, target publicTarget, op string) (record, error) {
	defer clear(raw)
	var zero record
	e, err := readReply(raw, exit, "recovery")
	if err != nil {
		return zero, refused(unknownMutation)
	}
	if e.OK {
		var r record
		if decode(e.Result, &r) != nil || validateRecord(r, target) != nil || op == "restore" && !pinnedFixture(r) {
			return zero, refused(unknownMutation)
		}
		return r, nil
	}
	if e.Error.Code != "recovery_outcome_unknown" {
		// Only a protocol-level duplicate is actionable as a definite no-op.
		// Suppress all child diagnostics, including arbitrary failure strings.
		if exit == 3 && e.Error.Code == "recovery_duplicate" && e.Error.Status == 0 && len(e.Result) == 0 {
			return zero, refused("recovery_duplicate_no_change")
		}
		return zero, refused(unknownMutation)
	}
	var u unknownRecovery
	if exit == 1 && e.Error.Status == 0 &&
		e.Error.Message == "Recovery mutation outcome is unknown; public reference is UNCONFIRMED" &&
		e.Error.Hint == "reconcile the UNCONFIRMED public reference; do not retry or delete" &&
		decode(e.Result, &u) == nil && u.Outcome == "unknown" && u.Operation == op &&
		validateRecord(u.Reference, target) == nil && (op != "restore" || pinnedFixture(u.Reference)) {
		public, marshalErr := json.Marshal(u)
		if marshalErr == nil {
			_ = writePublic(w.out, "UNCONFIRMED public reference; reconcile; do not retry or delete: "+string(public)+"\n")
		}
	}
	return zero, refused(unknownMutation)
}

func (w workflow) assertCurrent(binary string, target publicTarget, expected record) error {
	e, _, err := w.call(binary, "recovery", "pub", target.NostrIdentity, "--version", fmt.Sprint(target.Version))
	var current record
	if err != nil || !e.OK || decode(e.Result, &current) != nil || validateRecord(current, target) != nil || !reflect.DeepEqual(current, expected) {
		return refused("public_record_readback_mismatch_keep_do_not_retry")
	}
	return nil
}

func (w workflow) requireACL(target publicTarget) error {
	answer, err := w.prompt("Inspect Access Control for works.relux.mac-keyvault.nostr.v1 / "+target.group()+": only the newly installed vault may access it. Never show its password. Type ACL-ONE after checking: ", 7)
	if err != nil || answer != "ACL-ONE" {
		return refused("acl_confirmation_missing_keep_do_not_retry")
	}
	return nil
}

func (w workflow) qualify(binary, foreign string, target publicTarget) error {
	raw, exit := w.restore(binary, target)
	r, err := w.mutationReply(raw, exit, target, "restore")
	if err != nil {
		return err
	}
	if err := w.requireACL(target); err != nil {
		return err
	}
	identity := []string{target.NostrIdentity + "/nostr", "--version", fmt.Sprint(target.NostrVersion)}
	signArgs := append(append([]string(nil), identity...), "--digest", qualificationDigest)
	e, _, err := w.call(binary, "nostr", "sign", signArgs...)
	var signed struct {
		Algorithm string `json:"algorithm"`
		Signature string `json:"signature"`
	}
	if err != nil || !e.OK || decode(e.Result, &signed) != nil || signed.Algorithm != "secp256k1-bip340" || !verifyDigest(r.Nostr.PublicKey, signed.Signature, qualificationDigest) {
		return refused("qualification_signature")
	}
	otherKey := "f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9"
	if otherKey == r.Nostr.PublicKey || verifyDigest(otherKey, signed.Signature, qualificationDigest) {
		return refused("qualification_wrong_key_control")
	}
	if err := w.requireRefusal(foreign, "nostr", "sign", "security", 1, -25293, signArgs...); err != nil {
		return err
	}
	if err := w.requireRefusal(binary, "recovery", "plan", "recovery_duplicate", 3, 0, target.mutationArguments()...); err != nil {
		return err
	}
	if err := w.requireRefusal(binary, "nostr", "sign", "usage", 2, 0, append(append([]string(nil), identity...), "--digest", "00")...); err != nil {
		return err
	}
	if err := w.requireRefusal(binary, "nostr", "pub", "usage", 2, 0, append(append([]string(nil), identity...), "--format", "nsec")...); err != nil {
		return err
	}
	if err := w.assertCurrent(binary, target, r); err != nil {
		return err
	}
	return writePublic(w.out, "Disposable fixture qualified; its record is kept. The next prompt is for the actual pair.\n")
}

func (w workflow) createActual(binary string, target publicTarget) error {
	args := append([]string{"--json", "recovery", "generate"}, target.mutationArguments()...)
	raw, exit := w.run(binary, args...)
	r, err := w.mutationReply(raw, exit, target, "generate")
	if err != nil {
		return err
	}
	if r.Nostr.NPub == publicFixtureNPub || r.Namecoin.XPub == publicFixtureXPub {
		return refused("actual_matches_public_fixture_keep_do_not_use_or_retry")
	}
	if err := w.requireACL(target); err != nil {
		return err
	}
	if err := w.assertCurrent(binary, target, r); err != nil {
		return err
	}
	for _, pair := range [][2]string{{"x-only-hex", r.Nostr.PublicKey}, {"npub", r.Nostr.NPub}} {
		e, _, err := w.call(binary, "nostr", "pub", target.NostrIdentity+"/nostr", "--version", fmt.Sprint(target.NostrVersion), "--format", pair[0])
		var p struct {
			Format    string `json:"format"`
			PublicKey string `json:"public_key"`
		}
		if err != nil || !e.OK || decode(e.Result, &p) != nil || p.Format != pair[0] || p.PublicKey != pair[1] {
			return refused("public_export_mismatch_keep_do_not_retry")
		}
	}
	if err := writePublic(w.out, fmt.Sprintf("CREATED PUBLIC IDENTITY\nnostr_identity=%s\nnamecoin_identity=%s\ngroup=%s\nnostr_record=%s\nnamecoin_record=%s\nx_only_hex=%s\nnpub=%s\nnamecoin_account_xpub=%s\nnamecoin_origin=%s\n",
		target.NostrIdentity, target.NamecoinIdentity, target.group(), target.nostr(), target.namecoin(), r.Nostr.PublicKey, r.Nostr.NPub, r.Namecoin.XPub, r.Namecoin.Origin)); err != nil {
		return refused("public_receipt_unavailable_keep_do_not_retry")
	}
	return nil
}
