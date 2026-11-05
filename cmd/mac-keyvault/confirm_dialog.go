package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os/exec"
	"regexp"
	"strconv"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// confirm-dialog is the reviewed consent hook for `ssh-agent --confirm-exec`.
// It reads one SSHConfirmation from stdin, shows a macOS dialog built only
// from validated fields, and exits 0 only when the owner pressed the grant
// button. Deny is the default and cancel button; giving up, a closed dialog,
// malformed input or any osascript failure refuses.
//
// The dialog is consent UX, not a hardware boundary: a process of the same
// user with Accessibility permission could press the button by script.

const (
	maxConfirmInput   = 4096
	defaultDialogWait = 12 * time.Second
	maxDialogWait     = 55 * time.Second
)

// dialogScript receives the prompt, the grant label and the wait in seconds
// as argv; no input is ever spliced into script text.
const dialogScript = `on run argv
set r to display dialog (item 1 of argv) with title "mac-keyvault" buttons {"Deny", (item 2 of argv)} default button "Deny" cancel button "Deny" giving up after ((item 3 of argv) as integer) with icon caution
return (button returned of r) & "|" & ((gave up of r) as text)
end run`

// confirmFields maps each accepted member to its JSON type: '"' string,
// '0' non-negative integer.
var confirmFields = map[string]byte{"purpose": '"', "address": '"', "version": '0', "fingerprint": '"', "sha256": '"', "until": '"'}

var (
	fingerprintPattern = regexp.MustCompile(`^SHA256:[A-Za-z0-9+/]{43}$`)
	digestPattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	confirmNow         = time.Now
	runOSAScript       = func(ctx context.Context, args ...string) ([]byte, error) {
		cmd := dialogCommand(ctx, args...)
		return cmd.Output()
	}
)

// dialogCommand bounds Output's pipe cleanup after the context deadline or
// process exit, even when an osascript descendant inherits stdout/stderr.
func dialogCommand(ctx context.Context, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, "/usr/bin/osascript", args...)
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin"}
	cmd.WaitDelay = time.Second
	return cmd
}

func runConfirmDialog(args []string, out output) int {
	fs := flag.NewFlagSet("confirm-dialog", flag.ContinueOnError)
	wait := fs.Duration("wait", defaultDialogWait, "dialog gives up (refuses) after this long, at most 55s")
	positional, err := parseFlags(fs, args)
	if err != nil {
		return out.fail(err)
	}
	if len(positional) != 0 || *wait < time.Second || *wait > maxDialogWait {
		return out.fail(usagef("confirm-dialog takes no arguments and --wait in [1s, 55s]"))
	}
	req, err := readConfirmation(stdinReader)
	if err != nil {
		return out.fail(&keyvault.Refusal{Code: keyvault.CodeConfirmationRequired, Message: "confirmation request refused: " + err.Error(), Hint: "confirm-dialog reads one ssh-agent confirmation object on stdin"})
	}
	prompt, grant := confirmPrompt(req)
	ctx, cancel := context.WithTimeout(context.Background(), *wait+5*time.Second)
	defer cancel()
	result, runErr := runOSAScript(ctx, "-e", dialogScript, prompt, grant, strconv.Itoa(int(wait.Seconds())))
	if runErr != nil || string(result) != grant+"|false\n" {
		return out.fail(&keyvault.Refusal{Code: keyvault.CodeConfirmationRequired, Message: "not confirmed", Hint: "only the " + grant + " button grants"})
	}
	return exitOK
}

// readConfirmation accepts exactly one well-formed request: known fields
// only, no trailing data, and the fields its purpose requires.
func readConfirmation(r io.Reader) (keyvault.SSHConfirmation, error) {
	var req keyvault.SSHConfirmation
	data, err := io.ReadAll(io.LimitReader(r, maxConfirmInput+1))
	if err != nil || len(data) > maxConfirmInput {
		return req, errors.New("input unreadable or too large")
	}
	// One document, one object, no repeated (or escape-equivalent) member,
	// exact member names: a struct decode alone would collapse duplicates
	// and match names case-insensitively.
	object, err := signerclient.DecodeObject(data)
	if err != nil {
		return req, errors.New("malformed request")
	}
	for _, name := range object.Names() {
		raw, _ := object.Get(name)
		kind, known := confirmFields[name]
		if !known {
			return req, errors.New("unknown field")
		}
		// Exact JSON types: a null or another type must not collapse into
		// a zero value that later passes as "absent".
		first := bytes.TrimSpace(raw)
		if len(first) == 0 || (kind == '"' && first[0] != '"') || (kind == '0' && (first[0] < '0' || first[0] > '9')) {
			return req, errors.New("wrong field type")
		}
	}
	required := []string{"purpose", "address", "version", "fingerprint"}
	var purpose string
	if raw, ok := object.Get("purpose"); ok {
		_ = json.Unmarshal(raw, &purpose)
	}
	if purpose == keyvault.SSHConfirmUnlock {
		required = append(required, "until")
		if object.Has("sha256") {
			return req, errors.New("an unlock request carries no sha256")
		}
	} else {
		required = append(required, "sha256")
		if object.Has("until") {
			return req, errors.New("a sign request carries no until")
		}
	}
	for _, name := range required {
		if !object.Has(name) {
			return req, errors.New("missing " + name)
		}
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&req); err != nil {
		return req, errors.New("malformed request")
	}
	if _, err := keyvault.ParseAddress(req.Address, keyvault.KindKey, req.Version); err != nil || req.Version < 1 {
		return req, errors.New("invalid address or version")
	}
	if !fingerprintPattern.MatchString(req.Fingerprint) {
		return req, errors.New("invalid fingerprint")
	}
	switch req.Purpose {
	case keyvault.SSHConfirmSign:
		if !digestPattern.MatchString(req.SHA256) || req.Until != "" {
			return req, errors.New("a sign request needs sha256 and no until")
		}
	case keyvault.SSHConfirmUnlock:
		until, err := time.Parse(time.RFC3339, req.Until)
		if err != nil || req.SHA256 != "" || !until.After(confirmNow()) {
			return req, errors.New("an unlock request needs a future until and no sha256")
		}
	default:
		return req, errors.New("unknown purpose")
	}
	return req, nil
}

func confirmPrompt(req keyvault.SSHConfirmation) (prompt, grant string) {
	if req.Purpose == keyvault.SSHConfirmUnlock {
		until, _ := time.Parse(time.RFC3339, req.Until)
		return fmt.Sprintf("Unlock %s v%d for agent signing until %s?\n\nKey %s\n\nDeny unless you asked for this unlock.",
			req.Address, req.Version, until.Local().Format("2006-01-02 15:04 MST"), req.Fingerprint), "Unlock"
	}
	return fmt.Sprintf("Sign with %s v%d?\n\nKey %s\nRequest %s…\n\nDeny unless you started this signature.",
		req.Address, req.Version, req.Fingerprint, req.SHA256[:16]), "Sign"
}
