package main

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type recoveryPipeOperations struct{ recoveryReceiptOperations }

func (f *recoveryPipeOperations) Create(q keyvault.RecoveryRequest, t keyvault.RecoveryTerminal, r bool) (keyvault.RecoveryRecord, error) {
	record, err := f.recoveryReceiptOperations.Create(q, t, r)
	fmt.Fprintln(os.Stderr, "fixture_effect=1")
	return record, err
}
func (f *recoveryPipeOperations) Delete(q keyvault.RecoveryDeleteRequest, terminal keyvault.RecoveryTerminal) (keyvault.RecoveryRecord, error) {
	record, err := f.recoveryReceiptOperations.Delete(q, terminal)
	fmt.Fprintln(os.Stderr, "fixture_effect=1")
	return record, err
}

// This child executes only injected fake mutations. Its stdout is an actual
// fd1 pipe supplied by the parent; no vault/Keychain/helper route is selected.
func TestRecoveryPipeChild(t *testing.T) {
	if os.Getenv("RECOVERY_PIPE_CHILD") != "1" {
		return
	}
	if os.Getenv("RECOVERY_PIPE_HANDLER") == "1" {
		signal.Ignore(syscall.SIGPIPE)
	}
	f := &recoveryPipeOperations{}
	newRecoveryBackend = func() keyvault.RecoveryBackend { return nil }
	makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return f }
	newRecoveryTerminal = func() (ownerRecoveryTerminal, error) { return recoveryReceiptTerminal{}, nil }
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{Path: t.TempDir() + "/lock"}, nil }
	op := os.Getenv("RECOVERY_PIPE_OP")
	args := []string{"recovery", op}
	if os.Getenv("RECOVERY_PIPE_JSON") == "1" {
		args = append([]string{"--json"}, args...)
	}
	switch op {
	case "delete":
		args = append(args, "fixture", "--version", "1", "--expected-group-id", strings.Repeat("1", 32))
	case "generate", "restore":
		args = append(args, "--service", "fixture", "--version", "1", "--nostr-version", "2", "--namecoin-version", "1")
		if op == "restore" {
			args = append(args, recoveryPublicFixturePins(t)...)
		}
	default:
		t.Fatal("invalid public fixture operation")
	}
	code := run(args, os.Stdout, os.Stderr)
	fmt.Fprintf(os.Stderr, "fixture_return=%d effects=%d\n", code, f.effects)
	os.Exit(code)
}

// A real closed fd1 pipe must return exit1 and reconciliation guidance after
// exactly one fake effect. Open pipes and an independently ignored SIGPIPE are
// positive controls, covering generate/restore/delete in JSON and text.
func TestRecoveryClosedStdoutPipe(t *testing.T) {
	for _, op := range []string{"generate", "restore", "delete"} {
		for _, format := range []string{"text", "json"} {
			for _, mode := range []string{"open", "closed", "closed-handler"} {
				t.Run(op+"/"+format+"/"+mode, func(t *testing.T) {
					exe, err := os.Executable()
					if err != nil {
						t.Fatal(err)
					}
					cmd := exec.Command(exe, "-test.run=^TestRecoveryPipeChild$")
					cmd.Env = append(os.Environ(), "RECOVERY_PIPE_CHILD=1", "RECOVERY_PIPE_OP="+op, "RECOVERY_PIPE_JSON="+map[string]string{"text": "0", "json": "1"}[format], "RECOVERY_PIPE_HANDLER="+map[bool]string{true: "1", false: "0"}[mode == "closed-handler"])
					var stdout, stderr bytes.Buffer
					cmd.Stderr = &stderr
					cmd.Stdout = &stdout
					if mode != "open" {
						r, w, e := os.Pipe()
						if e != nil {
							t.Fatal(e)
						}
						r.Close()
						defer w.Close()
						cmd.Stdout = w
					}
					err = cmd.Run()
					code := cmd.ProcessState.ExitCode()
					if strings.Count(stderr.String(), "fixture_effect=1") != 1 {
						t.Fatalf("fake effect count not one: %q", stderr.String())
					}
					if mode == "open" {
						if err != nil || code != 0 || stdout.Len() == 0 || !strings.Contains(stderr.String(), "fixture_return=0 effects=1") {
							t.Fatal("valid open pipe failed", err)
						}
						return
					}
					if code != 1 || !strings.Contains(stderr.String(), "fixture_return=1 effects=1") || !strings.Contains(stderr.String(), "reconcile") || !strings.Contains(stderr.String(), "do not retry or delete") {
						t.Fatalf("closed stdout lost mutation receipt: code=%d err=%v stderr=%q", code, err, stderr.String())
					}
				})
			}
		}
	}
}
