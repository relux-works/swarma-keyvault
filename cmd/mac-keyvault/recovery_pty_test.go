//go:build darwin || linux

package main

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"golang.org/x/sys/unix"
)

const recoveryTTYFixture = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"

type recoveryPTYStore struct{ stores int }

func (*recoveryPTYStore) Create(keyvault.NostrRecord) (keyvault.NostrRecord, error) {
	panic("fixture reached unused operation")
}
func (*recoveryPTYStore) List() ([]keyvault.NostrRecord, error) { return nil, nil }
func (*recoveryPTYStore) Sign(keyvault.NostrRecord, []byte) ([]byte, error) {
	panic("fixture reached unused operation")
}
func (*recoveryPTYStore) RecoveryList() ([]keyvault.RecoveryRecord, error) { return nil, nil }
func (f *recoveryPTYStore) RecoveryStore(keyvault.RecoveryRecord, []byte) error {
	f.stores++
	return nil
}
func (*recoveryPTYStore) RecoveryDelete(keyvault.RecoveryRecord) error { return errors.New("unused") }
func (*recoveryPTYStore) NostrDelete(keyvault.NostrRecord) error       { return errors.New("unused") }

type recoveryPTYManager struct{ store *recoveryPTYStore }

func (m recoveryPTYManager) Create(q keyvault.RecoveryRequest, terminal keyvault.RecoveryTerminal, restore bool) (keyvault.RecoveryRecord, error) {
	a, b := q.NostrIdentity, q.NamecoinIdentity
	if q.Service != "" {
		a, b = q.Service, q.Service
	}
	p := keyvault.RecoveryPlan{NostrIdentity: a, NamecoinIdentity: b, Group: fmt.Sprintf("%s/recovery@%d", a, q.Version), NostrRecord: fmt.Sprintf("%s/nostr@%d", a, q.NostrVersion), NamecoinRecord: fmt.Sprintf("%s/namecoin@%d", b, q.NamecoinVersion)}
	if err := terminal.ConfirmIdentities(p); err != nil {
		return keyvault.RecoveryRecord{}, errors.New("identity confirmation refused")
	}
	if restore {
		phrase, err := terminal.ReadMnemonic()
		defer clear(phrase)
		if err != nil {
			return keyvault.RecoveryRecord{}, fmt.Errorf("fixture restore refused: %w", err)
		}
		if !bytes.Equal(phrase, []byte(recoveryTTYFixture)) {
			return keyvault.RecoveryRecord{}, errors.New("fixture restore mismatch")
		}
	} else {
		words := bytes.Fields([]byte(recoveryTTYFixture))
		defer func() {
			for _, word := range words {
				clear(word)
			}
		}()
		if err := terminal.ConfirmMnemonic(words); err != nil {
			return keyvault.RecoveryRecord{}, fmt.Errorf("fixture confirmation refused: %w", err)
		}
	}
	r := keyvault.RecoveryRecord{Service: q.Service, Version: q.Version}
	if err := m.store.RecoveryStore(r, []byte("public fixture ciphertext")); err != nil {
		return r, err
	}
	return r, nil
}
func (recoveryPTYManager) Describe(string, int) (keyvault.RecoveryRecord, error) {
	return keyvault.RecoveryRecord{}, errors.New("unused")
}
func (recoveryPTYManager) Delete(keyvault.RecoveryDeleteRequest, keyvault.RecoveryTerminal) (keyvault.RecoveryRecord, error) {
	return keyvault.RecoveryRecord{}, errors.New("unused")
}
func (recoveryPTYManager) Plan(keyvault.RecoveryRequest) (keyvault.RecoveryPlan, error) {
	return keyvault.RecoveryPlan{}, errors.New("unused")
}

// Child uses the actual CLI/parser and real /dev/tty frontend, with an explicit
// fake crypto/custody manager. Cryptographic/atomic behavior is tested in the
// keyvault package; this test never opens a real Keychain or Enclave key.
func TestRecoveryPTYChild(t *testing.T) {
	mode := os.Getenv("RECOVERY_PTY_FIXTURE")
	if mode == "" {
		t.Skip("isolated child fixture only")
	}
	before, beforeErr := recoveryGetTermios(int(os.Stdin.Fd()))
	if mode == "random-fail" {
		newRecoveryTerminal = func() (ownerRecoveryTerminal, error) {
			value, err := openRecoveryTerminal()
			if err == nil {
				value.(*recoveryTerminal).random = bytes.NewReader(nil)
			}
			return value, err
		}
	}
	f := &recoveryPTYStore{}
	newRecoveryBackend = func() keyvault.RecoveryBackend { return f }
	makeRecoveryManager = func(keyvault.RecoveryBackend, keyvault.Locker) recoveryOperations { return recoveryPTYManager{f} }
	vaultLock = func() (keyvault.FileLock, error) { return keyvault.FileLock{Path: t.TempDir() + "/fixture.lock"}, nil }
	args := []string{"--json", "recovery", "generate", "--service", "fixture", "--version", "1", "--nostr-version", "1", "--namecoin-version", "1"}
	if strings.HasPrefix(mode, "restore") {
		args[2] = "restore"
		args = append(args, recoveryPublicFixturePins(t)...)
	}
	_ = run(args, os.Stdout, os.Stderr)
	after, afterErr := recoveryGetTermios(int(os.Stdin.Fd()))
	if mode != "no-tty" {
		fmt.Fprintf(os.Stderr, "fixture_terminal_restored=%t\n", beforeErr == nil && afterErr == nil && before.Lflag == after.Lflag && before.Iflag == after.Iflag)
	}
	fmt.Fprintf(os.Stderr, "fixture_stores=%d\n", f.stores)
}

func recoveryFixtureLeak(raw string) error {
	tokens := strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool { return r < 'a' || r > 'z' })
	for _, word := range strings.Fields(recoveryTTYFixture) {
		for _, token := range tokens {
			if token == word {
				return errors.New("fixture_word_in_public_output")
			}
		}
	}
	return nil
}

// Intentional plants establish that the public-output checker detects every
// individual fixture word as well as the full phrase, with a clean control.
func TestRecoveryPublicOutputLeakControl(t *testing.T) {
	if recoveryFixtureLeak(`{"ok":true,"npub":"npub1publicfixture"}`) != nil {
		t.Fatal("clean public output rejected")
	}
	for _, plant := range append(strings.Fields(recoveryTTYFixture), recoveryTTYFixture) {
		if err := recoveryFixtureLeak("prefix " + plant + " suffix"); err == nil || err.Error() != "fixture_word_in_public_output" {
			t.Fatal("known leak plant not detected")
		}
	}
}

// Positive generation/restore store exactly once through the fake backend.
// Wrong A/B identities, identity EOF, wrong/empty word confirmation,
// cancellation and missing controlling TTY store
// zero. The original terminal ECHO/canonical flags are restored after each
// isolated child, and captured stdout/stderr contain no fixture word.
func TestRecoveryPTYOwnerFlowAndRefusals(t *testing.T) {
	for _, mode := range []string{"generate", "identity-wrong-a", "identity-wrong-b", "identity-eof", "wrong", "empty", "empty-confirm", "no-backup", "random-fail", "eof", "cancel", "hangup", "restore", "restore-eof", "no-tty"} {
		t.Run(mode, func(t *testing.T) {
			master, slave := recoveryTestPTY(t)
			_, err := recoveryGetTermios(int(slave.Fd()))
			if err != nil {
				t.Fatal(err)
			}
			exe, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.Command(exe, "-test.run=^TestRecoveryPTYChild$", "-test.count=1")
			cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "MAC_KEYVAULT_SKIP_KEYCHAIN=1", "RECOVERY_PTY_FIXTURE=" + mode}
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr
			// Detach even the missing-TTY control from the caller's terminal.
			cmd.SysProcAttr = recoveryPTYAttributes(false)
			if mode != "no-tty" {
				cmd.Stdin = slave
				cmd.SysProcAttr = recoveryPTYAttributes(true)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			t.Cleanup(func() { _ = cmd.Process.Kill() })
			if mode != "no-tty" {
				transcript := ""
				handled := 0
				backed := false
				restored := false
				positions := map[int]bool{}
				identities := map[string]bool{}
				deadline := time.Now().Add(8 * time.Second)
			loop:
				for time.Now().Before(deadline) {
					select {
					case err := <-done:
						if err != nil {
							t.Fatal("fixture child failed")
						}
						done <- nil
						break loop
					default:
					}
					poll := []unix.PollFd{{Fd: int32(master.Fd()), Events: unix.POLLIN}}
					_, _ = unix.Poll(poll, 100)
					var data [2048]byte
					n := 0
					if poll[0].Revents&unix.POLLIN != 0 {
						n, _ = unix.Read(int(master.Fd()), data[:])
					}
					if n > 0 {
						transcript += string(data[:n])
					}

					for _, purpose := range []string{"Nostr", "Namecoin"} {
						if !identities[purpose] && strings.Contains(transcript, "Retype "+purpose+" identity: ") {
							identities[purpose] = true
							if mode == "identity-eof" && purpose == "Nostr" {
								_, _ = master.Write([]byte{4})
							} else {
								answer := "fixture"
								if mode == "identity-wrong-a" && purpose == "Nostr" || mode == "identity-wrong-b" && purpose == "Namecoin" {
									answer = "other"
								}
								_, _ = master.Write([]byte(answer + "\n"))
							}
						}
					}
					if !backed && strings.Contains(transcript, "Type BACKED-UP") {
						backed = true
						switch mode {
						case "empty":
							_, _ = master.Write([]byte("\n"))
						case "eof":
							_, _ = master.Write([]byte{4})
						case "cancel":
							_ = cmd.Process.Signal(syscall.SIGTERM)
						case "hangup":
							_ = master.Close()
						case "no-backup":
							_, _ = master.Write([]byte("NO\n"))
						default:
							_, _ = master.Write([]byte("BACKED-UP\n"))
						}
					}
					matches := regexp.MustCompile(`Retype word ([0-9]+) from`).FindAllStringSubmatch(transcript, -1)
					for handled < len(matches) {
						position, _ := strconv.Atoi(matches[handled][1])
						handled++
						if position < 1 || position > 24 || positions[position] {
							t.Fatal("confirmation positions invalid or repeated")
						}
						positions[position] = true
						answer := strings.Fields(recoveryTTYFixture)[position-1]
						if mode == "wrong" {
							answer = "incorrect"
						}
						if mode == "empty-confirm" {
							answer = ""
						}
						_, _ = master.Write([]byte(answer + "\n"))
					}
					if !restored && strings.Contains(transcript, "Restore exactly 24") {
						restored = true
						if mode == "restore-eof" {
							_, _ = master.Write([]byte{4})
						} else {
							_, _ = master.Write([]byte(recoveryTTYFixture + "\n"))
						}
					}
				}
				if (mode == "identity-wrong-a" || mode == "identity-wrong-b" || mode == "identity-eof") && (strings.Contains(transcript, "Type BACKED-UP") || strings.Contains(transcript, "Restore exactly 24")) {
					t.Fatal("identity refusal exposed the phrase stage")
				}
				if mode == "generate" && (len(positions) != 3 || len(identities) != 2) {
					t.Fatalf("three distinct positions not confirmed; public child output: %s %s", stdout.String(), stderr.String())
				}
				// The only captured secret display belongs to this public synthetic
				// fixture's PTY. Never persist a live owner's terminal transcript.
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal("fixture child failed")
				}
			case <-time.After(3 * time.Second):
				_ = cmd.Process.Kill()
				t.Fatal("fixture child did not terminate")
			}
			if mode != "no-tty" && mode != "hangup" && !strings.Contains(stderr.String(), "fixture_terminal_restored=true") {
				t.Fatal("terminal mode not restored inside child")
			}

			want := 0
			if mode == "generate" || mode == "restore" {
				want = 1
			}
			public := stdout.String() + stderr.String()
			if !strings.Contains(public, fmt.Sprintf("fixture_stores=%d", want)) {
				t.Fatalf("unexpected fake persistent effect; public child output: %s %s", stdout.String(), stderr.String())
			}
			if err := recoveryFixtureLeak(public); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func recoveryPTYAttributes(withTTY bool) *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true, Setctty: withTTY, Ctty: 0}
}

// All terminals here are disposable fixtures. Detaching the no-TTY child must
// deny /dev/tty even when its immediate parent has a controlling terminal;
// omitting that detach must expose this specific fixture, proving the control.
func TestRecoveryTTYIsolationRegression(t *testing.T) {
	mode := os.Getenv("RECOVERY_TTY_ISOLATION")
	if mode == "probe" {
		f, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
		if err != nil {
			if !errors.Is(err, syscall.ENXIO) && !errors.Is(err, syscall.ENODEV) && !errors.Is(err, syscall.ENOENT) {
				t.Fatal("unexpected terminal-open failure")
			}
			fmt.Println("fixture_controlling_tty=false")
			return
		}
		defer f.Close()
		foreground, err := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP)
		if err != nil || foreground != unix.Getpgrp() {
			t.Fatal("probe did not reach its foreground fixture")
		}
		fmt.Println("fixture_controlling_tty=true")
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := func(childMode string) *exec.Cmd {
		cmd := exec.Command(exe, "-test.run=^TestRecoveryTTYIsolationRegression$", "-test.count=1")
		cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "MAC_KEYVAULT_SKIP_KEYCHAIN=1", "RECOVERY_TTY_ISOLATION=" + childMode}
		return cmd
	}
	if mode == "" {
		_, slave := recoveryTestPTY(t)
		cmd := command("parent")
		cmd.Stdin = slave
		cmd.SysProcAttr = recoveryPTYAttributes(true)
		if data, err := recoveryRunFixtureCommand(cmd); err != nil {
			t.Fatalf("isolated parent failed: %v; %s", err, data)
		} else {
			t.Logf("isolated parent evidence:\n%s", data)
		}
		return
	}
	if mode != "parent" {
		t.Fatal("unknown fixture mode")
	}
	f, err := os.OpenFile("/dev/tty", os.O_RDWR|syscall.O_NOCTTY, 0)
	if err != nil {
		t.Fatal("fixture parent has no controlling terminal")
	}
	ttyGroup, first := unix.IoctlGetInt(int(f.Fd()), unix.TIOCGPGRP)
	stdinGroup, second := unix.IoctlGetInt(int(os.Stdin.Fd()), unix.TIOCGPGRP)
	_ = f.Close()
	if first != nil || second != nil || ttyGroup != unix.Getpgrp() || stdinGroup != ttyGroup {
		t.Fatal("parent terminal is not its assigned disposable fixture")
	}
	for _, control := range []struct {
		name       string
		attributes *syscall.SysProcAttr
		present    bool
	}{
		{"detached", recoveryPTYAttributes(false), false},
		{"omitted-setsid-control", nil, true},
		{"enabled-tty-sibling", recoveryPTYAttributes(true), true},
	} {
		t.Run(control.name, func(t *testing.T) {
			cmd := command("probe")
			cmd.SysProcAttr = control.attributes
			if control.name == "enabled-tty-sibling" {
				_, slave := recoveryTestPTY(t)
				cmd.Stdin = slave
			}
			data, err := recoveryRunFixtureCommand(cmd)
			if err != nil || !bytes.Contains(data, []byte(fmt.Sprintf("fixture_controlling_tty=%t", control.present))) {
				t.Fatalf("wrong terminal-control outcome: %v; %s", err, data)
			}
		})
	}
	// Exercise the actual missing-TTY CLI from that same terminal-owning parent.
	cmd := exec.Command(exe, "-test.run=^TestRecoveryPTYChild$", "-test.count=1")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + os.Getenv("HOME"), "MAC_KEYVAULT_SKIP_KEYCHAIN=1", "RECOVERY_PTY_FIXTURE=no-tty"}
	cmd.SysProcAttr = recoveryPTYAttributes(false)
	data, err := recoveryRunFixtureCommand(cmd)
	if err != nil || !bytes.Contains(data, []byte("owner foreground controlling terminal unavailable")) || !bytes.Contains(data, []byte("fixture_stores=0")) {
		t.Fatalf("missing-TTY CLI did not refuse before storage: %v; %s", err, data)
	}
	if recoveryFixtureLeak(string(data)) != nil {
		t.Fatal("missing-TTY CLI leaked a fixture word")
	}
}

func recoveryRunFixtureCommand(cmd *exec.Cmd) ([]byte, error) {
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		return output.Bytes(), err
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		<-done
		return output.Bytes(), errors.New("isolated fixture timeout")
	}
}
