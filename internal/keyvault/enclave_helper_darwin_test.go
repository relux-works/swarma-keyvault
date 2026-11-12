//go:build darwin

package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/testguard"
	"github.com/relux-works/swarma-keyvault/internal/nativebuild"
)

// realEnclave builds mac-keyvault-enclave from source and returns a manager
// over a temp enclave store that never shows a prompt. It skips when swiftc
// is missing or this machine has no Secure Enclave (a VM runner). Nothing is
// written to any keychain; the keys exist only as blobs in the temp dir.
func realEnclave(t *testing.T) (*Manager, *EnclaveStore) {
	t.Helper()
	testguard.Require(t)
	swiftc, err := exec.LookPath("swiftc")
	if err != nil {
		t.Skip("swiftc not found")
	}
	dir := t.TempDir()
	helper := filepath.Join(dir, "mac-keyvault-enclave")
	_ = swiftc // Preserve the existing missing-tool skip; package setup errors fail.
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal("native package root unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	var buildLog bytes.Buffer
	native, err := nativebuild.Build(ctx, nativebuild.Options{Root: root, GoTool: filepath.Join(runtime.GOROOT(), "bin", "go"), Log: &buildLog})
	if err != nil {
		t.Fatalf("native package build failed: %v\n%s", err, buildLog.Bytes())
	}
	if err := nativebuild.CopyHelper(native, helper); err != nil {
		t.Fatal("native package helper copy failed")
	}
	store := NewEnclaveStore(filepath.Join(dir, "enclave"), ExecEnclaveHelper{Path: helper, Timeout: 15 * time.Second, InteractiveTimeout: 15 * time.Second})
	store.NonInteractive = true
	m := newTestManager(t, RoutedBackend{Keychain: newFakeStore(), Enclave: store})
	if _, err := m.Init(enclaveSpec("probe", false)); err != nil {
		var refusal *Refusal
		if errors.As(err, &refusal) && refusal.Status == -25291 {
			t.Skip("no Secure Enclave on this machine")
		}
		t.Fatal(err)
	}
	return m, store
}

// On the real Secure Enclave, through the real helper: a key without
// presence signs and verifies (positive control), a Touch ID key refuses
// without a finger with errSecInteractionNotAllowed, and a tampered blob or
// a silent blob swapped under a presence record yields no signature. The
// interactive Touch ID path itself is not exercised here (it needs the
// owner); NonInteractive keeps every call prompt-free.
func TestEnclaveRealHelper(t *testing.T) {
	m, store := realEnclave(t)
	digest := sha256.Sum256([]byte("real enclave"))
	silent := Address{Kind: KindKey, Service: TestService, Purpose: "probe"}
	result, err := m.Sign(silent, digest[:])
	if err != nil {
		t.Fatalf("silent key: %v", err)
	}
	if ok, err := VerifyDigest(result.Key.SPKI, digest[:], result.Signature); err != nil || !ok {
		t.Fatal("silent key signature does not verify")
	}
	owner, err := m.Init(enclaveSpec("owner", true))
	if err != nil {
		t.Fatalf("presence key: %v", err)
	}
	_, err = m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:])
	if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || refusal.Status != -25308 {
		t.Fatalf("presence key without a finger: %+v", refusal)
	}
	rewrite := func(change func(*enclaveFile)) { rewriteEnclaveFile(t, store, owner.Label, change) }
	original, _ := store.read(owner.Label)
	rewrite(func(f *enclaveFile) {
		f.Blob = append([]byte(nil), f.Blob...)
		f.Blob[len(f.Blob)/2] ^= 0xff
	})
	_, err = m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:])
	if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "refused the key blob") {
		t.Fatalf("tampered blob: %+v", refusal)
	}
	probe, _ := store.read(tl("probe", 1))
	rewrite(func(f *enclaveFile) { f.Blob, f.Point = probe.Blob, probe.Point })
	_, err = m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:])
	if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "without user presence") {
		t.Fatalf("silent blob under a presence record: %+v", refusal)
	}
	rewrite(func(f *enclaveFile) { *f = original })
	if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:]); refusalOf(t, err).Status != -25308 {
		t.Fatalf("restored presence key: %v", err)
	}
}

// OpenSSH signs an SSHSIG (namespace git) through the agent socket with a
// real Secure Enclave key and verifies it with ssh-keygen; the altered
// message is rejected by the same verifier. A Touch ID key served the same
// way yields no signature without a finger.
func TestEnclaveRealHelperSSHSIG(t *testing.T) {
	m, _ := realEnclave(t)
	if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	data := []byte("mac-keyvault enclave SSHSIG\n")
	input := filepath.Join(dir, "message")
	if err := os.WriteFile(input, data, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		purpose string
		signs   bool
	}{{"probe", true}, {"owner", false}} {
		t.Run(tc.purpose, func(t *testing.T) {
			addr := Address{Kind: KindKey, Service: TestService, Purpose: tc.purpose, Version: 1}
			a, err := NewSSHAgent(m, []Address{addr}, nil)
			if err != nil {
				t.Fatal(err)
			}
			socket, _, _ := sshSocket(t, a)
			pub := SSHPublicBytes(t, a)
			key := filepath.Join(dir, tc.purpose+".pub")
			if err := os.WriteFile(key, pub, 0o600); err != nil {
				t.Fatal(err)
			}
			os.Remove(input + ".sig")
			env := append(os.Environ(), "SSH_AUTH_SOCK="+socket)
			sign := exec.Command("/usr/bin/ssh-keygen", "-Y", "sign", "-f", key, "-n", "git", input)
			sign.Env = env
			out, err := sign.CombinedOutput()
			if !tc.signs {
				if err == nil {
					t.Fatalf("a Touch ID key signed without a finger: %s", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("ssh-keygen sign: %v %s", err, out)
			}
			allowed := filepath.Join(dir, "allowed_signers")
			os.WriteFile(allowed, append([]byte("owner@example.test "), pub...), 0o600)
			args := []string{"-Y", "verify", "-f", allowed, "-I", "owner@example.test", "-n", "git", "-s", input + ".sig"}
			sshCommand(t, env, data, "/usr/bin/ssh-keygen", args...)
			altered := exec.Command("/usr/bin/ssh-keygen", args...)
			altered.Stdin = strings.NewReader(string(data) + "!")
			if out, err := altered.CombinedOutput(); err == nil || !strings.Contains(string(out), "Could not verify signature.") {
				t.Fatalf("altered-data control: %v %s", err, out)
			}
		})
	}
}

// The real helper creates presence keys only as "user-presence" (Touch ID or
// the login password); the superseded "biometry-current-set" policy name is
// refused as a bad request and creates nothing. TestEnclaveRealHelper proves
// the user-presence key itself refuses to sign without the owner.
func TestEnclaveRealHelperPresencePolicyNames(t *testing.T) {
	_, store := realEnclave(t)
	if _, err := store.Helper.Call(EnclaveRequest{Op: "create", Presence: enclavePresenceUser}, false); err != nil {
		t.Fatalf("user-presence create: %v", err)
	}
	_, err := store.Helper.Call(EnclaveRequest{Op: "create", Presence: "biometry-current-set"}, false)
	var helperErr *EnclaveHelperError
	if !errors.As(err, &helperErr) || helperErr.Code != "bad_request" {
		t.Fatalf("biometry-current-set create: %v", err)
	}
}
