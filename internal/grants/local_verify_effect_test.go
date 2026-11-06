//go:build darwin || linux

package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

type localVerifyEffectNode struct {
	Name string
	Size int64
	Mode fs.FileMode
}

// This is a before/after observation, not a transient create/delete detector.
func localVerifyEffectListing(t *testing.T, parent string) []localVerifyEffectNode {
	t.Helper()
	var nodes []localVerifyEffectNode
	err := filepath.WalkDir(parent, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		name, err := filepath.Rel(parent, path)
		if err != nil {
			return err
		}
		if entry.Name() == "local.journal" || entry.Name() == "local.lock" {
			t.Errorf("verification left a journal or lock under enrollment paths: %s", name)
		}
		nodes = append(nodes, localVerifyEffectNode{name, info.Size(), info.Mode()})
		return nil
	})
	if err != nil {
		t.Fatal("recursive enrollment parent listing", err)
	}
	return nodes
}

func localVerifyEffectAbsent(t *testing.T, path, claim string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal(claim, err)
	}
}

func localVerifyEffectProvider(t *testing.T, parent string) (string, string) {
	t.Helper()
	provider := filepath.Join(parent, "fake-provider")
	// The marker is derived from argv[0], so paths need no shell interpolation.
	if err := os.WriteFile(provider, []byte("#!/bin/sh\nprintf started > \"$0.started\"\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return provider, provider + ".started"
}

func localVerifyEffectExecutable(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "swarma-keyvault")
	ctx, cancel := context.WithTimeout(context.Background(), 80*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "build", "-buildvcs=false", "-o", bin, "../../cmd/swarma-keyvault")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("candidate build failed (not behavioral evidence): %v: %s", err, out)
	}
	raw, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("actual candidate executable SHA256 %x (%d bytes)", sha256.Sum256(raw), len(raw))
	return bin
}

func localVerifyEffectProcess(t *testing.T, bin string, f *localFixture, c, q []byte, refused, stdin bool) {
	t.Helper()
	parent := t.TempDir()
	state := filepath.Join(parent, "state")
	provider, marker := localVerifyEffectProvider(t, parent)
	configuration := make(map[string]any, len(f.config))
	for name, value := range f.config {
		configuration[name] = value
	}
	configuration["state_dir"], configuration["gh_path"] = state, provider
	config, certificate, request := filepath.Join(parent, "enrollment.json"), filepath.Join(parent, "certificate.json"), filepath.Join(parent, "request.json")
	for path, raw := range map[string][]byte{config: requestTestBytes(t, configuration), certificate: c, request: q} {
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	// A nested neighbor makes the recursive listing cover more than siblings.
	nested := filepath.Join(parent, "preserved", "nested")
	if err := os.MkdirAll(nested, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nested, "neighbor"), []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	localVerifyEffectAbsent(t, state, "state path must be absent before command")
	localVerifyEffectAbsent(t, marker, "provider marker must be absent before command")
	before := localVerifyEffectListing(t, parent)
	at := f.now
	if refused {
		// Same signed authority as its accepted neighbor, at exclusive expiry.
		at = time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC)
	}
	args := []string{"grants", "verify", "--config", config, "--certificate", certificate, "--request", request, "--at", at.Format(time.RFC3339Nano)}
	if stdin {
		args[7] = "-"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(q)
	var out, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatal("verify did not finish within the command bound", ctx.Err())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("candidate launch failed (not verdict evidence)", err)
		}
		code = exit.ExitCode()
	}
	if refused {
		if code != 1 || out.Len() != 0 || stderr.String() != "refused: "+ErrExpired.Error()+"\n" {
			t.Fatalf("executable refusal assertion: code=%d stdout=%s stderr=%s", code, out.String(), stderr.String())
		}
	} else {
		var verdict struct {
			Verdict string `json:"verdict"`
			LocalVerification
		}
		want := LocalVerification{CertificateID: "certificate-A", RequestID: "request-A", Action: "repository.create",
			Target: LocalVerificationTarget{LocalOrganization, LocalRepository, "private"}, ValidAt: at.UTC(),
			ExpiresAt: time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC)}
		if code != 0 || stderr.Len() != 0 || json.Unmarshal(out.Bytes(), &verdict) != nil || verdict.Verdict != "accepted" || verdict.LocalVerification != want {
			t.Fatalf("executable accepted neighbor assertion: code=%d stdout=%s stderr=%s", code, out.String(), stderr.String())
		}
	}
	t.Logf("real CLI verdict assertion passed: refused=%t stdin=%t exit=%d", refused, stdin, code)
	localVerifyEffectAbsent(t, marker, "fake provider was started")
	localVerifyEffectAbsent(t, state, "verification created execution state")
	after := localVerifyEffectListing(t, parent)
	if !reflect.DeepEqual(before, after) {
		t.Fatalf("recursive enrollment parent names/sizes/modes changed: before=%+v after=%+v", before, after)
	}
}

// Claim: Real CLI acceptance/refusal preserves absent state, recursive parent names/sizes/modes and no provider marker on Darwin/Linux.
func TestLocalVerifyExecutableEffects(t *testing.T) {
	bin := localVerifyEffectExecutable(t)
	for _, stdin := range []bool{false, true} {
		name := "file"
		if stdin {
			name = "stdin"
		}
		t.Run(name, func(t *testing.T) {
			f := localTestFixture(t)
			c, q := f.envelopes(t)
			t.Run("accepted", func(t *testing.T) { localVerifyEffectProcess(t, bin, f, c, q, false, stdin) })
			t.Run("refused", func(t *testing.T) { localVerifyEffectProcess(t, bin, f, c, q, true, stdin) })
		})
	}
}

// Claim: The synthetic provider writes the watched marker when actually started, even though it exits unsuccessfully.
func TestLocalVerifyEffectProviderMarker(t *testing.T) {
	provider, marker := localVerifyEffectProvider(t, t.TempDir())
	localVerifyEffectAbsent(t, marker, "marker must be absent before witness launch")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, provider).CombinedOutput()
	var exit *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 99 || len(out) != 0 {
		t.Fatal("synthetic provider witness did not launch/exit as expected", err, string(out))
	}
	raw, err := os.ReadFile(marker)
	if err != nil || string(raw) != "started" {
		t.Fatal("synthetic provider marker missing", err, string(raw))
	}
}
