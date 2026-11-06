//go:build linux

package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func localVerifyExecutable(t *testing.T) string {
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

func localVerifyConfig(e *LocalEnrollment, state, provider string) map[string]any {
	return map[string]any{"type": "grants-local-enrollment-2", "owner_mxid": e.owner.ownerMXID,
		"owner_spki":     base64.RawURLEncoding.EncodeToString(e.owner.spkiDER),
		"requester_spki": base64.RawURLEncoding.EncodeToString(e.requesterDER),
		"subject":        map[string]any{"account_mxid": e.subject.accountMXID, "device_id": e.subject.deviceID},
		"audience":       map[string]any{"deployment_id": e.audience.deploymentID, "executor_id": e.audience.executorID},
		"cycle":          map[string]any{"cycle_id": e.cycle.cycleID, "runtime": e.cycle.runtime, "channel": e.cycle.channel},
		"organization":   LocalOrganization, "name": LocalRepository, "state_dir": state, "gh_path": provider}
}

type localVerifyNode struct {
	device, inode uint64
	mode          os.FileMode
	size          int64
	modified      time.Time
	contents      string
}

func localVerifyNodeSnapshot(t *testing.T, path string) localVerifyNode {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	st := info.Sys().(*syscall.Stat_t)
	contents := ""
	if info.Mode().IsRegular() {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		contents = string(raw)
	}
	return localVerifyNode{uint64(st.Dev), st.Ino, info.Mode(), info.Size(), info.ModTime(), contents}
}

func localVerifyProcess(t *testing.T, bin string, e *LocalEnrollment, c, q []byte, at time.Time, heldState, stdin bool, want error) {
	t.Helper()
	root := t.TempDir()
	state, provider := filepath.Join(root, "state"), filepath.Join(root, "gh")
	marker := filepath.Join(root, "PROVIDER-STARTED")
	if err := os.WriteFile(provider, []byte("#!/bin/sh\nprintf started > '"+marker+"'\nexit 99\n"), 0700); err != nil {
		t.Fatal(err)
	}
	config, certificate, request := filepath.Join(root, "enrollment.json"), filepath.Join(root, "certificate.json"), filepath.Join(root, "request.json")
	for name, raw := range map[string][]byte{config: requestTestBytes(t, localVerifyConfig(e, state, provider)), certificate: c, request: q} {
		if err := os.WriteFile(name, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	before := map[string]localVerifyNode{}
	watch := -1
	if heldState {
		if err := os.Mkdir(state, 0700); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"local.lock", "local.journal"} {
			if err := os.WriteFile(filepath.Join(state, name), []byte("untouched-"+name), 0600); err != nil {
				t.Fatal(err)
			}
		}
		lock, err := os.OpenFile(filepath.Join(state, "local.lock"), os.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer lock.Close()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{state, filepath.Join(state, "local.lock"), filepath.Join(state, "local.journal")} {
			before[path] = localVerifyNodeSnapshot(t, path)
		}
		watch, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(watch)
		for path := range before {
			if _, err := unix.InotifyAddWatch(watch, path, unix.IN_OPEN|unix.IN_ACCESS|unix.IN_MODIFY|unix.IN_ATTRIB|unix.IN_CREATE|unix.IN_DELETE|unix.IN_MOVED_FROM|unix.IN_MOVED_TO|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF); err != nil {
				t.Fatal(err)
			}
		}
	} else if _, err := os.Lstat(state); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("state path must be absent before command", err)
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
		t.Fatal("verify blocked on execution lock or provider", ctx.Err())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal("candidate launch failed (not verdict evidence)", err)
		}
		code = exit.ExitCode()
	}
	if want == nil {
		var verdict struct {
			Verdict string `json:"verdict"`
			LocalVerification
		}
		if code != 0 || stderr.Len() != 0 || json.Unmarshal(out.Bytes(), &verdict) != nil || verdict.Verdict != "accepted" || verdict.CertificateID != "certificate-A" || verdict.RequestID != "request-A" || verdict.Action != "repository.create" || verdict.Target != (LocalVerificationTarget{LocalOrganization, LocalRepository, "private"}) || !verdict.ValidAt.Equal(at) || !verdict.ExpiresAt.Equal(time.Date(2026, 11, 2, 11, 30, 0, 0, time.UTC)) {
			t.Fatalf("executable positive assertion: code=%d stdout=%s stderr=%s", code, out.String(), stderr.String())
		}
	} else if code != 1 || out.Len() != 0 || stderr.String() != "refused: "+want.Error()+"\n" {
		t.Fatalf("executable negative assertion: want=%v code=%d stdout=%s stderr=%s", want, code, out.String(), stderr.String())
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("fake provider was started", err)
	}
	if heldState {
		buf := make([]byte, 8192)
		if n, err := unix.Read(watch, buf); n > 0 || !errors.Is(err, unix.EAGAIN) {
			t.Fatalf("verification opened/accessed/changed state nodes: %d inotify bytes, %v", n, err)
		}
		for path, old := range before {
			if current := localVerifyNodeSnapshot(t, path); current != old {
				t.Fatalf("state node changed: %s", filepath.Base(path))
			}
		}
		entries, err := os.ReadDir(state)
		if err != nil || len(entries) != 2 {
			t.Fatal("state nodes added or removed", err)
		}
	} else {
		for _, path := range []string{state, filepath.Join(state, "local.journal"), filepath.Join(state, "local.lock")} {
			if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("verification created execution state", path, err)
			}
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 4+lenBeforeState(heldState) {
		t.Fatal("unexpected provider, lock, journal or other sibling node", err)
	}
}

func lenBeforeState(held bool) int {
	if held {
		return 1
	}
	return 0
}

// Claim: The actual candidate accepts/refuses every authority class without state opens, locks, journal changes or provider starts.
func TestLocalVerifyExecutable(t *testing.T) {
	bin := localVerifyExecutable(t)
	for _, held := range []bool{false, true} {
		name := "absent-state"
		if held {
			name = "held-lock-and-watched-nodes"
		}
		t.Run(name, func(t *testing.T) {
			e, c, q, at := localVerifyInputs(t, "valid")
			localVerifyProcess(t, bin, e, c, q, at, held, false, nil)
			localVerifyProcess(t, bin, e, c, q, at, held, true, nil)
			for i, tc := range localVerifyCases {
				t.Run(tc.name, func(t *testing.T) {
					bad, bc, bq, ba := localVerifyInputs(t, tc.name)
					localVerifyProcess(t, bin, bad, bc, bq, ba, held, i%2 == 0, tc.want)
					localVerifyProcess(t, bin, e, c, q, at, held, i%2 != 0, nil)
				})
			}
		})
	}
}
