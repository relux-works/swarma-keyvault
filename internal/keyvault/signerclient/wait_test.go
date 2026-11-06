package signerclient_test

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
)

// Only a temporary shell fixture is executed. The recorded descendant retains
// both output pipes for 6s; cleanup kills that exact PID on every test outcome.
//
// macOS checks a newly written executable on its first run. That check is
// shared system work: about 0.3 s when idle, and much longer under load. It
// is not what these tests time, so the fixture runs once with "warm" before
// it is returned, and the timed runs start an executable already checked.
func pipeHoldingSigner(t *testing.T, hello bool) string {
	t.Helper()
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "pid")
	path := filepath.Join(dir, "signer")
	script := "#!/bin/sh\n[ \"$1\" = warm ] && exit 0\n/bin/sleep 6 &\nprintf '%s' $! > '" + pidPath + "'\n"
	if hello {
		script += `printf '%s\n' '{"contract":1,"ok":true,"result":{"tool":"mac-keyvault","tool_version":"test","address":"test/fake","kind":"key","version":1,"label":"test-label","fingerprint":"test-fingerprint","ops":["describe","pub","sign","verify"]}}'` + "\n"
		// Close sends EOF. Exit successfully without waiting for the descendant.
		script += "while IFS= read -r line; do :; done\nexit 0\n"
	} else {
		script += "wait\n"
	}
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	if out, err := exec.Command(path, "warm").CombinedOutput(); err != nil || len(out) != 0 {
		t.Fatalf("fixture warm-up: %v %q", err, out)
	}
	t.Cleanup(func() {
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err == nil && pid > 1 {
			_ = syscall.Kill(pid, syscall.SIGKILL)
		}
	})
	return path
}

func TestSignerStartCancellationBoundsInheritedPipes(t *testing.T) {
	binary := pipeHoldingSigner(t, false)
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var stderr bytes.Buffer // forces os/exec to copy stderr through a pipe
	start := time.Now()
	client, err := signerclient.Start(ctx, signerclient.Options{Binary: binary, Address: "test/fake", Stderr: &stderr})
	if client != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, signerclient.ErrProtocol) {
		t.Fatalf("startup cancellation outcome: client=%v, err=%v", client, err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("signer startup pipe wait not bounded: %v", elapsed)
	}
}

func TestSignerCloseReportsInheritedPipeFailure(t *testing.T) {
	binary := pipeHoldingSigner(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var stderr bytes.Buffer
	started := time.Now()
	client, err := signerclient.Start(ctx, signerclient.Options{Binary: binary, Address: "test/fake", Stderr: &stderr})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("signer start took %v", time.Since(started))
	start := time.Now()
	err = client.Close()
	if !errors.Is(err, exec.ErrWaitDelay) {
		t.Fatalf("signer close pipe failure predicate: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("signer close pipe wait not bounded: %v", elapsed)
	}
}
