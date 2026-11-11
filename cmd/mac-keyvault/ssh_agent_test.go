package main

import (
	"bytes"
	"crypto/sha512"
	"encoding/json"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/sockettest"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// CLI validation refuses missing/unpinned identities, invalid hook options,
// an --unlock-for outside (0, 24h], and any explicit --confirm-when (even
// "sign") without a hook or an unlock confirmation without --unlock-for, an
// invalid --sign-namespace (including an explicit empty one) and a relative
// --audit-log, all before opening the backend. Adjacent valid pub output is
// parseable.
func TestRunSSHAgentArgumentsAndPublicKey(t *testing.T) {
	store := newMemStore(tl("ssh-agent", 1))
	old := newBackend
	newBackend = func() keyvault.Backend { return store }
	defer func() { newBackend = old }()
	for _, args := range [][]string{
		{}, {"--socket", "/tmp/test.sock"}, {"--socket", "/tmp/test.sock", "--key", "test/ssh-agent"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@0"}, {"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-arg", "x"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-exec", "relative"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--unlock-for", "0s"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--unlock-for", "-1s"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--unlock-for", "25h"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-exec", "/usr/bin/true", "--confirm-when", "always"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--unlock-for", "1h", "--confirm-when", "unlock"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-when", "sign"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-exec", "/usr/bin/true", "--confirm-when", "unlock"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--confirm-exec", "/usr/bin/true", "--confirm-when", "both"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--sign-namespace", ""},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--sign-namespace", "g it"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--sign-namespace", "-git"},
		{"--socket", "/tmp/test.sock", "--key", "test/ssh-agent@1", "--audit-log", "audit.jsonl"},
	} {
		var out, err bytes.Buffer
		code := run(append([]string{"--json", "ssh-agent"}, args...), &out, &err)
		if code != exitUsage || err.Len() != 0 {
			t.Fatalf("args %v: %d %s %s", args, code, &out, &err)
		}
	}
	if store.touched() {
		t.Fatal("invalid flags opened vault")
	}
	var out, err bytes.Buffer
	if code := run([]string{"pub", "test/ssh-agent", "--version", "1", "--format", "ssh"}, &out, &err); code != 0 {
		t.Fatalf("pub: %d %s", code, &err)
	}
	key, _, _, _, parseErr := ssh.ParseAuthorizedKey(out.Bytes())
	if parseErr != nil || key.Type() != ssh.KeyAlgoECDSA256 {
		t.Fatalf("public SSH output: %v", parseErr)
	}
	out.Reset()
	err.Reset()
	if code := run([]string{"--json", "pub", "test/ssh-agent", "--version", "1", "--format", "ssh"}, &out, &err); code != 0 {
		t.Fatalf("json pub: %d %s", code, &out)
	}
	var response struct{ Result map[string]any }
	if json.Unmarshal(out.Bytes(), &response) != nil || !strings.HasPrefix(response.Result["ssh"].(string), ssh.KeyAlgoECDSA256) {
		t.Fatal("SSH pub envelope missing public output")
	}
}

// The process-level helper uses a memory backend only; no user keychain or
// live configuration is accessed during daemon lifecycle verification.
func TestSSHAgentCLIHelper(t *testing.T) {
	if os.Getenv("MAC_KEYVAULT_SSH_HELPER") != "1" {
		return
	}
	store := newMemStore(tl("ssh-agent", 1))
	newBackend = func() keyvault.Backend { return store }
	vaultLock = func() (keyvault.FileLock, error) {
		return keyvault.FileLock{Path: filepath.Join(os.Getenv("MAC_KEYVAULT_SSH_HELPER_DIR"), "lock")}, nil
	}
	args := []string{"ssh-agent", "--socket", os.Getenv("MAC_KEYVAULT_SSH_HELPER_SOCKET"), "--key", "test/ssh-agent@1"}
	if extra := os.Getenv("MAC_KEYVAULT_SSH_HELPER_EXTRA"); extra != "" {
		args = append(args, strings.Split(extra, "\x1f")...)
	}
	os.Exit(run(args, os.Stdout, os.Stderr))
}

// The actual CLI serves identities, handles SIGTERM cleanly and removes its
// socket. A pre-existing path is refused without overwriting its content.
func TestRunSSHAgentLifecycle(t *testing.T) {
	dir := sockettest.Dir(t, "kv-cli-")
	var err error
	socket := filepath.Join(dir, "agent.sock")
	var logs syncBuffer
	cmd := exec.Command(os.Args[0], "-test.run=^TestSSHAgentCLIHelper$")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "MAC_KEYVAULT_SSH_HELPER=1", "MAC_KEYVAULT_SSH_HELPER_DIR=" + dir, "MAC_KEYVAULT_SSH_HELPER_SOCKET=" + socket}
	cmd.Stdout = &logs
	cmd.Stderr = &logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	var conn net.Conn
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		conn, err = net.Dial("unix", socket)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("CLI did not create socket")
	}
	defer conn.Close()
	keys, err := agent.NewClient(conn).List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("CLI identities: %v %v", keys, err)
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("CLI shutdown: %v %s", err, &logs)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("CLI shutdown timed out")
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("CLI socket survived shutdown")
	}
	os.WriteFile(socket, []byte("foreign"), 0600)
	logs.Reset()
	next := exec.Command(os.Args[0], "-test.run=^TestSSHAgentCLIHelper$")
	next.Env = cmd.Env
	next.Stdout = &logs
	next.Stderr = &logs
	if err := next.Run(); err == nil {
		t.Fatal("CLI replaced foreign file")
	}
	content, _ := os.ReadFile(socket)
	if string(content) != "foreign" {
		t.Fatal("foreign path changed")
	}
}

// startSSHHelper runs the CLI agent in a child process with a memory backend
// and the given extra arguments.
func startSSHHelper(t *testing.T, extra ...string) (*exec.Cmd, string, *syncBuffer) {
	t.Helper()
	dir := sockettest.Dir(t, "kv-cli-")
	socket := filepath.Join(dir, "agent.sock")
	logs := &syncBuffer{}
	cmd := exec.Command(os.Args[0], "-test.run=^TestSSHAgentCLIHelper$")
	cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "MAC_KEYVAULT_SSH_HELPER=1", "MAC_KEYVAULT_SSH_HELPER_DIR=" + dir,
		"MAC_KEYVAULT_SSH_HELPER_SOCKET=" + socket, "MAC_KEYVAULT_SSH_HELPER_EXTRA=" + strings.Join(extra, "\x1f")}
	cmd.Stdout = logs
	cmd.Stderr = logs
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if cmd.ProcessState == nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
	})
	return cmd, socket, logs
}

// syncBuffer collects a child process's output. os/exec copies into it from
// its own goroutine while the process runs, so every read and write takes the
// lock; a plain bytes.Buffer read on a failure path raced with that copier.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func (s *syncBuffer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.b.Reset()
}

// dialSSHHelper waits for the child agent's socket. The bound is generous:
// under a loaded full-suite run, starting the test binary and a hook takes
// seconds.
func dialSSHHelper(t *testing.T, socket string, logs *syncBuffer) net.Conn {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if conn, err := net.Dial("unix", socket); err == nil {
			return conn
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("agent did not open its socket: %s", logs)
	return nil
}

func waitExit(t *testing.T, cmd *exec.Cmd, within time.Duration) (int, bool) {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case <-done:
		return cmd.ProcessState.ExitCode(), true
	case <-time.After(within):
		return 0, false
	}
}

// Claim: with --unlock-for the CLI agent serves its identities, then stops
// by itself at the deadline with exit 0 and removes its socket; the plain
// agent in TestRunSSHAgentLifecycle keeps running until signalled.
func TestRunSSHAgentUnlockExpires(t *testing.T) {
	cmd, socket, logs := startSSHHelper(t, "--unlock-for", "6s")
	conn := dialSSHHelper(t, socket, logs)
	keys, err := agent.NewClient(conn).List()
	conn.Close()
	if err != nil || len(keys) != 1 {
		t.Fatalf("identities before the deadline: %v %v", keys, err)
	}
	code, exited := waitExit(t, cmd, 15*time.Second)
	if !exited || code != 0 {
		t.Fatalf("exited=%v code=%d logs %s", exited, code, logs)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("socket survived the unlock deadline")
	}
	if !strings.Contains(logs.String(), " until ") {
		t.Fatalf("readiness line does not state the deadline: %s", logs)
	}
}

// Claim: when the unlock is not confirmed the agent exits refused and never
// creates its socket; a granting hook is the positive control.
func TestRunSSHAgentUnlockConfirmation(t *testing.T) {
	cmd, socket, logs := startSSHHelper(t, "--unlock-for", "1h", "--confirm-when", "unlock", "--confirm-exec", "/usr/bin/false")
	code, exited := waitExit(t, cmd, 10*time.Second)
	if !exited || code != exitRefused {
		t.Fatalf("denied unlock: exited=%v code=%d logs %s", exited, code, logs)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("a socket exists after a denied unlock")
	}
	control, controlSocket, controlLogs := startSSHHelper(t, "--unlock-for", "1h", "--confirm-when", "unlock", "--confirm-exec", "/usr/bin/true")
	dialSSHHelper(t, controlSocket, controlLogs).Close()
	control.Process.Signal(syscall.SIGTERM)
	if code, exited := waitExit(t, control, 3*time.Second); !exited || code != 0 {
		t.Fatalf("control shutdown: exited=%v code=%d", exited, code)
	}
}

// Claim: --confirm-when decides which requests reach the hook. With a hook
// that grants only unlock requests, `unlock` lets signatures through without
// asking, while `both` also asks for each signature and so refuses it.
func TestRunSSHAgentConfirmWhenSelectsPurposes(t *testing.T) {
	dir := sockettest.Dir(t, "kv-hook-")
	hook := filepath.Join(dir, "unlock-only")
	if err := os.WriteFile(hook, []byte("#!/bin/sh\nexec /usr/bin/grep -q '\"purpose\":\"unlock\"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		when   string
		signOK bool
	}{{"unlock", true}, {"both", false}} {
		t.Run(tc.when, func(t *testing.T) {
			cmd, socket, logs := startSSHHelper(t, "--unlock-for", "1h", "--confirm-when", tc.when, "--confirm-exec", hook)
			conn := dialSSHHelper(t, socket, logs)
			defer conn.Close()
			client := agent.NewClient(conn)
			keys, err := client.List()
			if err != nil || len(keys) != 1 {
				t.Fatalf("identities: %v %v", keys, err)
			}
			_, signErr := client.Sign(keys[0], []byte("message"))
			if (signErr == nil) != tc.signOK {
				t.Fatalf("sign error = %v, want ok=%v", signErr, tc.signOK)
			}
			cmd.Process.Signal(syscall.SIGTERM)
			waitExit(t, cmd, 3*time.Second)
		})
	}
}

func sshsigRequest(namespace string) []byte {
	sum := sha512.Sum512([]byte("tag"))
	return append([]byte("SSHSIG"), ssh.Marshal(struct {
		Namespace, Reserved, Algorithm string
		Hash                           []byte
	}{namespace, "", "sha512", sum[:]})...)
}

// Claim: the CLI agent started with --sign-namespace git and --audit-log
// signs a git SSHSIG request (positive control, verified), refuses a file
// namespace and an authentication-style request, and writes one audit record
// per request with the client pid; its readiness line names both settings.
func TestRunSSHAgentGitNamespaceAndAudit(t *testing.T) {
	auditDir := sockettest.Dir(t, "kv-audit-")
	audit := filepath.Join(auditDir, "audit.jsonl")
	cmd, socket, logs := startSSHHelper(t, "--sign-namespace", "git", "--audit-log", audit)
	conn := dialSSHHelper(t, socket, logs)
	client := agent.NewClient(conn)
	keys, err := client.List()
	if err != nil || len(keys) != 1 {
		t.Fatalf("identities: %v %v", keys, err)
	}
	pub, _ := ssh.ParsePublicKey(keys[0].Blob)
	git := sshsigRequest("git")
	sig, err := client.Sign(pub, git)
	if err != nil || pub.Verify(git, sig) != nil {
		t.Fatalf("git request: %v %s", err, logs)
	}
	if _, err := client.Sign(pub, sshsigRequest("file")); err == nil {
		t.Fatal("file namespace signed")
	}
	if _, err := client.Sign(pub, append(ssh.Marshal(struct{ Session []byte }{bytes.Repeat([]byte{1}, 32)}), 50)); err == nil {
		t.Fatal("authentication-style request signed")
	}
	conn.Close()
	cmd.Process.Signal(syscall.SIGTERM)
	if code, exited := waitExit(t, cmd, 10*time.Second); !exited || code != 0 {
		t.Fatalf("exit %d %v: %s", code, exited, logs)
	}
	raw, err := os.ReadFile(audit)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	want := []string{`"outcome":"signed"`, `"reason":"namespace"`, `"reason":"not_sshsig"`}
	if len(lines) != len(want) {
		t.Fatalf("audit lines: %q", raw)
	}
	for i, fragment := range want {
		if !strings.Contains(lines[i], fragment) || !strings.Contains(lines[i], `"client_pid":`+strconv.Itoa(os.Getpid())) {
			t.Errorf("record %d: %s", i, lines[i])
		}
	}
	if !strings.Contains(logs.String(), "; signs only SSHSIG namespace git; audit log "+audit+"\n") {
		t.Fatalf("readiness: %s", logs)
	}
}

// Claim: an audit log the agent cannot use (here a symlink) stops the CLI
// before the socket exists, so no client can reach an unaudited agent.
func TestRunSSHAgentRefusesUnusableAuditLog(t *testing.T) {
	auditDir := sockettest.Dir(t, "kv-audit-")
	target := filepath.Join(auditDir, "real.jsonl")
	os.WriteFile(target, nil, 0600)
	link := filepath.Join(auditDir, "audit.jsonl")
	os.Symlink(target, link)
	cmd, socket, logs := startSSHHelper(t, "--sign-namespace", "git", "--audit-log", link)
	if code, exited := waitExit(t, cmd, 15*time.Second); !exited || code == 0 {
		t.Fatalf("exit %d %v: %s", code, exited, logs)
	}
	if _, err := os.Lstat(socket); !os.IsNotExist(err) {
		t.Fatal("socket created with an unusable audit log")
	}
}

// Claim: a child's output copier can write a syncBuffer while the test reads
// it, without a data race under -race, and every byte written is kept.
func TestSyncBufferConcurrentReadWrite(t *testing.T) {
	var b syncBuffer
	done := make(chan struct{})
	go func() {
		for i := 0; i < 2000; i++ {
			b.Write([]byte("x"))
		}
		close(done)
	}()
	for i := 0; i < 2000; i++ {
		_ = b.String()
	}
	<-done
	if got := len(b.String()); got != 2000 {
		t.Fatal("bytes lost", got)
	}
}
