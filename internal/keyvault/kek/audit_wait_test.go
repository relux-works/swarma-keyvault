package kek

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

func TestAuditLockDeadlineAndRecovery(t *testing.T) {
	a := &Audit{Path: filepath.Join(privateTemp(t), "audit.jsonl")}
	holder, err := os.OpenFile(a.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	unlock := func() { _ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN) }
	timer := time.AfterFunc(800*time.Millisecond, unlock)
	defer func() {
		if timer.Stop() {
			unlock()
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = a.AppendContext(ctx, AuditEntry{Op: "test", Verdict: "refused"}, time.Now())
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("audit lock deadline predicate: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("audit wait not bounded: %v", elapsed)
	}
	if data, err := os.ReadFile(a.Path); err != nil || len(data) != 0 {
		t.Fatalf("refused append changed log: %q, %v", data, err)
	}
	if timer.Stop() {
		unlock()
	}
	if err := a.Append(AuditEntry{Op: "test", Verdict: "answered"}, time.Now()); err != nil {
		t.Fatal(err)
	}
	if n, _, err := a.Verify(); err != nil || n != 1 {
		t.Fatalf("recovery chain: n=%d, %v", n, err)
	}
}

// The broker must use the connection's existing deadline for audit locking,
// withhold the answer when it expires, and return the audit failure to its caller.
func TestServerAuditUsesRequestDeadline(t *testing.T) {
	f := newFixture(t, nil)
	if err := os.MkdirAll(filepath.Dir(f.audit.Path), 0o700); err != nil {
		t.Fatal(err)
	}
	holder, err := os.OpenFile(f.audit.Path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := syscall.Flock(int(holder.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	unlock := func() { _ = syscall.Flock(int(holder.Fd()), syscall.LOCK_UN) }
	timer := time.AfterFunc(800*time.Millisecond, unlock)
	defer func() {
		if timer.Stop() {
			unlock()
		}
	}()
	sock := filepath.Join(privateTemp(t), "s")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	s := &Server{Vault: f.manager, Inspector: f.inspect, Audit: f.audit, Op: kekclient.OpUnwrap, Address: address, Timeout: 100 * time.Millisecond}
	done := make(chan error, 1)
	go func() { done <- s.Serve(listener) }()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(append(request(kekclient.OpUnwrap, f.envelope), '\n')); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = <-done
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "audit:") {
		t.Fatalf("server audit deadline predicate: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("server audit wait not bounded: %v", elapsed)
	}
	raw, err := io.ReadAll(conn)
	if err != nil || len(raw) != 0 {
		t.Fatalf("expired connection received an answer: %q, %v", raw, err)
	}
	if data, err := os.ReadFile(f.audit.Path); err != nil || len(data) != 0 {
		t.Fatalf("expired audit changed log: %q, %v", data, err)
	}
	if timer.Stop() {
		unlock()
	}
	if resp, raw := f.unwrap(); !resp.OK {
		t.Fatalf("recovery after contention: %s", raw)
	}
}
