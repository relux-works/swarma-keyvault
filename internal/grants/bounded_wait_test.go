package grants

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// orphanHold is how long the fixture's grandchild keeps the inherited pipes
// open. It is well above orphanBound so a missing WaitDelay is visible.
const orphanHold = "8"

// orphanBound is the latest a refused call may return after its deadline.
const orphanBound = 4 * time.Second

// holdInheritedPipes runs inside a fixture child: it starts a grandchild that
// inherits stdout/stderr and outlives the child, then stalls until killed.
func holdInheritedPipes() {
	holder := exec.Command("/bin/sleep", orphanHold)
	holder.Stdout, holder.Stderr = os.Stdout, os.Stderr
	if holder.Start() != nil {
		os.Exit(97)
	}
	time.Sleep(time.Minute)
	os.Exit(98)
}

// Claim: a G2 provider child killed at the caller's deadline returns within a
// bounded time even when a grandchild keeps its stdout pipe open; the use stays
// held as UNKNOWN and is never dispatched twice. Limit: one grandchild, macOS
// /bin/sleep; it does not prove the descendant itself is reaped.
func TestA2AProviderOrphanPipeBounded(t *testing.T) {
	_, m, _, e := a2aMediatorFixture(t)
	calls := filepath.Join(t.TempDir(), "calls")
	t.Setenv("KEYVAULT_A2A_GH_FIXTURE", "orphan-pipe")
	t.Setenv("KEYVAULT_A2A_GH_CALLS", calls)
	m.provider = a2aGHProvider{path: m.providerPath}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	out, err := m.Execute(ctx, e)
	elapsed := time.Since(start)
	if !errors.Is(err, ErrA2AUnknown) || out == nil || out.State != "unknown" {
		t.Fatal("orphan pipe outcome", out, err)
	}
	if elapsed > orphanBound {
		t.Fatal("provider wait not bounded", elapsed)
	}
	if _, err := m.Execute(context.Background(), e); !errors.Is(err, ErrA2AUseHeld) {
		t.Fatal("unknown use not held", err)
	}
	if b, err := os.ReadFile(calls); err != nil || string(b) != "create\n" {
		t.Fatal("wrong process count", err, string(b))
	}
}

// Claim: the same bound holds for the G local provider adapter (same failure
// class as the G2 site). Limit as above.
func TestLocalProviderOrphanPipeBounded(t *testing.T) {
	f := localTestFixture(t)
	c, q := f.envelopes(t)
	enrollment, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
	if err != nil {
		t.Fatal(err)
	}
	checked, err := enrollment.check(c, q, f.now)
	if err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYVAULT_LOCAL_GH_FIXTURE", "orphan-pipe")
	t.Setenv("KEYVAULT_LOCAL_GH_CALLS", filepath.Join(t.TempDir(), "calls"))
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	raw, err := (localGHProvider{path: exe}).create(ctx, checked)
	elapsed := time.Since(start)
	if err == nil || raw != nil {
		t.Fatal("orphan pipe accepted", raw, err)
	}
	if elapsed > orphanBound {
		t.Fatal("local provider wait not bounded", elapsed)
	}
}

// Claim: an observation child killed at the deadline returns a projection
// refusal within a bounded time despite a grandchild holding its pipes, with no
// provider call and no state change. Limit as above.
func TestA2AExecutorOrphanPipeBounded(t *testing.T) {
	_, e, _, _, providerCalls := a2aExecutorFixture(t)
	if err := e.InitializeState(); err != nil {
		t.Fatal(err)
	}
	m := NewA2AMediator(e.receiver, e.state, e.ghPath)
	before := a2aJournalBytes(t, m)
	t.Setenv("KEYVAULT_A2A_PROJECTION_FIXTURE", "orphan-pipe")
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	start := time.Now()
	result, err := e.Execute(ctx, "$fixture-event")
	elapsed := time.Since(start)
	if !errors.Is(err, ErrA2AProjection) || result != nil {
		t.Fatal("orphan observation accepted", result, err)
	}
	if elapsed > orphanBound {
		t.Fatal("observation wait not bounded", elapsed)
	}
	a2aNoFixtureCall(t, providerCalls)
	if !bytes.Equal(before, a2aJournalBytes(t, m)) {
		t.Fatal("refused observation wrote state")
	}
}

// Claim: lockStateFile refuses when another open file description holds the
// lock and the caller's context ends, and acquires once the holder releases
// (positive control). Limit: same process, two descriptions of one file.
func TestStateLockHonorsContext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.lock")
	holder, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	waiter, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	if err := lockStateFile(ctx, waiter); !errors.Is(err, errStateLockUnavailable) {
		t.Fatal("held lock acquired", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatal("lock wait ignored context", elapsed)
	}
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	if err := lockStateFile(context.Background(), waiter); err != nil {
		t.Fatal("free lock refused", err)
	}
	if err := lockStateFile(nil, waiter); !errors.Is(err, errStateLockUnavailable) { //nolint:staticcheck // nil context is a refusal case
		t.Fatal("nil context accepted", err)
	}
}

// Claim: a G2 execution whose context ends while another process holds the
// state lock refuses with ErrA2AState, starts no provider and writes nothing.
func TestA2AExecuteLockWaitHonorsContext(t *testing.T) {
	_, m, p, e := a2aMediatorFixture(t)
	before := a2aJournalBytes(t, m)
	holder, err := os.OpenFile(filepath.Join(m.state.Directory, "a2a.lock"), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer holder.Close()
	if err := unix.Flock(int(holder.Fd()), unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	if _, err := m.Execute(ctx, e); !errors.Is(err, ErrA2AState) {
		t.Fatal("execute under held lock", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatal("execute lock wait ignored context", elapsed)
	}
	if p.calls.Load() != 0 {
		t.Fatal("provider started under held lock")
	}
	if !bytes.Equal(before, a2aJournalBytes(t, m)) {
		t.Fatal("state written under held lock")
	}
}
