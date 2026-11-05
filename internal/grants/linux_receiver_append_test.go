package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Moving the descriptor offset must not overwrite the activation or a previous
// snapshot. Exercise creation and reopening without requiring filesystem flags,
// elevated privileges, or a claim about protection against same-UID tampering.
// Claim: MU appends preserve every prior frame despite descriptor seeks, and reopen preserves signer union and highwater.
func TestLinuxRevocationJournalAppend(t *testing.T) {
	c := MUStateConfig{Directory: filepath.Join(t.TempDir(), "state"), Epoch: sha256.Sum256([]byte("append-test-epoch"))}
	if err := os.Mkdir(c.Directory, 0700); err != nil {
		t.Fatal(err)
	}
	b := MUBinding{Audience: muDockAud, GrantRoot: "p256:synthetic-root"}
	if err := InitializeMUState(c, b); err != nil {
		t.Fatal(err)
	}
	s, err := openMUState(context.Background(), c, b)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.write = func(f *os.File, raw []byte) (int, error) {
		flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_APPEND == 0 {
			t.Fatalf("journal is not opened for append: flags=%x err=%v", flags, err)
		}
		if _, err := f.Seek(0, io.SeekStart); err != nil {
			t.Fatal(err)
		}
		return f.Write(raw)
	}
	path := filepath.Join(c.Directory, "mu.journal")
	read := func() []byte {
		t.Helper()
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	prefix := read()
	entry := MURevocation{"record", "sha256:synthetic-revoked"}
	v := LinuxVerifiedSnapshot{Signer: "p256:synthetic-publisher", IssuedAt: muNow.Add(-time.Second), Entries: []MURevocation{entry}}
	d := MUDecision{PublisherKey: v.Signer, Revocations: v.Entries}
	for i := 0; i < 2; i++ {
		rs, err := openLinuxRevocationState(s)
		if err != nil {
			t.Fatal(err)
		}
		v.IssuedAt = v.IssuedAt.Add(time.Second)
		if err := rs.admit(s, []LinuxVerifiedSnapshot{v}, d, v.IssuedAt); err != nil {
			rs.close()
			t.Fatal(err)
		}
		rs.close()
		raw := read()
		if len(raw) <= len(prefix) || !bytes.HasPrefix(raw, prefix) {
			t.Fatal("append overwrote an existing journal prefix")
		}
		prefix = raw
	}
	rs, err := openLinuxRevocationState(s)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.close()
	if got := rs.latest[v.Signer]; !got.IssuedAt.Equal(v.IssuedAt) || len(got.Entries) != 1 || got.Entries[0] != entry {
		t.Fatal("recovery lost the signer highwater or union", got)
	}
	older := v
	older.IssuedAt = older.IssuedAt.Add(-time.Second)
	if err := rs.admit(s, []LinuxVerifiedSnapshot{older}, d, v.IssuedAt); !errors.Is(err, ErrMURollback) {
		t.Fatal("recovered highwater did not refuse rollback", err)
	}
	d.Revocations, v.Entries = nil, nil
	if err := rs.admit(s, []LinuxVerifiedSnapshot{v}, d, v.IssuedAt); !errors.Is(err, ErrMURollback) {
		t.Fatal("recovered union did not refuse omission", err)
	}
	if !bytes.Equal(read(), prefix) {
		t.Fatal("refused rollback changed the journal")
	}
}

// Claim: Unsafe file mode, symlink or torn MU state refuses without repair, accounting change or effect.
func TestLinuxRevocationJournalUnsafeRecovery(t *testing.T) {
	for _, mode := range []string{"mode", "symlink", "torn-tail"} {
		t.Run(mode, func(t *testing.T) {
			g := newLinuxRig(t)
			path := filepath.Join(g.r.config.State.Directory, "mu.journal")
			switch mode {
			case "mode":
				if err := os.Chmod(path, 0640); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "torn-tail":
				f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
				if err != nil {
					t.Fatal(err)
				}
				_, err = f.Write([]byte("partial-frame"))
				closeErr := f.Close()
				if err != nil || closeErr != nil {
					t.Fatal(err, closeErr)
				}
			}
			before := g.journal(t)
			if _, err := g.r.Handle(context.Background(), g.event(t, "$unsafe-journal")); !errors.Is(err, ErrMUState) {
				t.Fatal("unsafe journal admitted", err)
			}
			if g.calls.Load() != 0 || !bytes.Equal(g.journal(t), before) {
				t.Fatal("unsafe recovery reached accounting or effect")
			}
		})
	}
}
