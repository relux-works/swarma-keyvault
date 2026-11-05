package grants

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// This is a file-metadata fixture, never an executable-format or process probe.
// The docking tests separately launch the real Go fixture executable.
func localExecutableMetadataFixture(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "gh")
	if err := os.WriteFile(path, []byte("metadata fixture; never invoked"), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func changeLocalExecutableFixture(t *testing.T, path, mode string) {
	t.Helper()
	if mode == "not-executable" {
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	var err error
	switch mode {
	case "missing":
	case "symlink":
		target := localExecutableMetadataFixture(t)
		err = os.Symlink(target, path)
	case "directory":
		err = os.Mkdir(path, 0700)
	case "fifo":
		err = syscall.Mkfifo(path, 0700)
	default:
		t.Fatal("unknown fixture mode", mode)
	}
	if err != nil {
		t.Fatal(err)
	}
}

// Known-invalid executable metadata refuses before state is opened, even when
// valid authority and a successful fake provider are available. Nearby valid
// metadata still dispatches; this does not prove ACL or binary-format validity.
func TestLocalProviderExecutableRefusesBeforeState(t *testing.T) {
	for _, mode := range []string{"missing", "not-executable", "symlink", "directory", "fifo"} {
		t.Run(mode, func(t *testing.T) {
			_, m, p, c, q := localMediatorFixture(t)
			changeLocalExecutableFixture(t, m.enrollment.ghPath, mode)
			opened := 0
			original := m.open
			m.open = func(ctx context.Context, e *LocalEnrollment) (*localState, error) { opened++; return original(ctx, e) }
			out, err := m.Execute(context.Background(), c, q)
			if out != nil || !errors.Is(err, ErrLocalProviderUnavailable) || opened != 0 || p.calls != 0 {
				t.Fatal("provider metadata pre-state refusal", out, err, opened, p.calls)
			}
			entries, err := os.ReadDir(m.enrollment.stateDir)
			if err != nil || len(entries) != 0 {
				t.Fatal("pre-state refusal created files", entries, err)
			}
			_, valid, vp, vc, vq := localMediatorFixture(t)
			if _, err := valid.Execute(context.Background(), vc, vq); err != nil || vp.calls != 1 {
				t.Fatal("valid regular executable neighbor", err, vp.calls)
			}
		})
	}
}

// A path changing after preflight while the state lock is acquired is checked
// again immediately before reservation. Existing journal bytes and allowance
// survive; repairing only the fixture path allows the same use to succeed.
func TestLocalProviderExecutableRecheckedUnderLock(t *testing.T) {
	for _, mode := range []string{"missing", "not-executable", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			_, m, p, c, q := localMediatorFixture(t)
			seed, err := openLocalState(context.Background(), m.enrollment)
			if err != nil {
				t.Fatal(err)
			}
			seed.close()
			journal := filepath.Join(m.enrollment.stateDir, "local.journal")
			before, err := os.ReadFile(journal)
			if err != nil {
				t.Fatal(err)
			}
			opened, writes := 0, 0
			original := m.open
			m.open = func(ctx context.Context, e *LocalEnrollment) (*localState, error) {
				s, err := original(ctx, e)
				if err != nil {
					return nil, err
				}
				opened++
				changeLocalExecutableFixture(t, e.ghPath, mode)
				write := s.write
				s.write = func(file *os.File, raw []byte) (int, error) { writes++; return write(file, raw) }
				return s, nil
			}
			out, err := m.Execute(context.Background(), c, q)
			if out != nil || !errors.Is(err, ErrLocalProviderUnavailable) || opened != 1 || writes != 0 || p.calls != 0 {
				t.Fatal("provider metadata under-lock refusal", out, err, opened, writes, p.calls)
			}
			after, err := os.ReadFile(journal)
			if err != nil || !bytes.Equal(before, after) {
				t.Fatal("pre-reservation refusal changed journal", err)
			}
			state, err := openLocalState(context.Background(), m.enrollment)
			if err != nil {
				t.Fatal(err)
			}
			if len(state.uses) != 0 || state.link.sequence != 1 {
				t.Fatal("pre-reservation refusal burned allowance")
			}
			state.close()
			if err := os.Remove(m.enrollment.ghPath); err != nil && !os.IsNotExist(err) {
				t.Fatal(err)
			}
			if err := os.WriteFile(m.enrollment.ghPath, []byte("metadata fixture; never invoked"), 0700); err != nil {
				t.Fatal(err)
			}
			m.open = original
			if _, err := m.Execute(context.Background(), c, q); err != nil || p.calls != 1 {
				t.Fatal("same allowance after path repair", err, p.calls)
			}
		})
	}
}

// A disappearance after the final check/intent remains UNKNOWN and held, even
// when exec cannot start the missing fixture. No real provider process starts;
// restoring path metadata never releases that already-reserved allowance.
func TestLocalProviderExecutableDisappearsAfterIntent(t *testing.T) {
	_, m, _, c, q := localMediatorFixture(t)
	path := m.enrollment.ghPath
	m.provider = localGHProvider{path: path}
	original := m.open
	syncs := 0
	m.open = func(ctx context.Context, e *LocalEnrollment) (*localState, error) {
		s, err := original(ctx, e)
		if err != nil {
			return nil, err
		}
		sync := s.sync
		s.sync = func(file *os.File) error {
			syncs++
			if err := sync(file); err != nil {
				return err
			}
			if syncs == 2 {
				return os.Remove(path)
			}
			return nil
		}
		return s, nil
	}
	got, err := m.Execute(context.Background(), c, q)
	if !errors.Is(err, ErrLocalUnknown) || got == nil || got.State != "unknown" || syncs != 2 {
		t.Fatal("post-intent missing path", got, err, syncs)
	}
	state, err := openLocalState(context.Background(), m.enrollment)
	if err != nil {
		t.Fatal(err)
	}
	if state.link.sequence != 3 || len(state.uses) != 1 {
		t.Fatal("post-intent allowance was released")
	}
	for _, held := range state.uses {
		if !held.intent || held.receipt != nil {
			t.Fatal("wrong uncertain dispatch state")
		}
	}
	state.close()
	if err := os.WriteFile(path, []byte("metadata fixture; never invoked"), 0700); err != nil {
		t.Fatal(err)
	}
	m.open = original
	if out, err := m.Execute(context.Background(), c, q); out != nil || !errors.Is(err, ErrLocalUseHeld) {
		t.Fatal("repair released uncertain allowance", out, err)
	}
}
