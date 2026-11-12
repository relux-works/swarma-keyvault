package keyvault

import (
	"context"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func rootGrantsLockFixture45(t *testing.T) FileLock {
	t.Helper()
	// Darwin's temporary directory may be spelled through /var, a symlink.
	// Explicitly choose its real disposable directory; production never resolves
	// a symlink to make an otherwise refused vault path admissible.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "init.lock")
	if err := os.WriteFile(path, []byte("public-lock-fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return FileLock{Path: path}
}

// These tests exercise real flock and disposable filesystem admission only.
// They prove no Keychain ACL, signed code, native store or enrollment behavior.
func TestRootGrantsExistingLock45PositiveAndRelease(t *testing.T) {
	lock := rootGrantsLockFixture45(t)
	before, err := os.ReadFile(lock.Path)
	if err != nil {
		t.Fatal(err)
	}
	guard, err := lockRootGrantsExisting(context.Background(), lock)
	if err != nil || guard == nil {
		t.Fatalf("existing admitted lock refused: %v", err)
	}
	probe, err := os.Open(lock.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err == nil {
		t.Fatal("same existing guard was not held")
	}
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() { defer wg.Done(); guard.Release() }()
	}
	wg.Wait()
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		t.Fatal("guard not released exactly once")
	}
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(lock.Path)
	if err != nil || string(before) != string(after) {
		t.Fatal("lock contents changed")
	}
}

func TestRootGrantsExistingLock45Refusals(t *testing.T) {
	for _, name := range []string{"missing-file", "missing-parent", "symlink-file", "symlink-parent", "unsafe-file", "unsafe-parent", "directory", "fifo", "relative", "unclean", "canceled", "expired", "nil-context"} {
		t.Run(name, func(t *testing.T) {
			lock := rootGrantsLockFixture45(t)
			var ctx context.Context = context.Background()
			switch name {
			case "missing-file":
				if err := os.Remove(lock.Path); err != nil {
					t.Fatal(err)
				}
			case "missing-parent":
				lock.Path = filepath.Join(filepath.Dir(lock.Path), "absent", "init.lock")
			case "symlink-file":
				target := lock.Path
				lock.Path += ".link"
				if err := os.Symlink(target, lock.Path); err != nil {
					t.Fatal(err)
				}
			case "symlink-parent":
				dir := filepath.Dir(lock.Path)
				link := filepath.Join(dir, "parent-link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				lock.Path = filepath.Join(link, "init.lock")
			case "unsafe-file":
				if err := os.Chmod(lock.Path, 0644); err != nil {
					t.Fatal(err)
				}
			case "unsafe-parent":
				if err := os.Chmod(filepath.Dir(lock.Path), 0777); err != nil {
					t.Fatal(err)
				}
			case "directory":
				lock.Path = filepath.Dir(lock.Path)
			case "fifo":
				if err := os.Remove(lock.Path); err != nil {
					t.Fatal(err)
				}
				if err := unix.Mkfifo(lock.Path, 0600); err != nil {
					t.Fatal(err)
				}
			case "relative":
				lock.Path = "init.lock"
			case "unclean":
				lock.Path = filepath.Dir(lock.Path) + "/./init.lock"
			case "canceled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "expired":
				var cancel context.CancelFunc
				ctx, cancel = context.WithDeadline(ctx, time.Unix(1, 0))
				defer cancel()
			case "nil-context":
				ctx = nil
			}
			guard, err := lockRootGrantsExisting(ctx, lock)
			if guard != nil || err == nil || err.Error() != recoveryRefuse("lock_unavailable").Error() {
				if guard != nil {
					guard.Release()
				}
				t.Fatal("invalid prerequisite did not return sanitized lock_unavailable")
			}
			if name == "missing-file" || name == "missing-parent" {
				if _, err := os.Lstat(lock.Path); !os.IsNotExist(err) {
					t.Fatal("missing guard bootstrapped")
				}
				if name == "missing-parent" {
					if _, err := os.Lstat(filepath.Dir(lock.Path)); !os.IsNotExist(err) {
						t.Fatal("missing parent bootstrapped")
					}
				}
			}
		})
	}
}

func TestRootGrantsExistingLock45BusyCancellation(t *testing.T) {
	lock := rootGrantsLockFixture45(t)
	guard, err := lockRootGrantsExisting(context.Background(), lock)
	if err != nil {
		t.Fatal(err)
	}
	defer guard.Release()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	second, err := lockRootGrantsExisting(ctx, lock)
	if second != nil || err == nil || ctx.Err() == nil {
		if second != nil {
			second.Release()
		}
		t.Fatal("busy guard bypassed caller deadline")
	}
	guard.Release()
	control, err := lockRootGrantsExisting(context.Background(), lock)
	if err != nil {
		t.Fatal("released positive control refused")
	}
	control.Release()
}
