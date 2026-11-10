package keyvault

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
)

const recoveryCodesignTestsEnv = "KEYVAULT_CODESIGN_TESTS"

// This fixed host path deliberately does not depend on checkout, HOME or TMPDIR.
// Never unlink the lock: replacing its inode could admit overlapping runs.
const recoveryCodesignHostLock = "/tmp/swarma-keyvault-codesign-tests.lock"

var errRecoveryCodesignBusy = errors.New("KEYVAULT_CODESIGN_TESTS: host lane busy")
var recoveryFixtureLane *recoveryTestLane

type recoveryTestLane struct {
	root      string
	lock      *os.File
	buildOnce sync.Once
	fixture   string
	buildErr  error
	closeOnce sync.Once
	closeErr  error
}

// TestMain owns this lock itself, so a terminated go driver cannot release the
// lane while its test process continues using signed executable fixtures.
func openRecoveryTestLane(optIn, lockPath, temporaryRoot string) (*recoveryTestLane, error) {
	if optIn != "1" {
		return nil, nil
	}
	f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, fmt.Errorf("codesign test lock unavailable: %w", err)
	}
	refuse := func(err error) (*recoveryTestLane, error) {
		_ = f.Close()
		return nil, err
	}
	info, err := f.Stat()
	if err != nil {
		return refuse(fmt.Errorf("codesign test lock stat: %w", err))
	}
	owner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !ok || owner.Uid != uint32(os.Getuid()) || owner.Nlink != 1 {
		return refuse(errors.New("codesign test lock is not an owned regular mode-0600 file"))
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return refuse(fmt.Errorf("%w: %s", errRecoveryCodesignBusy, lockPath))
		}
		return refuse(fmt.Errorf("codesign test flock: %w", err))
	}
	root, err := os.MkdirTemp(temporaryRoot, "keyvault-codesign-run-")
	if err != nil {
		return refuse(fmt.Errorf("codesign test fixture directory: %w", err))
	}
	return &recoveryTestLane{root: root, lock: f}, nil
}

// Only TestMain removes executable fixtures, once after m.Run returns. An
// abnormal process exit leaves the tree in place rather than deleting mid-run.
func (lane *recoveryTestLane) close() error {
	lane.closeOnce.Do(func() {
		lane.closeErr = os.RemoveAll(lane.root)
		if err := lane.lock.Close(); lane.closeErr == nil {
			lane.closeErr = err
		}
	})
	return lane.closeErr
}

func requireRecoveryTestLane(t *testing.T) *recoveryTestLane {
	t.Helper()
	if os.Getenv(recoveryCodesignTestsEnv) != "1" {
		t.Skip("executable/code-identity fixtures require KEYVAULT_CODESIGN_TESTS=1; use the documented -p 1 single-host lane")
	}
	if recoveryFixtureLane == nil {
		t.Fatal("codesign fixture requires the TestMain-owned host lock")
	}
	return recoveryFixtureLane
}

func recoveryFixtureDirectory(t *testing.T, prefix string) string {
	t.Helper()
	lane := requireRecoveryTestLane(t)
	// Unique invocation directories also keep -count repetitions from sharing
	// response markers. There is intentionally no per-test cleanup callback.
	dir, err := os.MkdirTemp(lane.root, prefix+"-")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}

func recoveryFixtureModeDirectory(t *testing.T, root, mode string) string {
	t.Helper()
	dir := filepath.Join(root, mode)
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
