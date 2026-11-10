package keyvault

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Without exact opt-in, the real fixture entry point skips before any build.
// The scheduled opt-in framing/code-boundary tests supply its positive control.
func TestRecoveryCodesignDefaultSkip(t *testing.T) {
	for _, value := range []string{"", "0", "true"} {
		var skipped bool
		ok := t.Run("value="+value, func(t *testing.T) {
			t.Setenv(recoveryCodesignTestsEnv, value)
			defer func() { skipped = t.Skipped() }()
			_ = recoveryBuildPipeFixture(t)
			t.Fatal("non-opt-in fixture did not skip")
		})
		if !ok || !skipped {
			t.Fatal("fixture guard did not perform the required skip")
		}
	}
}

// Non-executable local fixtures prove contention, retention across subtests,
// one final cleanup and re-acquisition without replacing the lock inode.
func TestRecoveryCodesignRunLockAndLifetime(t *testing.T) {
	base := t.TempDir()
	lockPath := filepath.Join(base, "lock")
	lane, err := openRecoveryTestLane("1", lockPath, base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lane.close() })
	before, err := os.ReadDir(base)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := openRecoveryTestLane("1", lockPath, base); !errors.Is(err, errRecoveryCodesignBusy) || second != nil {
		if second != nil {
			_ = second.close()
		}
		t.Fatal("second descriptor was not refused as a busy lane", err)
	}
	after, err := os.ReadDir(base)
	if err != nil || len(before) != len(after) {
		t.Fatal("refused lane created a fixture directory", err)
	}
	file := filepath.Join(lane.root, "public-marker")
	t.Run("first", func(t *testing.T) {
		if err := os.WriteFile(file, []byte("retained"), 0600); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("next", func(t *testing.T) {
		if data, err := os.ReadFile(file); err != nil || string(data) != "retained" {
			t.Fatal("fixture disappeared between subtests", err)
		}
	})
	lockBefore, err := os.Stat(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := lane.close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lane.root); !os.IsNotExist(err) {
		t.Fatal("completed run retained its fixture tree", err)
	}
	if err := lane.close(); err != nil {
		t.Fatal("repeated close performed another cleanup", err)
	}
	next, err := openRecoveryTestLane("1", lockPath, base)
	if err != nil {
		t.Fatal("completed run did not release its lock", err)
	}
	defer next.close()
	lockAfter, err := os.Stat(lockPath)
	if err != nil || !os.SameFile(lockBefore, lockAfter) {
		t.Fatal("lock inode was replaced", err)
	}
}

// No opt-in performs no lock/directory writes; malformed lock nodes refuse
// without modifying an existing target. An owned regular lock above is valid.
func TestRecoveryCodesignLockAdmission(t *testing.T) {
	base := t.TempDir()
	missing := filepath.Join(base, "absent", "lock")
	if lane, err := openRecoveryTestLane("", missing, base); err != nil || lane != nil {
		t.Fatal("default mode tried to acquire a lane", err)
	}
	if _, err := os.Stat(filepath.Dir(missing)); !os.IsNotExist(err) {
		t.Fatal("default mode wrote a lock prerequisite", err)
	}
	target := filepath.Join(base, "target")
	if err := os.WriteFile(target, []byte("unchanged"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if lane, err := openRecoveryTestLane("1", link, base); err == nil || lane != nil {
		if lane != nil {
			_ = lane.close()
		}
		t.Fatal("symlink lock was admitted")
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "unchanged" {
		t.Fatal("symlink target was modified", err)
	}
	if err := os.Chmod(target, 0644); err != nil {
		t.Fatal(err)
	}
	if lane, err := openRecoveryTestLane("1", target, base); err == nil || lane != nil {
		if lane != nil {
			_ = lane.close()
		}
		t.Fatal("unsafe lock mode was admitted")
	}
}

func recoveryCodesignControlProcess(t *testing.T, optIn, selection string) ([]byte, error) {
	t.Helper()
	lane := requireRecoveryTestLane(t)
	dir := recoveryFixtureDirectory(t, "control")
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	// Reuse this already built test executable. Controls never compile, sign or
	// delete another executable and preserve the inherited Keychain skip gate.
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.v", "-test.parallel=1", "-test.run="+selection)
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, recoveryCodesignTestsEnv+"=") && !strings.HasPrefix(entry, "TMPDIR=") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, recoveryCodesignTestsEnv+"="+optIn, "TMPDIR="+dir)
	output, err := cmd.CombinedOutput()
	if entries, readErr := os.ReadDir(dir); readErr != nil || len(entries) != 0 {
		t.Fatal("refused/default control created fixture state", readErr)
	}
	if _, statErr := os.Stat(lane.root); statErr != nil {
		t.Fatal("control removed the parent run tree", statErr)
	}
	return output, err
}

// A second real opt-in test process must refuse before m.Run or any fixture
// build/sign/exec. Its parent retains the host-wide lock and run tree.
func TestRecoveryCodesignSecondProcessRefused(t *testing.T) {
	output, err := recoveryCodesignControlProcess(t, "1", "^$")
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 75 || !strings.Contains(string(output), errRecoveryCodesignBusy.Error()) {
		t.Fatalf("second opt-in process did not report host-lane refusal: %v %s", err, output)
	}
}
