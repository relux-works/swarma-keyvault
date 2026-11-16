//go:build linux

package namecoinprocess

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinfiles"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
	"golang.org/x/sys/unix"
)

const hostedTMPDIRGuardEnv = "KEYVAULT_HOSTED_TMPDIR_POLICY_GUARD"

// Claim: the opted-in hosted setup probe validates the effective TMPDIR chain
// through CreateOutput, accepts a 0755/private complete-pair control, and rejects
// a task-local 01777 ancestor before output creation or child/lifecycle progress.
// Limit: this proves the policy on the current Linux filesystem and public test
// fixture; it does not establish hosted runner parent modes outside this run.
func TestHostedTMPDIRPolicyGuard(t *testing.T) {
	if os.Getenv(hostedTMPDIRGuardEnv) != "1" {
		t.Skip("hosted TMPDIR policy guard runs in the explicit setup step")
	}

	effectiveTMPDIR := os.TempDir()
	ancestryObserved := logHostedTMPDIRAncestry(t, effectiveTMPDIR)
	if !filepath.IsAbs(effectiveTMPDIR) {
		t.Log("owner=unknown mode=unknown class=relative")
	}

	probePath := filepath.Join(effectiveTMPDIR, "namecoinprocess-hosted-tmpdir-policy-probe")
	if _, err := os.Lstat(probePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("SETUP: effective TMPDIR probe class=not-fresh")
	}
	probe, err := namecoinfiles.CreateOutput(probePath)
	if err != nil {
		if errors.Is(err, namecoinfiles.ErrUnsafe) {
			t.Fatal("SETUP: effective TMPDIR policy class=ErrUnsafe")
		}
		t.Fatal("SETUP: effective TMPDIR policy class=other-error")
	}
	if !ancestryObserved {
		_ = probe.Close()
		_ = os.Remove(probePath)
		t.Fatal("SETUP: effective TMPDIR ancestry class=unobserved")
	}
	if err := probe.Close(); err != nil {
		_ = os.Remove(probePath)
		t.Fatal("SETUP: effective TMPDIR probe close class=error")
	}
	if err := os.Remove(probePath); err != nil {
		t.Fatal("SETUP: effective TMPDIR probe cleanup class=error")
	}
	t.Log("SETUP: effective TMPDIR policy class=accepted")

	helper := buildProcess2FixtureHelper(t)
	fixtureRoot := t.TempDir()
	safeRoot := filepath.Join(fixtureRoot, "safe-0755")
	safeOutputDir := filepath.Join(safeRoot, "private")
	makeHostedTMPDIRFixtureDir(t, safeRoot, 0o755, "safe-parent")
	makeHostedTMPDIRFixtureDir(t, safeOutputDir, 0o700, "safe-private")

	safeProbePath := filepath.Join(safeOutputDir, "safe-policy-probe")
	safeProbe, err := namecoinfiles.CreateOutput(safeProbePath)
	if err != nil {
		t.Fatal("safe 0755/private policy class=refused")
	}
	if err := safeProbe.Close(); err != nil {
		_ = os.Remove(safeProbePath)
		t.Fatal("safe 0755/private policy class=close-error")
	}
	if err := os.Remove(safeProbePath); err != nil {
		t.Fatal("safe 0755/private policy class=cleanup-error")
	}

	safeOutputPath := filepath.Join(safeOutputDir, "complete-pair.json")
	command, options, wantResult, wantAck := process2RunnerFixture(t, helper, safeOutputPath, "10")
	outcome, evidence := runProcess2(t.Context(), command, options)
	if !outcome.Success() || !bytes.Equal(outcome.Result(), wantResult) || !bytes.Equal(outcome.Line(), wantAck) ||
		!evidence.admitted || evidence.frameBytes != evidence.frameLength || !evidence.writerJoined ||
		!evidence.statusEOF || !evidence.stdoutEOF || !evidence.stderrEOF || evidence.stderrHadBytes ||
		!evidence.resultReadbackOK || !evidence.waitDone || evidence.waitExit != 0 || !evidence.outputCloseOK ||
		command.Process == nil || len(evidence.closeObservations) != 11 {
		t.Fatal("safe 0755/private complete-pair control class=not-success")
	}
	if info, err := os.Stat(safeOutputPath); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("safe 0755/private complete-pair control class=output-mode")
	}
	t.Log("control class=safe-0755-private-success")

	stickyRoot := filepath.Join(fixtureRoot, "sticky-writable")
	stickyOutputDir := filepath.Join(stickyRoot, "private")
	makeHostedTMPDIRFixtureDir(t, stickyRoot, 0o1777, "sticky-writable-parent")
	makeHostedTMPDIRFixtureDir(t, stickyOutputDir, 0o700, "sticky-child-private")
	negativeOutputPath := filepath.Join(stickyOutputDir, "must-not-exist.json")
	negativeProbe, err := namecoinfiles.CreateOutput(negativeOutputPath)
	if negativeProbe != nil || !errors.Is(err, namecoinfiles.ErrUnsafe) {
		if negativeProbe != nil {
			_ = negativeProbe.Close()
			_ = os.Remove(negativeOutputPath)
		}
		t.Fatal("sticky/writable policy control class=expected-ErrUnsafe-missing")
	}
	assertHostedTMPDIRNoOutput(t, negativeOutputPath)
	t.Log("control class=sticky-writable-policy-ErrUnsafe")

	command, options, _, _ = process2RunnerFixture(t, helper, negativeOutputPath, "10")
	outcome, evidence = runProcess2(t.Context(), command, options)
	failure, decodeErr := namecoinwire.DecodeFailure(outcome.Line())
	exit, exitKnown := outcome.Exit()
	if decodeErr != nil || !outcome.Done() || outcome.Success() || failure.Code() != namecoinwire.OutcomeUnknown ||
		failure.Status() != "UNKNOWN" || !exitKnown || exit != 1 || len(outcome.Result()) != 0 ||
		len(outcome.FinalTransaction()) != 0 || outcome.TxID() != "" {
		t.Fatal("sticky/writable runner control class=not-UNKNOWN-without-result")
	}
	if command.Process != nil || evidence.frameBytes != 0 || evidence.writeErr || evidence.writerCloseOK ||
		evidence.writerJoined || evidence.stdinCloseOK || evidence.childEndsCloseOK || evidence.readerCloseOK ||
		evidence.outputCloseOK || len(evidence.status) != 0 || evidence.statusEOF || evidence.statusOverflow ||
		len(evidence.stdout) != 0 || evidence.stdoutEOF || evidence.stdoutOverflow || evidence.stderrEOF ||
		evidence.stderrHadBytes || len(evidence.result) != 0 || evidence.resultReadbackOK || evidence.waitDone ||
		evidence.waitExit != 0 || evidence.waitErr || evidence.admitted || evidence.contextCancelledDuringInput ||
		len(evidence.closeObservations) != 0 {
		t.Fatal("sticky/writable runner control class=process-or-lifecycle-progress")
	}
	assertHostedTMPDIRNoOutput(t, negativeOutputPath)
	t.Log("control class=sticky-writable-ErrUnsafe-UNKNOWN-no-progress")
}

func logHostedTMPDIRAncestry(t *testing.T, effectiveTMPDIR string) bool {
	t.Helper()
	current := filepath.Clean(effectiveTMPDIR)
	if !filepath.IsAbs(current) {
		t.Log("owner=unknown mode=unknown class=relative")
		return false
	}
	for {
		var stat unix.Stat_t
		if err := unix.Lstat(current, &stat); err != nil {
			t.Log("owner=unknown mode=unknown class=stat-error")
			return false
		}
		class := "directory"
		if stat.Mode&unix.S_IFMT != unix.S_IFDIR {
			class = "non-directory"
		}
		t.Logf("owner=%d mode=%#o class=%s", stat.Uid, stat.Mode&0o7777, class)
		if class != "directory" {
			return false
		}
		if current == string(filepath.Separator) {
			return true
		}
		parent := filepath.Dir(current)
		if parent == current {
			t.Log("owner=unknown mode=unknown class=walk-stop")
			return false
		}
		current = parent
	}
}

func makeHostedTMPDIRFixtureDir(t *testing.T, path string, mode uint32, class string) {
	t.Helper()
	fileMode := hostedTMPDIRGoMode(mode)
	if err := os.Mkdir(path, fileMode); err != nil {
		t.Fatalf("fixture class=%s mkdir-error", class)
	}
	if err := os.Chmod(path, fileMode); err != nil {
		t.Fatalf("fixture class=%s chmod-error", class)
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil || stat.Mode&unix.S_IFMT != unix.S_IFDIR ||
		stat.Uid != uint32(os.Geteuid()) || stat.Mode&0o7777 != mode {
		t.Fatalf("fixture class=%s mode-not-applied", class)
	}
	t.Logf("owner=%d mode=%#o class=%s", stat.Uid, stat.Mode&0o7777, class)
}

func hostedTMPDIRGoMode(mode uint32) os.FileMode {
	fileMode := os.FileMode(mode & 0o777)
	if mode&0o4000 != 0 {
		fileMode |= os.ModeSetuid
	}
	if mode&0o2000 != 0 {
		fileMode |= os.ModeSetgid
	}
	if mode&0o1000 != 0 {
		fileMode |= os.ModeSticky
	}
	return fileMode
}

func assertHostedTMPDIRNoOutput(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("negative control class=output-present-or-unreadable")
	}
}
