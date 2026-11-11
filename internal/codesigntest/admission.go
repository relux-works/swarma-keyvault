package codesigntest

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
)

const (
	RecoverySelection    = "^(TestRecoveryPrivateHelperFramingAndAdmission|TestRecoveryActualChildCodeBoundary)$"
	KEKSelection         = "^(TestCodeInspectorPublicCertificate|TestCodeInspectorPeerExec|TestCodeInspectorReadsSignatures)$"
	CertificateSelection = "^TestCodeInspectorPublicCertificate$"
	NativeAttemptPrefix  = "codesigntest native attempt: "
)

var errDisabled = errors.New("requires KEYVAULT_CODESIGN_TESTS=1 and the documented serial codesigntest runner")

func testFlag(name string) string {
	if f := flag.Lookup("test." + name); f != nil {
		return f.Value.String()
	}
	return ""
}

// Require is called at each native fixture entry before any native action.
func Require(t testing.TB, selections ...string) string {
	t.Helper()
	selection := testFlag("run")
	run, err := admit(os.Getenv(OptInEnv), selection, testFlag("parallel"), testFlag("count"), selections, func() (string, error) { return inheritedRun(selection) })
	if errors.Is(err, errDisabled) {
		t.Skip(err)
	}
	if err != nil {
		t.Fatal(err)
	}
	return run
}

func admit(optIn, run, parallel, count string, selections []string, inherited func() (string, error)) (string, error) {
	if optIn != "1" {
		return "", errDisabled
	}
	if parallel == "1" && count == "1" {
		for _, selection := range selections {
			if run == selection {
				return inherited()
			}
		}
	}
	return "", errors.New("unsupported codesign test selection; use the documented serial runner")
}

func inheritedRun(selection string) (string, error) {
	pid := strconv.Itoa(os.Getppid())
	if os.Getenv(ParentEnv) != pid {
		return "", errors.New("codesign fixture requires its runner as the parent process")
	}
	dir, err := StateDir(false)
	if err != nil {
		return "", err
	}
	if err := ownedDir(dir, true); err != nil {
		return "", err
	}
	run := os.Getenv(RunEnv)
	if filepath.Dir(run) != dir || !runName(filepath.Base(run)) {
		return "", errors.New("codesign fixture requires the runner-owned directory")
	}
	if err := checkHeldLock(dir, LockFD); err != nil {
		return "", err
	}
	if err := checkActiveRun(dir, run); err != nil {
		return "", err
	}
	boot, err := BootID()
	if err != nil {
		return "", err
	}
	record, err := readRun(run)
	if err != nil || record.Boot != boot || strconv.Itoa(record.Group) != pid || syscall.Getpgrp() != record.Group {
		return "", errors.New("codesign fixture runner record does not match its parent and boot")
	}
	cert := selection == CertificateSelection
	if record.Certificate != cert {
		return "", errors.New("codesign fixture does not match its recorded lane")
	}
	if err := requireConfinement(cert, os.Getenv("MAC_KEYVAULT_SKIP_KEYCHAIN"), keychaingate.Applied(), keychaingate.Confined()); err != nil {
		return "", err
	}
	if cert {
		raw, err := readState(run, "certificate-canary")
		if err != nil || string(raw) != boot {
			return "", errors.New("certificate fixture requires its passed init-gate canary")
		}
	}
	return run, nil
}

func checkActiveRun(dir, run string) error {
	if err := healthy(dir); err != nil {
		return err
	}
	if err := ownedDir(run, true); err != nil {
		return err
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if (runName(name) && name != filepath.Base(run)) || strings.HasPrefix(name, cleanupPrefix) || strings.HasPrefix(name, "reap-") {
			return errors.New("codesign fixture has unrelated outstanding state")
		}
	}
	for _, name := range []string{"finished", "exited"} {
		if _, err := os.Lstat(filepath.Join(run, name)); !os.IsNotExist(err) {
			return errors.New("codesign fixture run is completed or unknown")
		}
	}
	return nil
}

func requireConfinement(cert bool, skip string, applied, confined bool) error {
	if skip != "1" || (!cert && !confined) || (cert && (!applied || confined)) {
		return errors.New("codesign fixture lacks its required Keychain confinement")
	}
	return nil
}

func checkHeldLock(dir string, fd int) error {
	var inherited, current syscall.Stat_t
	if syscall.Fstat(fd, &inherited) != nil || !validLock(&inherited) ||
		syscall.Lstat(filepath.Join(dir, "lock"), &current) != nil || !validLock(&current) ||
		inherited.Dev != current.Dev || inherited.Ino != current.Ino {
		return errors.New("codesign fixture requires the inherited lane lock")
	}
	probe, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer probe.Close()
	var opened syscall.Stat_t
	if err := syscall.Fstat(int(probe.Fd()), &opened); err != nil || !validLock(&opened) ||
		opened.Dev != inherited.Dev || opened.Ino != inherited.Ino {
		return errors.New("codesign fixture lock changed during admission")
	}
	// A shared probe only contends with an exclusive lock. A free or
	// shared-only file is refused without touching the inherited lock.
	err = syscall.Flock(int(probe.Fd()), syscall.LOCK_SH|syscall.LOCK_NB)
	if err == nil {
		return errors.New("codesign fixture parent did not hold an exclusive lane lock")
	}
	if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EAGAIN) {
		return err
	}
	// The exclusive lock already exists. A separate open description
	// still contends, while the inherited holding description succeeds.
	if err := syscall.Flock(fd, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return fmt.Errorf("codesign fixture did not inherit the held lane lock: %w", err)
	}
	return nil
}

func (l *Lane) RecordCertificateCanary(run string) error {
	return writeState(filepath.Join(run, "certificate-canary"), []byte(l.boot))
}

// CheckDefaultOutput rejects an attempted native action even if it left no
// files or the fixture later reported a skip.
func CheckDefaultOutput(out []byte, tests ...string) error {
	if bytes.Contains(out, []byte(NativeAttemptPrefix)) {
		return errors.New("default control attempted a native fixture action")
	}
	for _, test := range tests {
		if !bytes.Contains(out, []byte("--- SKIP: "+test+" (")) {
			return fmt.Errorf("default control did not skip %s", test)
		}
	}
	return nil
}

func NativeAttempt(t testing.TB, action string) {
	t.Helper()
	t.Log(NativeAttemptPrefix + action)
}

// FixtureDir creates a subtree that the operator cleans up with the whole run.
func FixtureDir(t testing.TB, run, prefix string) string {
	t.Helper()
	dir, err := os.MkdirTemp(run, prefix+"-")
	if err != nil {
		t.Fatal(err)
	}
	return dir
}
