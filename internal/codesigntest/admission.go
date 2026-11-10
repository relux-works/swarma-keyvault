package codesigntest

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
)

const (
	RecoverySelection    = "^(TestRecoveryPrivateHelperFramingAndAdmission|TestRecoveryActualChildCodeBoundary)$"
	KEKSelection         = "^(TestCodeInspectorPublicCertificate|TestCodeInspectorPeerExec|TestCodeInspectorReadsSignatures)$"
	CertificateSelection = "^TestCodeInspectorPublicCertificate$"
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
	run, err := admit(os.Getenv(OptInEnv), testFlag("run"), testFlag("parallel"), testFlag("count"), selections, inheritedRun)
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

func inheritedRun() (string, error) {
	pid := strconv.Itoa(os.Getppid())
	if os.Getenv(ParentEnv) != pid {
		return "", errors.New("codesign fixture requires its runner as the parent process")
	}
	dir, err := StateDir()
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
	if err := ownedDir(run, true); err != nil {
		return "", err
	}
	record, err := readRun(run)
	if err != nil || strconv.Itoa(record.Group) != pid || syscall.Getpgrp() != record.Group {
		return "", errors.New("codesign fixture runner record does not match its parent")
	}
	var inherited, current syscall.Stat_t
	if syscall.Fstat(LockFD, &inherited) != nil || !validLock(&inherited) ||
		syscall.Lstat(filepath.Join(dir, "lock"), &current) != nil ||
		inherited.Dev != current.Dev || inherited.Ino != current.Ino {
		return "", errors.New("codesign fixture requires the inherited lane lock")
	}
	// An independent descriptor cannot take a lock already held by the runner.
	// The inherited descriptor refers to the same open file description.
	if err := syscall.Flock(LockFD, syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		return "", fmt.Errorf("codesign fixture lane lock: %w", err)
	}
	return run, nil
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
