//go:build darwin && cgo

// Command codesigntest runs the opt-in macOS code-identity fixtures serially.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"syscall"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesigntest"
)

const (
	runMode           = "run"
	observedMode      = "run-observed"
	certificateMode   = "public-certificate"
	certificateCanary = "^TestSandboxCanary$"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	switch {
	case len(args) == 1 && fixtureMode(args[0]):
		return supervise(args[0])
	case len(args) == 1 && args[0] == "_probe-lock":
		lane, _, err := openLane()
		if errors.Is(err, codesigntest.ErrBusy) {
			return nil
		}
		if err != nil {
			return err
		}
		lane.Close()
		return errors.New("second process acquired the active fixture lock")
	case len(args) == 2 && args[0] == "_worker" && fixtureMode(args[1]):
		return worker(args[1])
	case len(args) == 2 && (args[0] == "cleanup" || args[0] == "cleanup-observed"):
		lane, dir, err := openLane()
		if err != nil {
			return err
		}
		defer lane.Close()
		if err := lane.Cleanup(args[1], args[0] == "cleanup-observed", time.Now()); err != nil {
			return err
		}
		fmt.Printf("Removed %s\n", filepath.Join(dir, args[1]))
		return nil
	default:
		return errors.New("usage: codesigntest run|run-observed|public-certificate|cleanup RUN_ID|cleanup-observed RUN_ID")
	}
}

func fixtureMode(mode string) bool {
	return mode == runMode || mode == observedMode || mode == certificateMode
}

func supervise(mode string) (result error) {
	if err := codesigntest.CheckHostHealth(); err != nil {
		return err
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	cmd := exec.Command(self, "_worker", mode)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case result = <-done:
	case sig := <-signals:
		_ = cmd.Process.Signal(sig)
		result = errors.Join(fmt.Errorf("fixture run interrupted by %s", sig), <-done)
	}
	// A surviving owned child can hold the inherited lock. A later
	// invocation can establish the quiet boundary once it has exited.
	lane, _, err := openLane()
	if errors.Is(err, codesigntest.ErrBusy) {
		return result
	}
	if err != nil {
		return errors.Join(result, err)
	}
	defer lane.Close()
	return errors.Join(result, lane.ObserveExit(cmd.Process.Pid, time.Now()))
}

func openLane() (*codesigntest.Lane, string, error) {
	dir, err := codesigntest.StateDir(true)
	if err != nil {
		return nil, "", err
	}
	boot, err := codesigntest.BootID()
	if err != nil {
		return nil, "", err
	}
	lane, err := codesigntest.Open(dir, boot)
	return lane, dir, err
}

func worker(mode string) (result error) {
	if err := codesigntest.CheckHostHealth(); err != nil {
		return err
	}
	if os.Getenv(codesigntest.OptInEnv) != "1" || os.Getenv("MAC_KEYVAULT_SKIP_KEYCHAIN") != "1" {
		return errors.New("native fixtures require KEYVAULT_CODESIGN_TESTS=1 and MAC_KEYVAULT_SKIP_KEYCHAIN=1")
	}
	if syscall.Getpgrp() != os.Getpid() {
		return errors.New("fixture worker requires its own process group")
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	if _, err := os.Stat(filepath.Join(root, "scripts", "keyvault-no-keychain.sb")); err != nil {
		return fmt.Errorf("run from the keyvault repository root: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	lane, _, err := openLane()
	if err != nil {
		return err
	}
	defer lane.Close()
	if err := checkContention(ctx); err != nil {
		return err
	}
	home, err := codesigntest.AccountHome()
	if err != nil {
		return err
	}
	path, err := lane.Begin(os.Getpid(), mode == observedMode, mode == certificateMode, time.Now())
	if err != nil {
		return err
	}
	fmt.Printf("Retained run %s (process group %d)\n", path, os.Getpid())
	defer func() {
		fmt.Printf("Run tree retained at %s\n", path)
	}()
	// Finish only after the chosen commands return. A crash before this
	// record requires observed cleanup or a later boot.
	r := runner{ctx: ctx, repo: root, path: path, home: home, lock: lane.ChildLock()}
	if mode == certificateMode {
		result = r.publicCertificate(lane)
	} else {
		recovery := r.confined("recovery", "internal/keyvault", codesigntest.RecoverySelection,
			"TestRecoveryPrivateHelperFramingAndAdmission", "TestRecoveryActualChildCodeBoundary")
		kek := r.confined("kek", "internal/keyvault/kek", codesigntest.KEKSelection,
			"TestCodeInspectorPublicCertificate", "TestCodeInspectorPeerExec", "TestCodeInspectorReadsSignatures")
		result = errors.Join(recovery, kek)
	}
	return errors.Join(result, lane.Finish(path, time.Now()))
}

func checkContention(ctx context.Context) error {
	self, err := os.Executable()
	if err != nil {
		return err
	}
	out, err := exec.CommandContext(ctx, self, "_probe-lock").CombinedOutput()
	if err != nil {
		return fmt.Errorf("independent lock control: %w: %s", err, out)
	}
	return nil
}

type runner struct {
	ctx              context.Context
	repo, path, home string
	lock             *os.File
}

func (r runner) command(dir, optIn, binary string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(r.ctx, binary, args...)
	cmd.WaitDelay = 5 * time.Second
	cmd.Dir = dir
	cmd.Env = append(os.Environ(),
		"HOME="+r.home, "GOFLAGS=", "GOWORK=off", "CGO_ENABLED=1", "GOTOOLCHAIN=local",
		"GOOS="+runtime.GOOS, "GOARCH="+runtime.GOARCH,
		codesigntest.OptInEnv+"="+optIn,
		codesigntest.RunEnv+"="+r.path,
		codesigntest.ParentEnv+"="+strconv.Itoa(os.Getpid()))
	cmd.ExtraFiles = []*os.File{r.lock}
	return cmd
}

func (r runner) build(name, pkg string, flags ...string) (string, error) {
	if err := codesigntest.CheckHostHealth(); err != nil {
		return "", err
	}
	path := filepath.Join(r.path, name+".test")
	args := append([]string{"test", "-c", "-p", "1", "-o", path}, flags...)
	args = append(args, "./"+pkg)
	binary, args := r.confine(filepath.Join(runtime.GOROOT(), "bin", "go"), args)
	cmd := r.command(r.repo, "0", binary, args...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("compile %s: %w", name, err)
	}
	return path, nil
}

func (r runner) test(path, pkg, selection, optIn string, confined bool) ([]byte, error) {
	if err := codesigntest.CheckHostHealth(); err != nil {
		return nil, err
	}
	binary := path
	args := []string{"-test.run=" + selection, "-test.parallel=1", "-test.count=1", "-test.timeout=10m", "-test.v"}
	if confined {
		binary, args = r.confine(binary, args)
	}
	out, err := r.command(filepath.Join(r.repo, pkg), optIn, binary, args...).CombinedOutput()
	_, _ = os.Stdout.Write(out)
	return out, err
}

func (r runner) confine(binary string, args []string) (string, []string) {
	return "/usr/bin/sandbox-exec", append([]string{
		"-D", "KEYVAULT_HOME=" + r.home,
		"-f", filepath.Join(r.repo, "scripts", "keyvault-no-keychain.sb"),
		binary,
	}, args...)
}

func (r runner) confined(name, pkg, selection string, tests ...string) error {
	fmt.Printf("=== %s (exec-level Keychain confinement) ===\n", name)
	path, err := r.build(name, pkg)
	if err != nil {
		return err
	}
	before, err := os.ReadDir(r.path)
	if err != nil {
		return err
	}
	out, err := r.test(path, pkg, selection, "0", true)
	if err != nil {
		return fmt.Errorf("%s default control: %w", name, err)
	}
	if err := codesigntest.CheckDefaultOutput(out, tests...); err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	after, err := os.ReadDir(r.path)
	if err != nil {
		return err
	}
	if len(before) != len(after) {
		return fmt.Errorf("%s default control changed the run directory", name)
	}
	for i := range before {
		if before[i].Name() != after[i].Name() {
			return fmt.Errorf("%s default control changed the run directory", name)
		}
	}
	out, err = r.test(path, pkg, selection, "1", true)
	if err != nil {
		return fmt.Errorf("%s native fixtures: %w", name, err)
	}
	for _, test := range tests {
		if !bytes.Contains(out, []byte("--- PASS: "+test+" (")) {
			return fmt.Errorf("%s opt-in did not pass %s", name, test)
		}
	}
	if name == "recovery" {
		if err := codesigntest.CheckRecoveryEvidence(out, r.path); err != nil {
			return err
		}
	}
	if name == "kek" && !bytes.Contains(out, []byte("exact trust refusal and zero attested facts verified")) {
		return errors.New("confined KEK case did not verify its trust refusal")
	}
	if _, err := codesigntest.FindSingleFixtureDir(r.path, name+"-base-"); err != nil {
		return fmt.Errorf("%s native fixture base: %w", name, err)
	}
	return nil
}

func (r runner) publicCertificate(lane *codesigntest.Lane) error {
	const gatePkg = "internal/keyvault/keychaingate"
	path, err := r.build("canary", gatePkg, "-tags=keyvault_gate_regression")
	if err != nil {
		return err
	}
	out, err := r.test(path, gatePkg, certificateCanary, "0", false)
	if err != nil {
		return fmt.Errorf("Keychain canary: %w", err)
	}
	if !bytes.Contains(out, []byte("keychaingate.Applied()=true")) || !bytes.Contains(out, []byte("--- PASS: TestSandboxCanary (")) {
		return errors.New("Keychain canary did not confirm init-level confinement")
	}
	if err := lane.RecordCertificateCanary(r.path); err != nil {
		return err
	}
	const kekPkg = "internal/keyvault/kek"
	path, err = r.build("kek-certificate", kekPkg)
	if err != nil {
		return err
	}
	out, err = r.test(path, kekPkg, codesigntest.CertificateSelection, "1", false)
	if err != nil {
		return fmt.Errorf("native public certificate fixture: %w", err)
	}
	if !bytes.Contains(out, []byte("--- PASS: TestCodeInspectorPublicCertificate (")) ||
		!bytes.Contains(out, []byte("native fixture gate: Applied=true Confined=false")) ||
		!bytes.Contains(out, []byte("validated public certificate/identifier")) {
		return errors.New("native public certificate fixture did not run")
	}
	return nil
}
