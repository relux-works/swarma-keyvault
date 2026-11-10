//go:build darwin && cgo

package keyvault

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Inside the scheduled opt-in run, the same executable in default mode
// actually skips both guarded tests without creating another fixture tree.
func TestRecoveryCodesignDefaultProcessControl(t *testing.T) {
	output, err := recoveryCodesignControlProcess(t, "", "^(TestRecoveryPrivateHelperFramingAndAdmission|TestRecoveryActualChildCodeBoundary)$")
	if err != nil || !strings.Contains(string(output), "--- SKIP: TestRecoveryPrivateHelperFramingAndAdmission") ||
		!strings.Contains(string(output), "--- SKIP: TestRecoveryActualChildCodeBoundary") {
		t.Fatalf("default executable fixtures did not skip: %v %s", err, output)
	}
}

// A real running public fixture with an ad-hoc hardened signature is admitted.
// Same code without runtime, a wrong hash and get-task-allow are rejected before
// receiving a request. These tests inspect code identity only, never Keychain.
func TestRecoveryActualChildCodeBoundary(t *testing.T) {
	fixture := recoveryBuildPipeFixture(t)
	root := recoveryFixtureDirectory(t, "identity")
	for _, mode := range []string{"hardened", "no-runtime", "wrong-hash", "debug-entitlement"} {
		t.Run(mode, func(t *testing.T) {
			dir := recoveryFixtureModeDirectory(t, root, mode)
			path := filepath.Join(dir, "pass")
			raw, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0700); err != nil {
				t.Fatal(err)
			}
			args := []string{"-s", "-", "--force", "--timestamp=none"}
			if mode != "no-runtime" {
				args = append(args, "--options", "runtime")
			}
			if mode == "debug-entitlement" {
				ent := filepath.Join(dir, "debug.plist")
				if err := os.WriteFile(ent, []byte(`<?xml version="1.0"?><!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd"><plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>`), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--entitlements", ent)
			}
			args = append(args, path)
			if out, err := exec.Command("/usr/bin/codesign", args...).CombinedOutput(); err != nil {
				t.Fatalf("fixture signing failed: %v %s", err, out)
			}
			info, err := exec.Command("/usr/bin/codesign", "-d", "--verbose=4", path).CombinedOutput()
			if err != nil {
				t.Fatal(err)
			}
			pin := ""
			for _, line := range strings.Split(string(info), "\n") {
				if strings.HasPrefix(line, "CDHash=") {
					pin = strings.TrimPrefix(line, "CDHash=")
				}
			}
			if pin == "" {
				t.Fatal("fixture hash unavailable")
			}
			if mode == "wrong-hash" {
				pin = strings.Repeat("0", len(pin))
			}
			verifiedChild := false
			childStatus := 0
			h := &execRecoveryHelper{path: path, pin: pin, timeout: 5 * time.Second, verify: func(pid int, hash []byte) error {
				if pid == 0 {
					return nil
				}
				verifiedChild = true
				err := verifyRecoveryCode(pid, hash)
				if refusal, ok := err.(*Refusal); ok {
					childStatus = refusal.Status
				}
				return err
			}}
			data, err := h.call(struct {
				Op string `json:"op"`
			}{"fixture"}, 68)
			if mode == "hardened" {
				if err != nil || len(data) != 68 {
					t.Fatalf("valid actual code refused: %v", err)
				}
			} else {
				recoveryCode(t, err, "helper_not_admitted")
				if childStatus != -25293 {
					t.Fatalf("policy plant did not reach the intended auth rejection: %d", childStatus)
				}
			}
			if !verifiedChild {
				t.Fatal("fixture did not reach actual child code check")
			}
			if mode != "hardened" {
				if _, err := os.Stat(path + ".received"); !os.IsNotExist(err) {
					t.Fatal("refused code received input")
				}
			}
		})
	}
}
