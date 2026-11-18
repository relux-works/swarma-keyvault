package keyvault

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const (
	rootTrustCountersignDarwinFile      = "root_grants_trust_contract_countersign_helper_darwin.go"
	rootTrustCountersignUnsupportedFile = "root_grants_trust_contract_countersign_helper_unsupported.go"
)

// This proves go list selects the actual production helper for Darwin+cgo and
// the unsupported fallback for Darwin without cgo and Linux+cgo; it detects a
// fallback build-tag mutation, but it does not typecheck or compile Darwin code.
func TestRootGrantsTrustContractCountersignHelperProductionBuildSelection(t *testing.T) {
	packageDir, err := rootTrustCountersignSelectionPackageDir()
	if err != nil {
		t.Fatal(err)
	}
	moduleDir := filepath.Clean(filepath.Join(packageDir, "..", ".."))
	for _, tc := range []struct {
		name string
		goos string
		cgo  string
		want string
	}{
		{name: "darwin cgo selects production helper", goos: "darwin", cgo: "1", want: rootTrustCountersignDarwinFile},
		{name: "darwin without cgo selects fallback", goos: "darwin", cgo: "0", want: rootTrustCountersignUnsupportedFile},
		{name: "linux cgo selects fallback", goos: "linux", cgo: "1", want: rootTrustCountersignUnsupportedFile},
	} {
		t.Run(tc.name, func(t *testing.T) {
			selection, err := rootTrustCountersignGoListSelection(t, moduleDir, tc.goos, tc.cgo)
			if err != nil {
				t.Fatal(err)
			}
			if err := rootTrustCountersignAssertSelection(selection, tc.want); err != nil {
				t.Fatal(err)
			}
		})
	}

	// The control changes the actual fallback file's build constraint in an
	// isolated package copy. go list must select both implementations, and the
	// same production-selection assertion above must reject that wrong choice.
	mutantDir, err := rootTrustCountersignMutantPackage(t, packageDir)
	if err != nil {
		t.Fatal(err)
	}
	selection, err := rootTrustCountersignGoListSelection(t, mutantDir, "darwin", "1")
	if err != nil {
		t.Fatal(err)
	}
	if err := rootTrustCountersignAssertSelection(selection, rootTrustCountersignDarwinFile); err == nil {
		t.Fatal("build-selection assertion accepted a mutated fallback selected beside the production helper")
	}
}

type rootTrustCountersignGoSelection struct {
	selected string
	ignored  string
}

func rootTrustCountersignGoListSelection(t *testing.T, moduleDir, goos, cgo string) (rootTrustCountersignGoSelection, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	command := exec.CommandContext(ctx, goTool, "list", "-f", `{{join .GoFiles ","}}|{{join .IgnoredGoFiles ","}}`, "./internal/keyvault")
	command.Dir = moduleDir
	command.Env = rootTrustCountersignSelectionEnv(os.Environ(), goos, cgo)
	output, err := command.CombinedOutput()
	if err != nil {
		return rootTrustCountersignGoSelection{}, fmt.Errorf("go list production selection for GOOS=%s CGO_ENABLED=%s: %w: %s", goos, cgo, err, strings.TrimSpace(string(output)))
	}
	parts := strings.Split(strings.TrimSpace(string(output)), "|")
	if len(parts) != 2 {
		return rootTrustCountersignGoSelection{}, fmt.Errorf("go list returned malformed selection output for GOOS=%s CGO_ENABLED=%s", goos, cgo)
	}
	return rootTrustCountersignGoSelection{selected: parts[0], ignored: parts[1]}, nil
}

func rootTrustCountersignAssertSelection(selection rootTrustCountersignGoSelection, want string) error {
	selected := strings.Split(selection.selected, ",")
	ignored := strings.Split(selection.ignored, ",")
	if !slicesContain(selected, want) {
		return fmt.Errorf("go list did not select %s", want)
	}
	other := rootTrustCountersignUnsupportedFile
	if want == rootTrustCountersignUnsupportedFile {
		other = rootTrustCountersignDarwinFile
	}
	if slicesContain(selected, other) || !slicesContain(ignored, other) {
		return fmt.Errorf("go list selected or failed to ignore the incompatible helper %s", other)
	}
	return nil
}

func rootTrustCountersignSelectionEnv(env []string, goos, cgo string) []string {
	filtered := make([]string, 0, len(env)+6)
	for _, entry := range env {
		name, _, _ := strings.Cut(entry, "=")
		switch name {
		case "GOOS", "CGO_ENABLED", "GOTOOLCHAIN", "GOPROXY", "GOSUMDB", "GOWORK":
			continue
		default:
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, "GOOS="+goos, "CGO_ENABLED="+cgo, "GOTOOLCHAIN=local", "GOPROXY=off", "GOSUMDB=off", "GOWORK=off")
}

func rootTrustCountersignSelectionPackageDir() (string, error) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("locate build-selection test source")
	}
	return filepath.Dir(source), nil
}

func rootTrustCountersignMutantPackage(t *testing.T, sourceDir string) (string, error) {
	t.Helper()
	root := t.TempDir()
	packageDir := filepath.Join(root, "internal", "keyvault")
	if err := os.MkdirAll(packageDir, 0o700); err != nil {
		return "", err
	}
	for _, name := range []string{rootTrustCountersignDarwinFile, rootTrustCountersignUnsupportedFile} {
		content, err := os.ReadFile(filepath.Join(sourceDir, name))
		if err != nil {
			return "", err
		}
		if name == rootTrustCountersignUnsupportedFile {
			const oldTag = "//go:build !darwin || !cgo"
			if !strings.Contains(string(content), oldTag) {
				return "", fmt.Errorf("fallback source is missing its expected production build constraint")
			}
			content = []byte(strings.Replace(string(content), oldTag, "//go:build darwin && cgo", 1))
		}
		if err := os.WriteFile(filepath.Join(packageDir, name), content, 0o600); err != nil {
			return "", err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.invalid/build-selection-control\n\ngo 1.26\n"), 0o600); err != nil {
		return "", err
	}
	return root, nil
}

func slicesContain(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
