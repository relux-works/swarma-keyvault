// verifiertoolchain qualifies the measurement toolchain using Go's module
// parser. It performs no dependency provisioning or product operation.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/version"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"time"
)

var exactToolchain = regexp.MustCompile(`^go[0-9]+\.[0-9]+\.[0-9]+$`)

func qualify(modfile, actual string) error {
	path, err := filepath.Abs(modfile)
	if err != nil {
		return errors.New("module path unavailable")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(runtime.GOROOT(), "bin", "go"), "mod", "edit", "-json", path)
	cmd.Env = append(os.Environ(), "GOTOOLCHAIN=local", "GOWORK=off")
	metadata, err := cmd.Output()
	if err != nil {
		return errors.New("Go module grammar refused or parser unavailable")
	}
	var module struct{ Go, Toolchain string }
	if err := json.Unmarshal(metadata, &module); err != nil {
		return errors.New("Go module parser returned invalid metadata")
	}
	expected := module.Toolchain
	if expected == "" {
		expected = "go" + module.Go
	}
	if !exactToolchain.MatchString(expected) {
		return errors.New("exact released toolchain pin required (explicit toolchain or patch go directive)")
	}
	if module.Go != "" && version.Compare(expected, "go"+module.Go) < 0 {
		return errors.New("selected toolchain pin is below the module Go minimum")
	}
	if actual != expected {
		return errors.New("runtime differs from the exact module toolchain pin")
	}
	return nil
}

func main() {
	modfile := flag.String("modfile", "go.mod", "module file to qualify without modifying it")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "verifier toolchain precondition failed: unexpected argument")
		os.Exit(2)
	}
	if err := qualify(*modfile, runtime.Version()); err != nil {
		fmt.Fprintln(os.Stderr, "verifier toolchain precondition failed:", err)
		os.Exit(2)
	}
}
