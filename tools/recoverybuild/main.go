// recoverybuild creates a matched hardened vault/helper pair in a NEW directory.
// It does not run custody commands, install binaries or modify existing trust.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"github.com/relux-works/swarma-keyvault/internal/nativebuild"
)

type artifact struct {
	Path         string `json:"path"`
	SHA256       string `json:"sha256"`
	CDHash       string `json:"cdhash"`
	Flags        string `json:"flags"`
	Entitlements string `json:"entitlements"`
}
type manifest struct {
	Schema string   `json:"schema"`
	Head   string   `json:"source_head"`
	Tree   string   `json:"source_tree"`
	Go     string   `json:"go_version"`
	Swift  string   `json:"swift_version"`
	Helper artifact `json:"helper"`
	Vault  artifact `json:"vault"`
}

// Signature validity and complete fixed-leaf readback are separate native checks.
func checkArtifactInfo(role codesignpolicy.Role, info, entitlements []byte) (string, error) {
	return codesignpolicy.CodeInfo(role, info, entitlements)
}

func signArtifact(ctx context.Context, log io.Writer, path string, role codesignpolicy.Role) error {
	args, err := codesignpolicy.SigningArgs(role, path)
	if err != nil {
		return err
	}
	_, err = command(ctx, log, "/usr/bin/codesign", args...)
	return err
}

func command(ctx context.Context, log io.Writer, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Match the host macOS target and exact running Go toolchain, independently
	// of ambient cross-compilation variables. No environment values are logged.
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if key != "GOOS" && key != "GOARCH" && key != "CGO_ENABLED" && key != "GOTOOLCHAIN" && key != "GOWORK" {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "GOOS=darwin", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=1", "GOTOOLCHAIN=local", "GOWORK=off")
	raw, err := cmd.CombinedOutput()
	fmt.Fprintf(log, "command=%s %q exit_error=%v\n", name, args, err)
	_, _ = log.Write(raw)
	return raw, err
}

func inspect(ctx context.Context, log io.Writer, path string, role codesignpolicy.Role) (artifact, error) {
	var a artifact
	if _, err := command(ctx, log, "/usr/bin/codesign", "--verify", "--strict", path); err != nil {
		return a, errors.New("artifact signature verification failed")
	}
	info, err := command(ctx, log, "/usr/bin/codesign", "-d", "--verbose=4", path)
	if err != nil {
		return a, err
	}
	cmd := exec.CommandContext(ctx, "/usr/bin/codesign", "-d", "--entitlements", "-", "--xml", path)
	entitlements, err := cmd.Output()
	if err != nil {
		return a, errors.New("artifact entitlement read failed")
	}
	pin, err := checkArtifactInfo(role, info, entitlements)
	if err != nil {
		return a, err
	}
	requirement, err := command(ctx, log, "/usr/bin/codesign", "-d", "-r-", path)
	if err != nil || codesignpolicy.RequirementReadback(role, requirement) != nil {
		return a, errors.New("artifact designated requirement refused")
	}
	if err := codesignpolicy.CertificateFile(path, role); err != nil {
		return a, errors.New("artifact certificate readback refused")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return a, err
	}
	sum := sha256.Sum256(raw)
	return artifact{Path: path, SHA256: hex.EncodeToString(sum[:]), CDHash: pin, Flags: "0x10000 (runtime)", Entitlements: "empty"}, nil
}

func build(out, seedVersion string) error {
	if runtime.GOOS != "darwin" || runtime.Version() != "go1.26.10" {
		return errors.New("requires macOS and the exact Go version pinned by go.mod")
	}
	if seedVersion != "" && !seedVersionPattern.MatchString(seedVersion) {
		return errors.New("seed version must be vMAJOR.MINOR.PATCH")
	}
	if !filepath.IsAbs(out) || filepath.Clean(out) != out {
		return errors.New("a new absolute output directory is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	status, err := exec.CommandContext(ctx, "git", "status", "--porcelain").Output()
	if err != nil || len(status) != 0 {
		return errors.New("build requires an exact clean committed source checkout")
	}
	head, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD").Output()
	if err != nil {
		return err
	}
	tree, err := exec.CommandContext(ctx, "git", "rev-parse", "HEAD^{tree}").Output()
	if err != nil {
		return err
	}
	if err := os.Mkdir(out, 0700); err != nil {
		return errors.New("output directory must not already exist")
	}
	log, err := os.OpenFile(filepath.Join(out, "build.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	helper := filepath.Join(out, "mac-keyvault-enclave")
	vault := filepath.Join(out, "mac-keyvault")
	swift, err := command(ctx, log, "/usr/bin/xcrun", "swiftc", "--version")
	if err != nil {
		return err
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	native, err := nativebuild.Build(ctx, nativebuild.Options{Root: root, GoTool: filepath.Join(runtime.GOROOT(), "bin", "go"), Log: log})
	if err != nil {
		return err
	}
	if err := nativebuild.CopyHelper(native, helper); err != nil {
		return err
	}
	if err := nativebuild.WriteReceipt(native, filepath.Join(out, "native-build-receipt.json")); err != nil {
		return err
	}
	if err := signArtifact(ctx, log, helper, codesignpolicy.Helper); err != nil {
		return err
	}
	h, err := inspect(ctx, log, helper, codesignpolicy.Helper)
	if err != nil {
		return err
	}
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	link := "-X github.com/relux-works/swarma-keyvault/internal/keyvault.recoveryHelperCDHash=" + h.CDHash
	if _, err := command(ctx, log, goTool, "build", "-trimpath", "-ldflags", link, "-o", vault, "./cmd/mac-keyvault"); err != nil {
		return err
	}
	if err := signArtifact(ctx, log, vault, codesignpolicy.Vault); err != nil {
		return err
	}
	v, err := inspect(ctx, log, vault, codesignpolicy.Vault)
	if err != nil {
		return err
	}
	if seedVersion != "" {
		return buildSeedBundle(ctx, log, goTool, out, seedVersion, strings.TrimSpace(string(head)), strings.TrimSpace(string(tree)), strings.TrimSpace(string(swift)), link, v, h)
	}
	m := manifest{Schema: "keyvault-recovery-build/1", Head: strings.TrimSpace(string(head)), Tree: strings.TrimSpace(string(tree)), Go: runtime.Version(), Swift: strings.TrimSpace(string(swift)), Helper: h, Vault: v}
	encoded, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	if err := os.WriteFile(filepath.Join(out, "manifest.json"), encoded, 0600); err != nil {
		return err
	}
	fmt.Println(filepath.Join(out, "manifest.json"))
	return nil
}

func main() {
	out := flag.String("out", "", "new absolute output directory")
	seedVersion := flag.String("seed-version", "", "build the complete attended seed release for this version")
	nativeOnly := flag.Bool("native-helper-only", false, "build an unqualified native package helper only; no signing, custody or installation")
	qualificationOnly := flag.Bool("root-storage-qualification-only", false, "build unsigned public-marker qualification artifacts only; no signing or execution")
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "no positional arguments allowed")
		os.Exit(2)
	}
	var err error
	if *qualificationOnly {
		var selected []string
		flag.Visit(func(f *flag.Flag) { selected = append(selected, f.Name) })
		if err = validateRootQualificationFlags(*out, selected); err == nil {
			err = buildRootQualification(context.Background(), *out)
		}
	} else if *nativeOnly {
		if *seedVersion != "" {
			err = errors.New("native helper build does not accept a seed version")
		} else {
			err = buildNativeHelper(*out)
		}
	} else {
		err = build(*out, *seedVersion)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
