// recoverybuild creates a matched hardened vault/helper pair in a NEW directory.
// It does not run custody commands, install binaries or modify existing trust.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
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

var hashPattern = regexp.MustCompile(`(?m)^CDHash=([a-f0-9]{40}|[a-f0-9]{64})$`)
var flagPattern = regexp.MustCompile(`flags=0x([a-f0-9]+)\(`)

func checkArtifactInfo(info, entitlements []byte) (string, error) {
	hashes := hashPattern.FindAllSubmatch(info, -1)
	flags := flagPattern.FindAllSubmatch(info, -1)
	if len(hashes) != 1 || len(flags) != 1 || !bytes.Contains(info, []byte("Signature=adhoc\n")) {
		return "", errors.New("unexpected code identity")
	}
	f, err := strconv.ParseUint(string(flags[0][1]), 16, 32)
	if err != nil || f != 0x10002 {
		return "", errors.New("ad-hoc hardened runtime required")
	}
	if len(bytes.TrimSpace(entitlements)) != 0 {
		decoder := xml.NewDecoder(bytes.NewReader(entitlements))
		depth := 0
		dict := false
		root := false
		for {
			token, err := decoder.Token()
			if err == io.EOF {
				break
			}
			if err != nil {
				return "", errors.New("invalid entitlement document")
			}
			switch v := token.(type) {
			case xml.StartElement:
				if v.Name.Space != "" {
					return "", errors.New("entitlement namespace refused")
				}
				if depth == 0 {
					if root {
						return "", errors.New("multiple entitlement roots")
					}
					root = true
					if len(v.Attr) != 1 || v.Attr[0].Name.Local != "version" || v.Attr[0].Value != "1.0" {
						return "", errors.New("invalid plist version")
					}
				}
				if depth == 1 && len(v.Attr) != 0 {
					return "", errors.New("unexpected dict attributes")
				}
				if (depth == 0 && v.Name.Local != "plist") || (depth == 1 && (v.Name.Local != "dict" || dict)) || depth >= 2 {
					return "", errors.New("entitlements are not empty")
				}
				if depth == 1 {
					dict = true
				}
				depth++
			case xml.EndElement:
				depth--
			case xml.CharData:
				if len(bytes.TrimSpace(v)) != 0 {
					return "", errors.New("unexpected entitlement text")
				}
			}
		}
		if depth != 0 || !dict {
			return "", errors.New("empty entitlement dictionary required")
		}
	}
	return string(hashes[0][1]), nil
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

func inspect(ctx context.Context, log io.Writer, path string) (artifact, error) {
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
	pin, err := checkArtifactInfo(info, entitlements)
	if err != nil {
		return a, err
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return a, err
	}
	sum := sha256.Sum256(raw)
	return artifact{Path: path, SHA256: hex.EncodeToString(sum[:]), CDHash: pin, Flags: "0x10002 (adhoc,runtime)", Entitlements: "empty"}, nil
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
	if _, err := command(ctx, log, "/usr/bin/xcrun", "swiftc", "-O", "-o", helper, "cmd/mac-keyvault-enclave/main.swift"); err != nil {
		return err
	}
	if _, err := command(ctx, log, "/usr/bin/codesign", "-s", "-", "--force", "--options", "runtime", "--timestamp=none", helper); err != nil {
		return err
	}
	h, err := inspect(ctx, log, helper)
	if err != nil {
		return err
	}
	goTool := filepath.Join(runtime.GOROOT(), "bin", "go")
	link := "-X github.com/relux-works/swarma-keyvault/internal/keyvault.recoveryHelperCDHash=" + h.CDHash
	if _, err := command(ctx, log, goTool, "build", "-trimpath", "-ldflags", link, "-o", vault, "./cmd/mac-keyvault"); err != nil {
		return err
	}
	if _, err := command(ctx, log, "/usr/bin/codesign", "-s", "-", "--force", "--options", "runtime", "--timestamp=none", vault); err != nil {
		return err
	}
	v, err := inspect(ctx, log, vault)
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
	flag.Parse()
	if flag.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "no positional arguments allowed")
		os.Exit(2)
	}
	if err := build(*out, *seedVersion); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
