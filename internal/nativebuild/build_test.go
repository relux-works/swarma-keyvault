package nativebuild

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

// All files are disposable PUBLIC fixtures. The executor below only writes
// public marker bytes to witness orchestration; it does NOT build Go/C/Swift,
// produce an executable, authenticate native code or prove package discovery.
func sourceFixture(t *testing.T) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("public fixture setup")
	}
	for name, body := range map[string]string{
		"internal/keyvault/recoverydata/english.txt": "PUBLIC embedded word-list fixture\n",
		"go.mod": "module public.example/fixture\n", "go.sum": "public sum fixture\n", "Package.swift": "public package source fixture\n",
		"cmd/mac-keyvault-namecoin-abi/module.modulemap": "module NamecoinArchiveABI [system] { header \"libkeyvault_namecoin.h\" export * }\n",
		"cmd/mac-keyvault-namecoin-archive/main.go":      "package main\n", "cmd/mac-keyvault-enclave/Core.swift": "// public source\n",
		"internal/sample/source.go": "package sample\n", "third_party/sample/source.go": "package sample\n", "tools/recoverybuild/main.go": "package main\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(p), 0700) != nil || os.WriteFile(p, []byte(body), 0600) != nil {
			t.Fatal("public fixture setup")
		}
	}
	// Only restore permissions on these owned disposable PUBLIC fixture dirs
	// after this test finishes. Production Build never cleans retained generations.
	t.Cleanup(func() {
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e == nil && d.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	})
	return root
}
func writePublic(t *testing.T, path string, b []byte) {
	t.Helper()
	if os.WriteFile(path, b, 0600) != nil {
		t.Fatal("public fixture write")
	}
}
func arg(args []string, key string) string {
	for i, s := range args {
		if s == key && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}

type publicExecutor struct {
	t              *testing.T
	calls          []Command
	fail           string
	stage, scratch string
	change         func()
}

func (f *publicExecutor) run(_ context.Context, c Command) ([]byte, error) {
	f.calls = append(f.calls, c)
	if c.Program == "/public/go" {
		f.stage = filepath.Dir(arg(c.Args, "-o"))
		writePublic(f.t, filepath.Join(f.stage, archiveName), []byte("PUBLIC archive marker"))
		if f.fail == "go" {
			return nil, ErrBuild
		}
		writePublic(f.t, filepath.Join(f.stage, headerName), []byte("PUBLIC header marker"))
		if f.fail == "source" {
			f.change()
		}
		return nil, nil
	}
	if c.Program != "/usr/bin/xcrun" {
		f.t.Fatal("unexpected command")
	}
	f.scratch = arg(c.Args, "--scratch-path")
	if arg(c.Args, "--product") != "" {
		if f.fail == "swift" {
			return nil, ErrBuild
		}
		if f.fail == "mutate" {
			f.change()
		}
		bin := filepath.Join(f.scratch, "arm64-apple-macosx", "release")
		if os.MkdirAll(bin, 0700) != nil {
			f.t.Fatal("public output setup")
		}
		if f.fail != "missing-helper" {
			path := filepath.Join(bin, "mac-keyvault-enclave")
			writePublic(f.t, path, []byte("PUBLIC helper marker"))
			if os.Chmod(path, 0700) != nil {
				f.t.Fatal("public marker mode")
			}
		}
		return nil, nil
	}
	if f.fail == "show" {
		return nil, ErrBuild
	}
	if f.fail == "escape" {
		return []byte("/tmp\n"), nil
	}
	return []byte(filepath.Join(f.scratch, "arm64-apple-macosx", "release") + "\n"), nil
}
func runPublic(t *testing.T, root string) (Result, *publicExecutor, error) {
	t.Helper()
	f := &publicExecutor{t: t}
	r, e := Build(context.Background(), Options{Root: root, GoTool: "/public/go", Execute: f.run})
	return r, f, e
}
func requireRefusal(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, ErrBuild) {
		t.Fatal("expected fixed native build refusal")
	}
}

// Valid controls include every build-input directory emitted by this builder
// and the retained explicit compatibility form. Escapes/noncanonical/unknown
// forms refuse before command execution; this is path syntax, not authority.
func TestInputAllowlist(t *testing.T) {
	for _, s := range []string{".temp/native-archive-" + strings.Repeat("a", 32), ".temp/native-archive-" + strings.Repeat("0", 32), ".temp/namecoin-native-archive"} {
		if !ValidInput(s) {
			t.Fatal("valid input refused")
		}
	}
	for _, s := range []string{"", "/tmp/archive", "../.temp/namecoin-native-archive", ".temp/../outside", ".temp//namecoin-native-archive", ".temp/native-archive-a", ".temp/native-archive-" + strings.Repeat("A", 32), ".temp/namecoin-native-archive/", ".temp/namecoin-native-archive\n", ".temp/other"} {
		if ValidInput(s) {
			t.Fatal("forbidden input admitted")
		}
	}
}

// Real hashes/receipt files and closed fake command selection. Public marker
// bytes do not establish actual generated declarations, linking or native success.
func TestFreshBuildCommandsReceiptAndCopy(t *testing.T) {
	root := sourceFixture(t)
	r, f, err := runPublic(t, root)
	if err != nil {
		t.Fatal("valid public orchestration refused")
	}
	if len(f.calls) != 3 {
		t.Fatal("wrong command count")
	}
	wantGo := []string{"build", "-p", "1", "-mod=readonly", "-trimpath", "-buildmode=c-archive", "-o", filepath.Join(root, filepath.FromSlash(r.Directory), archiveName), "./cmd/mac-keyvault-namecoin-archive"}
	if !reflect.DeepEqual(f.calls[0].Args, wantGo) {
		t.Fatal("wrong Go target/argv")
	}
	wantSwift := []string{"swift", "build", "--jobs", "1", "--package-path", root, "--scratch-path", r.Scratch, "--configuration", "release", "--product", "mac-keyvault-enclave"}
	if !reflect.DeepEqual(f.calls[1].Args, wantSwift) {
		t.Fatal("wrong production package selection")
	}
	wantShow := []string{"swift", "build", "--jobs", "1", "--package-path", root, "--scratch-path", r.Scratch, "--configuration", "release", "--show-bin-path"}
	if !reflect.DeepEqual(f.calls[2].Args, wantShow) {
		t.Fatal("wrong product location query")
	}
	for _, c := range f.calls {
		if c.Dir != root {
			t.Fatal("wrong command source root")
		}
		found := false
		for _, entry := range c.Env {
			if entry == InputVariable+"="+r.Directory {
				found = true
			}
		}
		if !found {
			t.Fatal("missing exact selected generation")
		}
	}
	source, e := SourceDigest(root)
	if e != nil {
		t.Fatal("source fixture refused")
	}
	receipt, e := ValidateStage(root, r.Directory, source)
	if e != nil || receipt != r.Receipt {
		t.Fatal("exact pair did not validate")
	}
	if receipt.ArchiveSHA256 != sum([]byte("PUBLIC archive marker")) || receipt.HeaderSHA256 != sum([]byte("PUBLIC header marker")) {
		t.Fatal("paired hash mismatch")
	}
	destination := filepath.Join(root, "new-helper")
	if CopyHelper(r, destination) != nil {
		t.Fatal("public copy refused")
	}
	requireRefusal(t, CopyHelper(r, destination))
	b, e := os.ReadFile(destination)
	if e != nil || string(b) != "PUBLIC helper marker" {
		t.Fatal("existing destination changed")
	}
	if _, e = os.Stat(r.Helper); e != nil {
		t.Fatal("original public output removed")
	}
}

// Repeated and genuinely concurrent orchestration uses independent real public
// directories/pairs. No OS compiler runs; this is not a runtime concurrency proof.
func TestRepeatedAndConcurrentGenerationsRetainPriorBytes(t *testing.T) {
	root := sourceFixture(t)
	first, _, err := runPublic(t, root)
	if err != nil {
		t.Fatal("first build refused")
	}
	var results [2]Result
	var errs [2]error
	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) { defer wg.Done(); results[i], _, errs[i] = runPublic(t, root) }(i)
	}
	wg.Wait()
	seen := map[string]bool{first.Directory: true}
	for i, r := range results {
		if errs[i] != nil || seen[r.Directory] {
			t.Fatal("generation collision/refusal")
		}
		seen[r.Directory] = true
		if _, err = os.Stat(r.Helper); err != nil {
			t.Fatal("result removed")
		}
	}
	source, _ := SourceDigest(root)
	if _, err = ValidateStage(root, first.Directory, source); err != nil {
		t.Fatal("prior generation mutated")
	}
}

// Partial failures retain PUBLIC generated bytes and stop before any later
// command. No overwrite/cleanup is used as recovery, and no failed build returns
// a helper result. These faults are synthetic command-boundary failures only.
func TestPartialFailuresAreClosedAndRetained(t *testing.T) {
	for _, fault := range []string{"go", "swift", "show", "escape", "missing-helper", "source"} {
		t.Run(fault, func(t *testing.T) {
			root := sourceFixture(t)
			f := &publicExecutor{t: t, fail: fault, change: func() { writePublic(t, filepath.Join(root, "Package.swift"), []byte("changed PUBLIC source\n")) }}
			r, err := Build(context.Background(), Options{Root: root, GoTool: "/public/go", Execute: f.run})
			requireRefusal(t, err)
			if r.Helper != "" {
				t.Fatal("failure returned helper")
			}
			if _, err = os.Stat(filepath.Join(f.stage, archiveName)); err != nil {
				t.Fatal("partial archive removed")
			}
			if (fault == "go" || fault == "source") && len(f.calls) != 1 {
				t.Fatal("compile proceeded after failed archive/source")
			}
			if fault == "swift" && len(f.calls) != 2 {
				t.Fatal("location query followed failed compile")
			}
		})
	}
}

// A real on-disk header change after the fake Swift build must be detected by
// the genuine hash checker. The mutation is public fixture code, not a native
// or protected-state fault and not proof of hostile same-UID race resistance.
func TestPostCompilePairMutationRefuses(t *testing.T) {
	root := sourceFixture(t)
	f := &publicExecutor{t: t, fail: "mutate"}
	f.change = func() {
		p := filepath.Join(f.stage, headerName)
		if os.Chmod(p, 0600) != nil {
			t.Fatal("fixture chmod")
		}
		writePublic(t, p, []byte("changed PUBLIC header"))
	}
	_, err := Build(context.Background(), Options{Root: root, GoTool: "/public/go", Execute: f.run})
	requireRefusal(t, err)
	if len(f.calls) != 2 {
		t.Fatal("queried helper after pair mutation")
	}
}

// Genuine disposable file validation pairs a valid receipt with missing, mixed,
// stale, writable, symlink, extra and malformed controls. No receipt is an Apple
// code identity or proof that the public marker is a compiled archive.
func TestReceiptAndFilesystemForbiddenControls(t *testing.T) {
	for _, fault := range []string{"missing-header", "missing-archive", "missing-receipt", "mixed-header", "stale-source", "symlink", "hardlink", "writable", "writable-receipt", "extra", "unknown-field", "duplicate-field", "directory-pin"} {
		t.Run(fault, func(t *testing.T) {
			root := sourceFixture(t)
			r, _, err := runPublic(t, root)
			if err != nil {
				t.Fatal("valid control refused")
			}
			source, _ := SourceDigest(root)
			dir := filepath.Join(root, filepath.FromSlash(r.Directory))
			if os.Chmod(dir, 0700) != nil {
				t.Fatal("fixture chmod")
			}
			switch fault {
			case "missing-archive":
				if os.Remove(filepath.Join(dir, archiveName)) != nil {
					t.Fatal("fixture remove")
				}
			case "writable-receipt":
				_ = os.Chmod(filepath.Join(dir, receiptName), 0600)
			case "hardlink":
				if os.Link(filepath.Join(dir, headerName), filepath.Join(root, "public-hardlink")) != nil {
					t.Fatal("fixture hardlink")
				}
			case "missing-header":
				if os.Remove(filepath.Join(dir, headerName)) != nil {
					t.Fatal("fixture remove")
				}
			case "missing-receipt":
				if os.Remove(filepath.Join(dir, receiptName)) != nil {
					t.Fatal("fixture remove")
				}
			case "mixed-header":
				p := filepath.Join(dir, headerName)
				_ = os.Chmod(p, 0600)
				writePublic(t, p, []byte("another PUBLIC generation"))
				_ = os.Chmod(p, 0400)
			case "stale-source":
				writePublic(t, filepath.Join(root, "Package.swift"), []byte("PUBLIC changed source after receipt\n"))
				source, err = SourceDigest(root)
				if err != nil {
					t.Fatal("changed source fixture")
				}
			case "symlink":
				p := filepath.Join(dir, headerName)
				_ = os.Remove(p)
				if os.Symlink(filepath.Join(root, "go.mod"), p) != nil {
					t.Fatal("fixture symlink")
				}
			case "writable":
				_ = os.Chmod(filepath.Join(dir, archiveName), 0600)
			case "extra":
				writePublic(t, filepath.Join(dir, "unexpected"), []byte("PUBLIC extra"))
			case "unknown-field", "duplicate-field", "directory-pin":
				p := filepath.Join(dir, receiptName)
				b, e := os.ReadFile(p)
				if e != nil {
					t.Fatal("fixture receipt")
				}
				_ = os.Chmod(p, 0600)
				if fault == "unknown-field" {
					b = append([]byte("{\"unexpected\":0,"), b[1:]...)
				}
				if fault == "duplicate-field" {
					b = append([]byte("{\"schema\":\"ignored\","), b[1:]...)
				}
				if fault == "directory-pin" {
					r.Receipt.Directory = ".temp/namecoin-native-archive"
					b, _ = json.MarshalIndent(r.Receipt, "", "  ")
					b = append(b, '\n')
				}
				writePublic(t, p, b)
				_ = os.Chmod(p, 0400)
			}
			_ = os.Chmod(dir, 0500)
			_, err = ValidateStage(root, r.Directory, source)
			requireRefusal(t, err)
		})
	}
}

// The explicit compatibility directory is admitted WITH the same complete pair,
// source receipt and immutable modes; its old unreceipted workflow is retired.
func TestCompatibilityDirectoryWithCompleteReceipt(t *testing.T) {
	root := sourceFixture(t)
	r, _, err := runPublic(t, root)
	if err != nil {
		t.Fatal("valid control refused")
	}
	old := filepath.Join(root, filepath.FromSlash(r.Directory))
	dir := filepath.Join(root, ".temp/namecoin-native-archive")
	if os.Rename(old, dir) != nil {
		t.Fatal("public fixture relocation")
	}
	_ = os.Chmod(dir, 0700)
	p := filepath.Join(dir, receiptName)
	_ = os.Chmod(p, 0600)
	r.Receipt.Directory = ".temp/namecoin-native-archive"
	b, _ := json.MarshalIndent(r.Receipt, "", "  ")
	writePublic(t, p, append(b, '\n'))
	_ = os.Chmod(p, 0400)
	_ = os.Chmod(dir, 0500)
	if _, err = ValidateStage(root, r.Receipt.Directory, r.Receipt.SourceSHA256); err != nil {
		t.Fatal("complete compatibility form refused")
	}
}

// Wrong roots/tools and symlinked staging refuse before the executor is invoked.
// Symlinks and existing output sentinels are real disposable public files.
func TestPreflightAndCopyRefusalsDoNotInvokeOrOverwrite(t *testing.T) {
	root := sourceFixture(t)
	called := false
	run := func(context.Context, Command) ([]byte, error) { called = true; return nil, ErrBuild }
	_, err := Build(context.Background(), Options{Root: root, GoTool: "relative-go", Execute: run})
	requireRefusal(t, err)
	if called {
		t.Fatal("invalid tool invoked")
	}
	outside := t.TempDir()
	if os.Symlink(outside, filepath.Join(root, ".temp")) != nil {
		t.Fatal("fixture symlink")
	}
	_, err = Build(context.Background(), Options{Root: root, GoTool: "/public/go", Execute: run})
	requireRefusal(t, err)
	if called {
		t.Fatal("symlinked stage invoked")
	}
}

// Parent environment values are never dumped. Positive required variables and
// poisoned selector/flag controls test the actual allowlist, not two validators.
func TestCommandEnvironmentIsAllowlisted(t *testing.T) {
	t.Setenv("CGO_LDFLAGS", "PUBLIC poisoned flags")
	t.Setenv("GOFLAGS", "PUBLIC flags")
	t.Setenv(InputVariable, ".temp/other")
	env := Environment(".temp/native-archive-" + strings.Repeat("a", 32))
	seen := map[string]string{}
	for _, entry := range env {
		k, v, _ := strings.Cut(entry, "=")
		seen[k] = v
	}
	if _, ok := seen["CGO_LDFLAGS"]; ok {
		t.Fatal("inherited linker flags")
	}
	if _, ok := seen["GOFLAGS"]; ok {
		t.Fatal("inherited Go flags")
	}
	if seen["CGO_ENABLED"] != "1" || seen["GOTOOLCHAIN"] != "local" || seen["GOWORK"] != "off" || seen[InputVariable] != ".temp/native-archive-"+strings.Repeat("a", 32) {
		t.Fatal("closed command environment changed")
	}
}

// Source pin controls include the actual repository's production embedded public
// word-list input as well as code, and refuse symlink substitutions. No owner
// mnemonic, account material or private fixture is read or constructed.
func TestSourcePinCoversEmbeddedInputAndRefusesSymlinks(t *testing.T) {
	root := sourceFixture(t)
	before, err := SourceDigest(root)
	if err != nil {
		t.Fatal("valid source refused")
	}
	// Empty go.sum is a legitimate source form for a dependency-free module.
	writePublic(t, filepath.Join(root, "go.sum"), nil)
	if before, err = SourceDigest(root); err != nil {
		t.Fatal("empty legitimate go.sum refused")
	}
	p := filepath.Join(root, "internal/keyvault/recoverydata/english.txt")
	writePublic(t, p, []byte("changed PUBLIC embedded fixture\n"))
	after, err := SourceDigest(root)
	if err != nil || before == after {
		t.Fatal("embedded input was not pinned")
	}
	p = filepath.Join(root, "cmd/mac-keyvault-enclave/Core.swift")
	if os.Remove(p) != nil || os.Symlink(filepath.Join(root, "go.mod"), p) != nil {
		t.Fatal("public source symlink setup")
	}
	_, err = SourceDigest(root)
	requireRefusal(t, err)
}

// New output/receipt creation preserves existing bytes and rejects a changed
// source helper. A parent alias is a legitimate public output spelling; it does
// not admit aliased archive/source inputs. No marker file is ever executed.
func TestCopyAndReceiptPreserveExistingOutputs(t *testing.T) {
	root := sourceFixture(t)
	r, _, err := runPublic(t, root)
	if err != nil {
		t.Fatal("valid orchestration refused")
	}
	receipt := filepath.Join(root, "caller-receipt.json")
	if WriteReceipt(r, receipt) != nil {
		t.Fatal("new receipt refused")
	}
	before, err := os.ReadFile(receipt)
	if err != nil {
		t.Fatal("public receipt read")
	}
	requireRefusal(t, WriteReceipt(r, receipt))
	after, err := os.ReadFile(receipt)
	if err != nil || string(before) != string(after) {
		t.Fatal("existing receipt overwritten")
	}
	alias := filepath.Join(root, "public-output-alias")
	if os.Symlink(root, alias) != nil {
		t.Fatal("public output alias setup")
	}
	if CopyHelper(r, filepath.Join(alias, "new-public-helper")) != nil {
		t.Fatal("legitimate output alias refused")
	}
	invalid := r
	invalid.HelperSHA256 = strings.Repeat("0", 64)
	destination := filepath.Join(root, "must-not-exist")
	requireRefusal(t, CopyHelper(invalid, destination))
	if _, err = os.Lstat(destination); !os.IsNotExist(err) {
		t.Fatal("pre-copy refusal changed destination")
	}
	writePublic(t, r.Helper, []byte("changed PUBLIC helper marker"))
	requireRefusal(t, CopyHelper(r, destination))
}

// A canceled build is a fixed pre-command refusal with no success result. This
// tests Go orchestration only, not cancellation of a real compiler/private use.
func TestCancellationRefusesBeforeCommand(t *testing.T) {
	root := sourceFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	called := false
	r, err := Build(ctx, Options{Root: root, GoTool: "/public/go", Execute: func(context.Context, Command) ([]byte, error) { called = true; return nil, ErrBuild }})
	requireRefusal(t, err)
	if called || r.Helper != "" {
		t.Fatal("canceled build dispatched or returned helper")
	}
}
