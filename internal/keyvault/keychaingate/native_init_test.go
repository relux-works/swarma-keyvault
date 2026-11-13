package keychaingate

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/parser"
	"go/token"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// This is a review tripwire, not enforcement: a test cannot stop native code
// that runs before Go init. New native inputs require an explicit reviewed
// allowlist change. Use scripts/keyvault-test-confined.sh for that boundary.
// Inventory: git ls-files for native suffixes and Go imports of "C".
var reviewedNativeInputs = []string{
	"cmd/mac-keyvault-namecoin-archive/init.go",
	"cmd/mac-keyvault-namecoin-archive/init_cgo_fixture.go",
	"cmd/mac-keyvault-namecoin-archive/main.go",
	"cmd/mac-keyvault-namecoin-archive/root.go",
	"cmd/mac-keyvault-namecoin-archive/root_cgo_fixture.go",
	"internal/codesignpolicy/file_darwin.go",
	"internal/keyvault/kek/inspect_darwin.c",
	"internal/keyvault/kek/inspect_darwin.go",
	"internal/keyvault/kek/inspect_darwin.h",
	"internal/keyvault/keychaingate/canary_darwin.go",
	"internal/keyvault/keychaingate/gate_darwin.go",
	"internal/keyvault/recovery_adoption_darwin.go",
	"internal/keyvault/recovery_code_flags_darwin.go",
	"internal/keyvault/recovery_darwin.go",
	"internal/keyvault/recoveryfixture/native_darwin.go",
	"internal/keyvault/root_acl_darwin.c",
	"internal/keyvault/root_acl_darwin.h",
	"internal/keyvault/root_acl_fault_darwin.go",
	"internal/keyvault/root_grants_store_darwin.c",
	"internal/keyvault/root_grants_store_darwin.h",
	"internal/keyvault/root_grants_vault_darwin.go",
	"internal/keyvault/root_qualification_darwin.c",
	"internal/keyvault/root_qualification_read_darwin.go",
	"internal/keyvault/security_darwin.c",
	"internal/keyvault/security_darwin.go",
	"internal/keyvault/security_darwin.h",
}

func nativeSuffix(name string) bool {
	switch filepath.Ext(name) {
	case ".c", ".h", ".m", ".mm", ".cc", ".cpp", ".cxx", ".hh", ".hpp", ".inc", ".s", ".S", ".sx", ".syso":
		return true
	}
	return false
}

func importsC(path string) (bool, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return false, err
	}
	for _, spec := range file.Imports {
		name, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return false, err
		}
		if name == "C" {
			return true, nil
		}
	}
	return false, nil
}

func nativeInputs(root string) ([]string, error) {
	var inputs []string
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			if inCheckoutState(rel) {
				return filepath.SkipDir
			}
			return nil
		}
		// Do not silently omit source behind a symlink or another special file.
		if !entry.Type().IsRegular() {
			return fmt.Errorf("uninspected input: %s", path)
		}
		native := nativeSuffix(path)
		if filepath.Ext(path) == ".go" {
			native, err = importsC(path)
			if err != nil {
				return err
			}
		}
		if native {
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			ref, err := checkoutStateReference(path)
			if err != nil {
				return fmt.Errorf("native input %s: %w", rel, err)
			}
			if ref != "" {
				return fmt.Errorf("native input %s names checkout state: %q", rel, ref)
			}
			inputs = append(inputs, filepath.ToSlash(rel))
		}
		return nil
	})
	slices.Sort(inputs)
	return inputs, err
}

// checkoutState lists the root-level directories that hold a checkout's own
// state rather than source: version control, scratch and local tool state. In
// a git work tree, every file under them is ignored and none is tracked
// (checkStateUntracked). Go can still build a package inside one when an
// import or an explicit argument names it, so the walk skips
// them only together with two checks: no package the default build graph
// selects lies inside one (checkDependencyInputs), and no native input names
// one (checkoutStateReference). .git and .temp are skipped at any depth, as
// before.
var checkoutState = []string{".agents", ".claude", ".codex", ".git", ".local", ".planning", ".task-board", ".temp"}

// inCheckoutState reports whether a module-relative path lies in checkout
// state.
func inCheckoutState(rel string) bool {
	elements := strings.Split(filepath.ToSlash(rel), "/")
	if slices.Contains(checkoutState, elements[0]) {
		return true
	}
	return slices.Contains(elements, ".git") || slices.Contains(elements, ".temp")
}

// stateName matches a checkout-state directory name used as a whole name, in
// any letter case, since the file system may ignore case; ".github" does not
// match ".git".
var stateName = func() *regexp.Regexp {
	names := make([]string, len(checkoutState))
	for i, name := range checkoutState {
		names[i] = regexp.QuoteMeta(name)
	}
	return regexp.MustCompile(`(?i)(?:` + strings.Join(names, "|") + `)(?:[^A-Za-z0-9_-]|$)`)
}()

// continuation joins a backslash, optional horizontal space and a line end,
// as the C preprocessor does (a space before the line end draws a warning, not
// an error).
var continuation = regexp.MustCompile(`\\[ \t\f\v]*\r?\n`)

// checkoutStateReference returns the first mention of a checkout-state
// directory in a native input. It is a conservative review admission check, not
// a model of the preprocessor or of cgo: it matches text, so a comment, a
// quoted or attached flag operand and a line-comment cgo preamble all count.
// Before matching, the trigraph ??/ becomes a backslash and continued lines are
// joined; the text is matched as is and with backslashes and quotes removed
// together (cgo escapes and quoting can join fragments).
// Known limits: names assembled by macro token pasting or other
// preprocessing, and include paths from CGO_CFLAGS or pkg-config, are not
// visible to a text scan; the confinement wrapper, not this tripwire, bounds
// native startup.
func checkoutStateReference(path string) (string, error) {
	source, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	source = bytes.ReplaceAll(source, []byte("??/"), []byte(`\`))
	source = continuation.ReplaceAll(source, nil)
	joined := strings.NewReplacer(`\`, "", `"`, "", "'", "").Replace(string(source))
	for _, view := range [][]byte{source, []byte(joined)} {
		if m := stateName.Find(view); m != nil {
			return string(m), nil
		}
	}
	return "", nil
}

// checkStateUntracked keeps the skipped directories to local state: in a git
// work tree, git tracks no file under a checkout-state name and reports none
// there as untracked and unignored, by its effective rules (nested .gitignore
// files, info/exclude and core.excludesFile included). The work tree may
// enclose the module root. Only a root without a .git entry in itself or any
// parent, such as a source archive, is not checked; with one, a failing git
// command is an error.
func checkStateUntracked(root string) error {
	inTree := false
	for dir := root; ; dir = filepath.Dir(dir) {
		if _, err := os.Lstat(filepath.Join(dir, ".git")); err == nil {
			inTree = true
			break
		} else if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		if filepath.Dir(dir) == dir {
			break
		}
	}
	if !inTree {
		return nil
	}
	var names []string
	for _, name := range checkoutState {
		if name != ".git" {
			names = append(names, name)
		}
	}
	git := func(args ...string) ([]string, error) {
		cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			return nil, fmt.Errorf("git %v: %w: %s", args, err, bytes.TrimSpace(stderr.Bytes()))
		}
		if len(out) == 0 {
			return nil, nil
		}
		return strings.Split(strings.TrimSuffix(string(out), "\x00"), "\x00"), nil
	}
	tracked, err := git(append([]string{"ls-files", "-z", "--"}, names...)...)
	if err != nil {
		return err
	}
	if len(tracked) != 0 {
		return fmt.Errorf("checkout state holds tracked files: %q", tracked)
	}
	unignored, err := git(append([]string{"ls-files", "-z", "--others", "--exclude-standard", "--"}, names...)...)
	if err != nil {
		return err
	}
	if len(unignored) != 0 {
		return fmt.Errorf("checkout state holds files that are not ignored: %q", unignored)
	}
	return nil
}

func checkNativeInputs(root string, allowlist []string) error {
	inputs, err := nativeInputs(root)
	if err != nil {
		return err
	}
	for _, input := range inputs {
		if !slices.Contains(allowlist, input) {
			return fmt.Errorf("unreviewed native input: %s", input)
		}
	}
	for _, reviewed := range allowlist {
		if !slices.Contains(inputs, reviewed) {
			return fmt.Errorf("stale native allowlist entry: %s", reviewed)
		}
	}
	return nil
}

type listedPackage struct {
	ImportPath, Dir                            string
	Standard                                   bool
	CgoFiles, CFiles, CXXFiles, MFiles, HFiles []string
	SFiles, SysoFiles                          []string
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found above the test directory")
		}
		dir = parent
	}
}

func dependencyNativeInputs(p listedPackage) []string {
	var inputs []string
	for _, files := range [][]string{p.CgoFiles, p.CFiles, p.CXXFiles, p.MFiles, p.HFiles, p.SysoFiles} {
		inputs = append(inputs, files...)
	}
	for _, name := range p.SFiles {
		// Go assembly (.s) in non-cgo packages is allowed: the Go assembler
		// emits Go functions, not native linker constructor sections. Uppercase
		// .S and .sx go through a native toolchain and are not exempt.
		if nativeSuffix(name) && (filepath.Ext(name) != ".s" || len(p.CgoFiles) != 0) {
			inputs = append(inputs, name)
		}
	}
	return inputs
}

// The module tree outside checkout state, including tag-excluded files and
// subdirectory headers, must match the reviewed native inventory, and no native
// input may name checkout state. This does not enforce confinement.
func TestNativeInputTripwire(t *testing.T) {
	root := moduleRoot(t)
	if err := checkStateUntracked(root); err != nil {
		t.Fatal(err)
	}
	if err := checkNativeInputs(root, reviewedNativeInputs); err != nil {
		t.Fatal(err)
	}
}

// Default-build non-standard dependencies outside the module must not add native
// inputs, and no package of the module's build graph may lie in checkout state,
// which the inventory walk skips. Other build graphs need their own review; the
// wrapper enforces startup.
func TestDependencyNativeInputTripwire(t *testing.T) {
	if err := checkDependencyInputs(moduleRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func checkDependencyInputs(root string) error {
	// Go reports package directories from its working directory. Compare them
	// with the same physical root, including when TMPDIR uses /tmp's alias.
	resolvedRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return fmt.Errorf("resolve module root: %w", err)
	}
	root = resolvedRoot
	cmd := exec.Command("go", "list", "-deps", "-test", "-json", "./...")
	cmd.Dir = root
	// An explicit Env otherwise retains a valid same-directory alias PWD.
	cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=", "PWD="+root)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("go list: %v\n%s", err, stderr.Bytes())
	}
	var errs []error
	moduleSeen := false
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p listedPackage
		if err := dec.Decode(&p); errors.Is(err, io.EOF) {
			break
		} else if err != nil {
			return err
		}
		if p.Standard {
			continue
		}
		if p.Dir == "" {
			return fmt.Errorf("go list returned no directory for %q", p.ImportPath)
		}
		rel, err := filepath.Rel(root, p.Dir)
		if err != nil {
			return err
		}
		if rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			moduleSeen = true
			if inCheckoutState(rel) {
				errs = append(errs, fmt.Errorf("build graph selects %s from checkout state %s", p.ImportPath, filepath.ToSlash(rel)))
			}
			continue
		}
		if inputs := dependencyNativeInputs(p); len(inputs) != 0 {
			errs = append(errs, fmt.Errorf("unreviewed external native dependency %s: %v", p.ImportPath, inputs))
		}
	}
	if !moduleSeen {
		errs = append(errs, errors.New("go list returned no module packages; dependency inventory is incomplete"))
	}
	return errors.Join(errs...)
}

// Scan-only controls plant native inputs without compiling or executing them.
// Detection proves review admission, not prevention of native startup.
func TestNativeInputTripwireControls(t *testing.T) {
	root := t.TempDir()
	write := func(name, source string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("ordinary.go", "package ordinary\n")
	write(".temp/ignored.c", "ignored scratch")
	write(".git/ignored.h", "ignored metadata")
	if err := checkNativeInputs(root, nil); err != nil {
		t.Fatalf("pure Go control: %v", err)
	}
	for _, name := range []string{"excluded.c", "include/startup.h", "excluded.cc", "excluded.go", "excluded.syso", "other.m", "other.mm", "other.cpp", "other.cxx", "other.hh", "other.hpp", "other.inc", "other.s", "other.S", "other.sx"} {
		t.Run(name, func(t *testing.T) {
			source := "//go:build never_enabled_tripwire_fixture\n\n"
			if filepath.Ext(name) == ".go" {
				source += "package fixture\nimport (\n_ \"fmt\"\n`C`\n)\n"
			}
			write(name, source)
			if err := checkNativeInputs(root, nil); err == nil || !strings.Contains(err.Error(), name) {
				t.Fatalf("planted input was not rejected: %v", err)
			}
			if err := checkNativeInputs(root, []string{name}); err != nil {
				t.Fatalf("explicit review control: %v", err)
			}
			if err := os.Remove(filepath.Join(root, name)); err != nil {
				t.Fatal(err)
			}
		})
	}
	if err := checkNativeInputs(root, []string{"missing.c"}); err == nil {
		t.Fatal("stale allowlist was accepted")
	}
}

// A checkout's local tool state in the named checkout-state directories (a
// board's C probe, a legacy install's symlinks) does not trip the scan, which
// is what a main checkout holds. Everything else still does: a symlink or an
// unlisted native file elsewhere, a dot-named file, and native files in any
// other dot-directory, nested or at the root, including testdata. A dot-named
// module root is scanned. An unreadable input reports its read error only.
func TestNativeInputTripwireCheckoutState(t *testing.T) {
	root := t.TempDir()
	write := func(name, source string) {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	remove := func(name string) {
		t.Helper()
		if err := os.Remove(filepath.Join(root, name)); err != nil {
			t.Fatal(err)
		}
	}
	write("ordinary.go", "package ordinary\n")
	write(".task-board/.resources/T/probe.c", "int probe;")
	write(".agents/.skills/pdf/SKILL.md", "skill")
	write(".agents/.configs/settings.json", "{}")
	for _, l := range [][2]string{{".agents/.skills/pdf", ".agents/skills/pdf"}, {".agents/.configs/settings.json", ".claude/settings.json"}} {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(root, l[1])), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(root, l[0]), filepath.Join(root, l[1])); err != nil {
			t.Fatal(err)
		}
	}
	write("pkg/ok.c", "// see .github/workflows\n#include \"ok.h\"\n#include <Security/Security.h>\n#include \"../include/shared.h\"\n")
	if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err != nil {
		t.Fatalf("local tool state control: %v", err)
	}

	if err := os.Symlink(filepath.Join(root, "ordinary.go"), filepath.Join(root, "pkg/linked.go")); err != nil {
		t.Fatal(err)
	}
	if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err == nil || !strings.Contains(err.Error(), "uninspected input") {
		t.Fatalf("symlink in a package directory: %v", err)
	}
	remove("pkg/linked.go")

	for _, name := range []string{"pkg/unlisted.h", "pkg/.hidden.c", ".native/native.c", "pkg/.agents/nested.c", "testdata/.fixtures/native.c"} {
		write(name, "int x;")
		if err := checkNativeInputs(root, []string{"pkg/ok.c"}); err == nil || !strings.Contains(err.Error(), name) {
			t.Fatalf("%s: %v", name, err)
		}
		remove(name)
	}

	write("pkg/unreadable.c", "int x;")
	if err := os.Chmod(filepath.Join(root, "pkg/unreadable.c"), 0); err != nil {
		t.Fatal(err)
	}
	err := checkNativeInputs(root, []string{"pkg/ok.c", "pkg/unreadable.c"})
	if !errors.Is(err, os.ErrPermission) || strings.Contains(err.Error(), "checkout state") {
		t.Fatalf("unreadable input: %v", err)
	}
	if err := os.Chmod(filepath.Join(root, "pkg/unreadable.c"), 0o600); err != nil {
		t.Fatal(err)
	}
	remove("pkg/unreadable.c")

	dotRoot := filepath.Join(t.TempDir(), ".checkout")
	if err := os.MkdirAll(dotRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dotRoot, "unlisted.c"), []byte("int x;"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkNativeInputs(dotRoot, nil); err == nil || !strings.Contains(err.Error(), "unlisted.c") {
		t.Fatalf("a dot-named module root was skipped: %v", err)
	}
}

// A native input that names checkout state is refused even when reviewed, in
// the forms PR82 reviews r1 to r3 found missed: line-comment cgo preambles,
// LF, CRLF and space-padded backslash continuations, attached and quoted flag
// operands, ${SRCDIR} paths, another letter case, a cgo backslash escape, a ??/
// trigraph and cgo quote concatenation. A name used as a longer word
// (.github, .templates) and ordinary includes pass (controls). Limit: names
// assembled by macro token pasting or other preprocessing, CGO_CFLAGS and
// pkg-config are not visible to a text scan.
func TestNativeInputTripwireStateReferences(t *testing.T) {
	refused := []struct{ name, source, ref string }{
		{"pkg/inc.c", "#include \"../.agents/evil.h\"\n", ".agents/"},
		{"pkg/next.h", "#  include_next <.task-board/evil.h>\n", ".task-board/"},
		{"pkg/line.go", "package pkg\n\n// #include \".claude/x.h\"\nimport \"C\"\n", ".claude/"},
		{"pkg/cont.c", "#include \".co\\\ndex/x.h\"\n", ".codex/"},
		{"pkg/joined.go", "package pkg\n\n// #cgo CFLAGS: -I.temp\nimport \"C\"\n", ".temp\n"},
		{"pkg/quoted.go", "package pkg\n\n/*\n#cgo CFLAGS: -I \".local\"\n*/\nimport \"C\"\n", ".local\""},
		{"pkg/srcdir.go", "package pkg\n\n/*\n#cgo CFLAGS: -iquote${SRCDIR}/.planning\n*/\nimport \"C\"\n", ".planning\n"},
		{"pkg/git.S", "#include \"../../.git/x.h\"\n", ".git/"},
		{"pkg/case.c", "#include \".Agents/x.h\"\n", ".Agents/"},
		{"pkg/crlf.c", "#include \".ag\\\r\nents/x.h\"\r\n", ".agents/"},
		{"pkg/escaped.go", "package pkg\n\n// #cgo CFLAGS: -I.age\\nts\n// #include <x.h>\nimport \"C\"\n", ".agents\n"},
		{"pkg/trigraph.go", "package pkg\n\n/*\n#cgo CFLAGS: -std=c11\n#include \".age??/\nnts/x.h\"\n*/\nimport \"C\"\n", ".agents/"},
		{"pkg/dquote.go", "package pkg\n\n// #cgo CFLAGS: -I.ag\"en\"ts\nimport \"C\"\n", ".agents\n"},
		{"pkg/squote.go", "package pkg\n\n// #cgo CFLAGS: -I.ag'en'ts\nimport \"C\"\n", ".agents\n"},
		{"pkg/empty.go", "package pkg\n\n// #cgo CFLAGS: -I.ag\"\"ents\nimport \"C\"\n", ".agents\n"},
		{"pkg/spaced.c", "#include \".age\\ \t\nnts/x.h\"\n", ".agents/"},
	}
	for _, c := range refused {
		t.Run(c.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, c.name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(c.source), 0o600); err != nil {
				t.Fatal(err)
			}
			err := checkNativeInputs(root, []string{c.name})
			if err == nil || !strings.Contains(err.Error(), "names checkout state") || !strings.Contains(err.Error(), strconv.Quote(c.ref)) {
				t.Fatalf("not refused: %v", err)
			}
		})
	}
	root := t.TempDir()
	ok := "// see .github and .templates/x\n#include \"ok.h\"\n#include <Security/Security.h>\n#include \"../include/shared.h\"\n"
	if err := os.WriteFile(filepath.Join(root, "ok.c"), []byte(ok), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := checkNativeInputs(root, []string{"ok.c"}); err != nil {
		t.Fatalf("control: %v", err)
	}
}

// Imported checkout-state packages are refused, while a plain module passes,
// for supplied, physical and symlinked roots, with default environment or a
// valid same-directory alias PWD. This retains the temporary-root regression
// and checks the child environment without changing the parent globally.
// Limit: explicit-only packages remain outside the default build graph.
func TestDependencyGraphCheckoutState(t *testing.T) {
	module := func(t *testing.T, main string) string {
		t.Helper()
		root := t.TempDir()
		files := map[string]string{
			"go.mod":         "module example.com/fixture\n\ngo 1.25\n",
			"main.go":        main,
			".agents/x/x.go": "package x\n\nconst X = 1\n",
			"lib/lib.go":     "package lib\n\nconst Y = 2\n",
		}
		for name, source := range files {
			path := filepath.Join(root, name)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return root
	}
	for _, aliasPWD := range []bool{false, true} {
		environment := "default-env"
		if aliasPWD {
			environment = "alias-pwd"
		}
		t.Run(environment, func(t *testing.T) {
			for _, spelling := range []string{"supplied", "physical", "symlink"} {
				t.Run(spelling, func(t *testing.T) {
					for _, hidden := range []bool{true, false} {
						name := "plain"
						main := "package main\n\nimport _ \"example.com/fixture/lib\"\n\nfunc main() {}\n"
						if hidden {
							name = "hidden"
							main = "package main\n\nimport (\n\t_ \"example.com/fixture/.agents/x\"\n\t_ \"example.com/fixture/lib\"\n)\n\nfunc main() {}\n"
						}
						t.Run(name, func(t *testing.T) {
							root := module(t, main)
							if spelling != "supplied" {
								var err error
								root, err = filepath.EvalSymlinks(root)
								if err != nil {
									t.Fatal(err)
								}
							}
							alias := ""
							if spelling == "symlink" || aliasPWD {
								alias = filepath.Join(t.TempDir(), "module")
								if err := os.Symlink(root, alias); err != nil {
									t.Fatal(err)
								}
							}
							if spelling == "symlink" {
								root = alias
							}
							if aliasPWD {
								rootInfo, err := os.Stat(root)
								if err != nil {
									t.Fatal(err)
								}
								aliasInfo, err := os.Stat(alias)
								if err != nil || !os.SameFile(rootInfo, aliasInfo) {
									t.Fatalf("PWD alias does not name the module: %v", err)
								}
								t.Setenv("PWD", alias)
							}
							err := checkDependencyInputs(root)
							if hidden {
								if err == nil || !strings.Contains(err.Error(), "from checkout state .agents/x") {
									t.Fatalf("hidden package not refused: %v", err)
								}
							} else if err != nil {
								t.Fatalf("control: %v", err)
							}
						})
					}
				})
			}
		})
	}
}

// A missing module root remains a specific filesystem failure, never an empty
// dependency inventory that can be accepted as a successful scan.
func TestDependencyGraphMissingRoot(t *testing.T) {
	err := checkDependencyInputs(filepath.Join(t.TempDir(), "absent"))
	if !errors.Is(err, fs.ErrNotExist) || !strings.Contains(err.Error(), "resolve module root") {
		t.Fatalf("missing root: %v", err)
	}
}

// In a git work tree, checkout state must hold only ignored, untracked files.
// Refused: a file force-added under an ignore rule (PR82 review r2), a root
// negation, a nested .gitignore that ignores everything but one file while the
// root rule is missing (review r3), and a tracked file in a module that is a
// subdirectory of the work tree (review r3). Passing controls: every name
// ignored and nothing tracked, a nested negation under an ignored directory
// (git cannot re-include it), and a tree with no .git in itself or a parent.
// A work tree where git cannot run is an error, not a pass.
// The fixtures run git with no global or system configuration and no
// templates. Limit: needs git on PATH inside a work tree.
func TestCheckoutStateUntracked(t *testing.T) {
	t.Setenv("GIT_CONFIG_GLOBAL", os.DevNull)
	t.Setenv("GIT_CONFIG_NOSYSTEM", "1")
	var ignore strings.Builder
	for _, name := range checkoutState {
		if name != ".git" {
			ignore.WriteString("/" + name + "/\n")
		}
	}
	write := func(t *testing.T, path, content string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	gitRun := func(t *testing.T, root string, args ...string) {
		t.Helper()
		if out, err := exec.Command("git", append([]string{"-C", root}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v %s", args, err, out)
		}
	}
	repo := func(t *testing.T, gitignore string) string {
		t.Helper()
		root := t.TempDir()
		gitRun(t, root, "init", "-q", "--template=")
		write(t, filepath.Join(root, ".gitignore"), gitignore)
		write(t, filepath.Join(root, ".agents/payload.h"), "int x;")
		return root
	}
	if err := checkStateUntracked(repo(t, ignore.String())); err != nil {
		t.Fatalf("control: %v", err)
	}
	nested := repo(t, ignore.String())
	write(t, filepath.Join(nested, ".agents/.gitignore"), "!payload.h\n")
	if err := checkStateUntracked(nested); err != nil {
		t.Fatalf("nested negation under an ignored directory: %v", err)
	}
	archive := t.TempDir()
	write(t, filepath.Join(archive, ".agents/payload.h"), "int x;")
	if err := checkStateUntracked(archive); err != nil {
		t.Fatalf("tree without .git: %v", err)
	}

	forced := repo(t, ignore.String())
	gitRun(t, forced, "add", "-f", ".agents/payload.h")
	if err := checkStateUntracked(forced); err == nil || !strings.Contains(err.Error(), "tracked files") || !strings.Contains(err.Error(), ".agents/payload.h") {
		t.Fatalf("tracked file admitted: %v", err)
	}
	negated := repo(t, ignore.String()+"!/.agents/\n")
	if err := checkStateUntracked(negated); err == nil || !strings.Contains(err.Error(), "not ignored") {
		t.Fatalf("root negation admitted: %v", err)
	}
	nestedOnly := repo(t, strings.Replace(ignore.String(), "/.agents/\n", "", 1))
	write(t, filepath.Join(nestedOnly, ".agents/.gitignore"), "*\n!payload.h\n")
	if err := checkStateUntracked(nestedOnly); err == nil || !strings.Contains(err.Error(), ".agents/payload.h") {
		t.Fatalf("a nested rule standing in for the directory rule was admitted: %v", err)
	}
	parent := repo(t, ignore.String())
	module := filepath.Join(parent, "submodule")
	write(t, filepath.Join(module, ".agents/payload.h"), "int x;")
	gitRun(t, parent, "add", "-f", "submodule/.agents/payload.h")
	if err := checkStateUntracked(module); err == nil || !strings.Contains(err.Error(), "tracked files") {
		t.Fatalf("a module inside a work tree skipped git: %v", err)
	}
	clean := repo(t, ignore.String())
	t.Setenv("PATH", t.TempDir())
	if err := checkStateUntracked(clean); err == nil || !strings.Contains(err.Error(), "git") {
		t.Fatalf("a work tree without a usable git passed: %v", err)
	}
}

// External native fields are refused; pure Go assembly remains allowed.
func TestDependencyNativeInputControls(t *testing.T) {
	for _, p := range []listedPackage{
		{CgoFiles: []string{"native.go"}}, {CFiles: []string{"native.c"}},
		{CXXFiles: []string{"native.cc"}}, {MFiles: []string{"native.m"}},
		{HFiles: []string{"native.h"}}, {SFiles: []string{"native.S"}},
		{SFiles: []string{"native.sx"}}, {SysoFiles: []string{"native.syso"}},
	} {
		if inputs := dependencyNativeInputs(p); len(inputs) == 0 {
			t.Errorf("native dependency accepted: %+v", p)
		}
	}
	if inputs := dependencyNativeInputs(listedPackage{SFiles: []string{"go_asm.s"}}); len(inputs) != 0 {
		t.Fatalf("Go assembly control rejected: %v", inputs)
	}
}
