package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/nativebuild"
	"golang.org/x/sys/unix"
)

// SOURCE tests only. Fake command output below is PUBLIC marker data, never an
// archive/header/executable or signature/native qualification success witness.
func qualificationError(t *testing.T, err error) {
	t.Helper()
	if !errors.Is(err, errQualificationBuild) {
		t.Fatal("expected fixed unsigned build refusal")
	}
}

// Exercise the actual flag library behavior and the production mode validator;
// no main/build/command is executed. Existing flag syntax remains unchanged.
func TestRootQualificationModeFlags(t *testing.T) {
	parse := func(args []string) error {
		f := flag.NewFlagSet("public-build-fixture", flag.ContinueOnError)
		f.SetOutput(io.Discard)
		out := f.String("out", "", "")
		mode := f.Bool("root-storage-qualification-only", false, "")
		f.Bool("native-helper-only", false, "")
		f.String("seed-version", "", "")
		if f.Parse(args) != nil || f.NArg() != 0 || !*mode {
			return errQualificationBuild
		}
		var selected []string
		f.Visit(func(v *flag.Flag) { selected = append(selected, v.Name) })
		return validateRootQualificationFlags(*out, selected)
	}
	for _, args := range [][]string{
		{"--root-storage-qualification-only", "--out", "/public-fixture/artifacts"},
		{"--out=/public-fixture/artifacts", "--root-storage-qualification-only=true"},
	} {
		if parse(args) != nil {
			t.Fatal("legitimate qualification flag form refused")
		}
	}
	for _, args := range [][]string{
		{"--root-storage-qualification-only"},
		{"--root-storage-qualification-only", "--out", "relative/artifacts"},
		{"--root-storage-qualification-only", "--out", "/public-fixture/../artifacts"},
		{"--root-storage-qualification-only", "--out", "/public-fixture/other"},
		{"--root-storage-qualification-only", "--out", "/public-fixture/artifacts", "--native-helper-only"},
		{"--root-storage-qualification-only", "--out", "/public-fixture/artifacts", "--native-helper-only=false"},
		{"--root-storage-qualification-only", "--out", "/public-fixture/artifacts", "--seed-version="},
		{"--root-storage-qualification-only", "--out", "/public-fixture/artifacts", "--seed-version=v1.2.3"},
		{"--root-storage-qualification-only", "--out", "/public-fixture/artifacts", "extra"},
		{"--root-storage-qualification-only", "--out", "/public-fixture/artifacts", "--unknown"},
	} {
		qualificationError(t, parse(args))
	}
}

// Both real Go role argv plans pin the SAME validated source and empty helper
// pin; only the foreign role receives qualificationOnly. This is not linking.
func TestRootQualificationExactRolesAndLinkerPins(t *testing.T) {
	head, tree := strings.Repeat("1", 40), strings.Repeat("2", 40)
	for _, foreign := range []bool{false, true} {
		args, err := qualificationGoArgs("/public-fixture/work/mac-keyvault", head, tree, foreign)
		if err != nil {
			t.Fatal("valid source pins refused")
		}
		link := "-X github.com/relux-works/swarma-keyvault/internal/keyvault.recoveryHelperCDHash= -X main.rootQualificationSourceHead=" + head + " -X main.rootQualificationSourceTree=" + tree
		if foreign {
			link += " -X main.recoveryQualificationOnly=1"
		}
		want := []string{"build", "-p", "1", "-mod=readonly", "-trimpath", "-ldflags", link, "-o", "/public-fixture/work/mac-keyvault", "./cmd/mac-keyvault"}
		if !reflect.DeepEqual(args, want) {
			t.Fatal("wrong role source/target/flags/pin")
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 39), strings.Repeat("a", 41), strings.Repeat("A", 40), "branch", strings.Repeat("a", 40) + " -X main.other=1", strings.Repeat("a", 39) + "\n"} {
		for _, pair := range [][2]string{{value, tree}, {head, value}} {
			_, err := qualificationGoArgs("/public-fixture/work/mac-keyvault", pair[0], pair[1], false)
			qualificationError(t, err)
		}
	}
	for _, pair := range [][2]string{{"arm64", "arm64"}, {"amd64", "x86_64"}} {
		got, err := qualificationSwiftTarget(pair[0])
		if err != nil || got != pair[1] {
			t.Fatal("supported macOS target refused")
		}
	}
	_, err := qualificationSwiftTarget("other")
	qualificationError(t, err)
	if qualificationIgnoredSources(nil) != nil {
		t.Fatal("actual empty ignored-source projection refused")
	}
	for _, raw := range [][]byte{[]byte("internal/public/shadow.go\x00"), []byte("cmd/public/Core.swift\x00"), []byte("third_party/public/extra.syso\x00"), []byte("internal/public/compiler.log\x00"), []byte("truncated"), []byte{0}} {
		qualificationError(t, qualificationIgnoredSources(raw))
	}
}

// Positive child environment plus poisoned ambient controls; no environment
// values are logged and no subprocess/toolchain is executed by this test.
func TestRootQualificationOfflineEnvironment(t *testing.T) {
	for _, key := range []string{"GOFLAGS", "GOOS", "GOARCH", "GOTOOLCHAIN", "GOWORK", "GOENV", "CGO_LDFLAGS", "GOROOT", "SWIFT_EXEC", "SDKROOT", nativebuild.InputVariable} {
		t.Setenv(key, "PUBLIC poisoned selector")
	}
	env := map[string]string{}
	for _, entry := range nativebuild.Environment("") {
		k, v, _ := strings.Cut(entry, "=")
		env[k] = v
	}
	for k, v := range map[string]string{"GOOS": "darwin", "GOARCH": runtime.GOARCH, "CGO_ENABLED": "1", "GOTOOLCHAIN": "local", "GOWORK": "off", "GOENV": "off", "GOPROXY": "off", "GOSUMDB": "off"} {
		if env[k] != v {
			t.Fatal("closed environment lost required value")
		}
	}
	for _, key := range []string{"GOFLAGS", "CGO_LDFLAGS", "GOROOT", "SWIFT_EXEC", "SDKROOT", nativebuild.InputVariable} {
		if _, ok := env[key]; ok {
			t.Fatal("ambient build authority inherited")
		}
	}
	if home, ok := os.LookupEnv("HOME"); ok && env["HOME"] != home {
		t.Fatal("real HOME replaced")
	}
	_, err := qualificationGoTool()
	qualificationError(t, err)
}

// Exercise real PATH lookup with inert public files, never execute them. This
// positive control must also pass when the test binary is built with -trimpath.
// Relative/current-directory lookup, missing/non-executable go and GOROOT
// replacement return the fixed refusal and no selected tool path.
// Disabling ErrDot only inside inert fixtures independently exercises the
// resolver's absolute-path guard; missing lookup must leave the directory empty.
func TestRootQualificationGoToolPath(t *testing.T) {
	for _, form := range []string{"absolute", "relative", "dot", "relative-no-errdot", "dot-no-errdot", "missing", "not-executable", "goroot"} {
		t.Run(form, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "bin")
			if err := os.Mkdir(bin, 0700); err != nil {
				t.Fatal(err)
			}
			tool := filepath.Join(bin, "go")
			marker := []byte("PUBLIC lookup fixture; never execute\n")
			mode := os.FileMode(0700)
			if form == "not-executable" {
				mode = 0600
			}
			if form != "missing" {
				if err := os.WriteFile(tool, marker, mode); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("GOROOT", "")
			t.Setenv("PATH", bin)
			switch form {
			case "relative", "relative-no-errdot":
				t.Chdir(dir)
				t.Setenv("PATH", "bin")
			case "dot", "dot-no-errdot":
				t.Chdir(bin)
				t.Setenv("PATH", ".")
			case "goroot":
				t.Setenv("GOROOT", "/PUBLIC/replacement")
			}
			if strings.HasSuffix(form, "-no-errdot") {
				t.Setenv("GODEBUG", "execerrdot=0")
			}
			got, err := qualificationGoTool()
			if form == "absolute" {
				if err != nil || got != tool {
					t.Fatal("absolute PATH go refused")
				}
				// The retained -trimpath lane must record false here; only a
				// boolean is logged, never a host/toolchain path.
				t.Logf("embedded GOROOT present: %t", runtime.GOROOT() != "")
			} else {
				qualificationError(t, err)
				if got != "" {
					t.Fatal("refusal returned a tool path")
				}
			}
			if form == "missing" {
				if _, err := os.Lstat(tool); !os.IsNotExist(err) {
					t.Fatal("lookup created the missing executable")
				}
				entries, err := os.ReadDir(bin)
				if err != nil || len(entries) != 0 {
					t.Fatal("missing lookup changed its empty directory")
				}
			} else {
				b, err := os.ReadFile(tool)
				st, statErr := os.Stat(tool)
				if err != nil || statErr != nil || !bytes.Equal(b, marker) || st.Mode().Perm() != mode {
					t.Fatal("lookup changed its inert fixture")
				}
			}
		})
	}
}

// A single context preserves an earlier parent deadline, never grants another
// 900s per phase. This is clock/context control only, not compiler termination.
func TestRootQualificationOriginalBudget(t *testing.T) {
	before := time.Now()
	ctx, cancel, err := qualificationContext(context.Background())
	if err != nil {
		t.Fatal("valid context refused")
	}
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || deadline.After(time.Now().Add(qualificationBudget)) || deadline.Before(before.Add(qualificationBudget)) {
		t.Fatal("wrong original cap")
	}
	early, stop := context.WithTimeout(context.Background(), time.Minute)
	defer stop()
	child, done, err := qualificationContext(early)
	if err != nil {
		t.Fatal("earlier deadline refused")
	}
	defer done()
	parentDeadline, _ := early.Deadline()
	actual, _ := child.Deadline()
	if !actual.Equal(parentDeadline) {
		t.Fatal("parent deadline extended")
	}
	stopped, halt := context.WithCancel(context.Background())
	halt()
	_, _, err = qualificationContext(stopped)
	qualificationError(t, err)
	_, _, err = qualificationContext(nil)
	qualificationError(t, err)
}

// The exact compatibility table admits root/above-home0755, actual-home0700
// and below-home0700/0755, with parent0700. Synthetic stat fields are NOT a
// qualification of this host's home/ACLs. No live home is read or changed.
func TestRootQualificationAncestorPolicy(t *testing.T) {
	home, parent := "/Users/public-home", "/Users/public-home/project/qualification"
	for _, entry := range []struct {
		path      string
		uid, mode uint32
	}{
		{"/", 0, 0755}, {"/Users", 0, 0755}, {home, 501, 0700}, {home + "/project", 501, 0755}, {home + "/project", 501, 0700}, {parent, 501, 0700},
	} {
		st := unix.Stat_t{Uid: entry.uid, Mode: unix.S_IFDIR | 0700}
		if entry.mode == 0755 {
			st.Mode = unix.S_IFDIR | 0755
		}
		if !qualificationDirectoryPolicy(entry.path, home, parent, st, 501) {
			t.Fatal("legitimate ancestor form refused")
		}
		for _, bad := range []unix.Stat_t{{Uid: entry.uid + 1, Mode: st.Mode}, {Uid: entry.uid, Mode: unix.S_IFDIR | 0777}, {Uid: entry.uid, Mode: unix.S_IFLNK | 0700}} {
			if qualificationDirectoryPolicy(entry.path, home, parent, bad, 501) {
				t.Fatal("forbidden owner/mode/type admitted")
			}
		}
	}
	if qualificationDirectoryPolicy(parent, home, parent, unix.Stat_t{Uid: 501, Mode: unix.S_IFDIR | 0755}, 501) {
		t.Fatal("nonprivate parent admitted")
	}
	for _, pair := range [][2]string{{"relative", "/public-fixture"}, {"/", "/public-fixture"}, {home, "/outside-home"}, {home, home + "/missing/../qualification"}} {
		q, err := openQualificationParent(pair[0], pair[1], 501)
		qualificationError(t, err)
		if q != nil {
			t.Fatal("invalid ancestry returned held authority")
		}
	}
}

func qualificationPublicWrite(t *testing.T, path string, b []byte, mode os.FileMode) {
	t.Helper()
	if os.WriteFile(path, b, mode) != nil {
		t.Fatal("PUBLIC fixture write")
	}
}
func qualificationFixture(t *testing.T) (string, *qualificationOutput) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("PUBLIC source root")
	}
	for name, body := range map[string]string{
		"go.mod": "module public.example/fixture\n\ngo 1.26.10\n", "go.sum": "", "Package.swift": "// PUBLIC package source\n",
		"cmd/mac-keyvault-namecoin-abi/module.modulemap": "module NamecoinArchiveABI [system] { header \"libkeyvault_namecoin.h\" export * }\n",
		"cmd/mac-keyvault-namecoin-archive/main.go":      "package main\n", "cmd/mac-keyvault-enclave/Core.swift": "// PUBLIC core source\n",
		"internal/keyvault/recoverydata/english.txt": "PUBLIC embedded source input\n", "third_party/fixture/source.go": "package fixture\n",
		"tools/recoverybuild/main.go": "package main\n",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if os.MkdirAll(filepath.Dir(p), 0700) != nil {
			t.Fatal("PUBLIC source dirs")
		}
		qualificationPublicWrite(t, p, []byte(body), 0600)
	}
	if os.Mkdir(filepath.Join(root, ".temp"), 0700) != nil {
		t.Fatal("PUBLIC existing stage parent")
	}
	parent, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal("PUBLIC qualification parent")
	}
	fd, err := unix.Open(parent, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal("PUBLIC parent open")
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		t.Fatal("PUBLIC parent stat")
	}
	// Isolated leaf fixture for real fd/file orchestration only. Production
	// openQualificationParent enforces the separate full ancestor policy above;
	// this fixture is NOT a whole-home admission or native success substitute.
	q := &qualificationOutput{uid: uint32(os.Getuid()), links: []qualificationDirectory{{fd: fd, parent: unix.AT_FDCWD, name: parent, path: parent, stat: st}}}
	t.Cleanup(func() {
		_ = q.close()
		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, e error) error {
			if e == nil && d.IsDir() {
				_ = os.Chmod(path, 0700)
			}
			return nil
		})
	})
	return root, q
}

type qualificationFake struct {
	t                          *testing.T
	root, fail, stage, scratch string
	calls                      []nativebuild.Command
	deadlines                  []time.Time
	owning, foreign, archives  int
}

func qualificationArg(args []string, key string) string {
	for i, s := range args {
		if s == key && i+1 < len(args) {
			return args[i+1]
		}
	}
	return ""
}
func (f *qualificationFake) run(ctx context.Context, c nativebuild.Command) ([]byte, error) {
	f.calls = append(f.calls, c)
	deadline, ok := ctx.Deadline()
	if !ok {
		f.t.Fatal("unbounded command context")
	}
	f.deadlines = append(f.deadlines, deadline)
	if ctx.Err() != nil {
		return nil, errQualificationBuild
	}
	if c.Program == "git" {
		if len(c.Args) < 2 || c.Args[0] != "--no-replace-objects" {
			f.t.Fatal("wrong source command")
		}
		switch c.Args[1] {
		case "status":
			if f.fail == "dirty" {
				return []byte(" M public.go\n"), nil
			}
			return nil, nil
		case "ls-files":
			if f.fail == "ignored-source" {
				return []byte("internal/public/shadow.go\x00"), nil
			}
			return nil, nil
		case "rev-parse":
			switch c.Args[2] {
			case "--show-toplevel":
				return []byte(f.root + "\n"), nil
			case "HEAD":
				if f.fail == "bad-head" {
					return []byte(strings.Repeat("A", 40) + "\n"), nil
				}
				if f.fail == "head-drift" && f.owning > 0 {
					return []byte(strings.Repeat("3", 40) + "\n"), nil
				}
				return []byte(strings.Repeat("1", 40) + "\n"), nil
			default:
				if strings.HasSuffix(c.Args[2], "^{tree}") && qualificationObject.MatchString(strings.TrimSuffix(c.Args[2], "^{tree}")) {
					if f.fail == "bad-tree" {
						return []byte("not-a-tree\n"), nil
					}
					return []byte(strings.Repeat("2", 40) + "\n"), nil
				}
			}
		case "verify-commit":
			if f.fail == "unsigned" {
				return nil, errQualificationBuild
			}
			return nil, nil
		}
		f.t.Fatal("unexpected git command")
	}
	if c.Program == "/public/go" {
		if reflect.DeepEqual(c.Args, []string{"version"}) {
			if f.fail == "go-version" {
				return []byte("go version go1.26.9 darwin/" + runtime.GOARCH + "\n"), nil
			}
			if f.fail == "go-platform" {
				return []byte("go version go1.26.10 linux/" + runtime.GOARCH + "\n"), nil
			}
			return []byte("go version go1.26.10 darwin/" + runtime.GOARCH + "\n"), nil
		}
		if len(c.Args) == 0 || c.Args[0] != "build" || qualificationArg(c.Args, "-p") != "1" {
			f.t.Fatal("wrong Go build command")
		}
		output := qualificationArg(c.Args, "-o")
		if strings.HasSuffix(output, "libkeyvault_namecoin.a") {
			f.archives++
			f.stage = filepath.Dir(output)
			qualificationPublicWrite(f.t, output, []byte("PUBLIC archive marker, not an archive"), 0600)
			if f.fail == "archive" {
				return nil, errQualificationBuild
			}
			qualificationPublicWrite(f.t, filepath.Join(f.stage, "libkeyvault_namecoin.h"), []byte("PUBLIC header marker, not declarations"), 0600)
			return nil, nil
		}
		if c.Args[len(c.Args)-1] != "./cmd/mac-keyvault" {
			f.t.Fatal("wrong Go sibling target")
		}
		foreign := strings.Contains(qualificationArg(c.Args, "-ldflags"), "main.recoveryQualificationOnly=1")
		body := "PUBLIC owning artifact marker, not executable"
		if foreign {
			f.foreign++
			body = "PUBLIC foreign artifact marker, not executable"
		} else {
			f.owning++
		}
		qualificationPublicWrite(f.t, output, []byte(body), 0700)
		if (!foreign && f.fail == "owning") || (foreign && f.fail == "foreign") {
			return nil, errQualificationBuild
		}
		if !foreign {
			switch f.fail {
			case "work-collision":
				foreignWork := filepath.Join(filepath.Dir(filepath.Dir(output)), "foreign", "mac-keyvault")
				qualificationPublicWrite(f.t, foreignWork, []byte("PUBLIC unrelated compiler-output sentinel"), 0600)
			case "source-drift":
				qualificationPublicWrite(f.t, filepath.Join(f.root, "Package.swift"), []byte("// changed PUBLIC source\n"), 0600)
			case "pair-drift":
				path := filepath.Join(f.stage, "libkeyvault_namecoin.h")
				if os.Chmod(path, 0600) != nil {
					f.t.Fatal("PUBLIC header mutation mode")
				}
				qualificationPublicWrite(f.t, path, []byte("changed PUBLIC header"), 0600)
				_ = os.Chmod(path, 0400)
			case "helper-drift":
				qualificationPublicWrite(f.t, filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(output))), "mac-keyvault-enclave"), []byte("changed PUBLIC helper"), 0700)
			case "receipt-drift":
				qualificationPublicWrite(f.t, filepath.Join(filepath.Dir(filepath.Dir(filepath.Dir(output))), "native-build-receipt.json"), []byte("changed PUBLIC receipt"), 0600)
			}
		}
		if foreign && f.fail == "receipt-collision" {
			artifacts := filepath.Dir(filepath.Dir(filepath.Dir(output)))
			qualificationPublicWrite(f.t, filepath.Join(artifacts, qualificationReceiptName), []byte("PUBLIC unrelated sentinel\n"), 0600)
		}
		return nil, nil
	}
	if c.Program == "/usr/bin/xcrun" {
		if reflect.DeepEqual(c.Args, []string{"swift", "--version"}) {
			target, err := qualificationSwiftTarget(runtime.GOARCH)
			if err != nil {
				f.t.Fatal("fixture host arch")
			}
			return []byte("Apple Swift version 6.0 (PUBLIC fixture)\nTarget: " + target + "-apple-macosx14.0\n"), nil
		}
		if len(c.Args) < 2 || c.Args[0] != "swift" || c.Args[1] != "build" || qualificationArg(c.Args, "--jobs") != "1" {
			f.t.Fatal("wrong actual Swift package/jobs selection")
		}
		f.scratch = qualificationArg(c.Args, "--scratch-path")
		bin := filepath.Join(f.scratch, "public-target", "release")
		if qualificationArg(c.Args, "--product") != "" {
			if qualificationArg(c.Args, "--product") != "mac-keyvault-enclave" {
				f.t.Fatal("wrong Swift product")
			}
			if f.fail == "swift" {
				return nil, errQualificationBuild
			}
			if os.MkdirAll(bin, 0700) != nil {
				f.t.Fatal("PUBLIC fake output dirs")
			}
			qualificationPublicWrite(f.t, filepath.Join(bin, "mac-keyvault-enclave"), []byte("PUBLIC helper marker, not executable"), 0700)
			return nil, nil
		}
		if c.Args[len(c.Args)-1] != "--show-bin-path" {
			f.t.Fatal("unexpected Swift command")
		}
		return []byte(bin + "\n"), nil
	}
	f.t.Fatal("forbidden sign/inspect/native/artifact/unknown command dispatched")
	return nil, errQualificationBuild
}
func qualificationRun(t *testing.T, root string, q *qualificationOutput, f *qualificationFake) (string, error) {
	t.Helper()
	ctx, cancel, err := qualificationContext(context.Background())
	if err != nil {
		t.Fatal("PUBLIC context")
	}
	defer cancel()
	return runQualificationBuild(ctx, root, "/public/go", q, f.run)
}

// Real disposable files/hashes/receipts plus a bounded command fake prove the
// intended one-generation orchestration only, NOT builds/signatures/native PASS.
func TestRootQualificationBuildPlanAndUnsignedReceipt(t *testing.T) {
	root, q := qualificationFixture(t)
	f := &qualificationFake{t: t, root: root}
	path, err := qualificationRun(t, root, q, f)
	if err != nil {
		t.Fatal("valid PUBLIC orchestration refused")
	}
	if f.archives != 1 || f.owning != 1 || f.foreign != 1 {
		t.Fatal("wrong generation/role count")
	}
	for _, deadline := range f.deadlines {
		if !deadline.Equal(f.deadlines[0]) {
			t.Fatal("phase renewed deadline")
		}
	}
	raw, err := os.ReadFile(path)
	if err != nil || len(raw) > 64<<10 {
		t.Fatal("bounded PUBLIC receipt missing")
	}
	var receipt qualificationBuildReceipt
	if json.Unmarshal(raw, &receipt) != nil || receipt.State != "unsigned-not-qualified" || len(receipt.Artifacts) != 3 || receipt.Created == "" {
		t.Fatal("wrong unsigned receipt")
	}
	if receipt.Head != strings.Repeat("1", 40) || receipt.Tree != strings.Repeat("2", 40) || receipt.SourceSHA256 != receipt.Native.Receipt.SourceSHA256 {
		t.Fatal("source receipt mismatch")
	}
	if bytes.Contains(bytes.ToLower(raw), []byte("cdhash")) || bytes.Contains(raw, []byte(`"leaf"`)) || bytes.Contains(raw, []byte(`"dr"`)) {
		t.Fatal("invented runtime signing fields")
	}
	out := filepath.Dir(path)
	for i, name := range []string{"mac-keyvault-enclave", "mac-keyvault", "qualification/mac-keyvault"} {
		p := filepath.Join(out, filepath.FromSlash(name))
		b, e := os.ReadFile(p)
		if e != nil || receipt.Artifacts[i].Path != name || receipt.Artifacts[i].SHA256 != qualificationSHA(b) || receipt.Artifacts[i].Bytes != len(b) {
			t.Fatal("actual public artifact hash mismatch")
		}
		st, e := os.Stat(p)
		if e != nil || st.Mode().Perm() != 0700 {
			t.Fatal("new artifact mode")
		}
	}
	nativeRaw, err := os.ReadFile(filepath.Join(out, "native-build-receipt.json"))
	if err != nil || receipt.NativeReceiptSHA256 != qualificationSHA(nativeRaw) {
		t.Fatal("native receipt binding missing")
	}
	if _, err = nativebuild.ValidateStage(root, receipt.Native.Directory, receipt.SourceSHA256); err != nil {
		t.Fatal("genuine stage validator rejected PUBLIC matching receipt")
	}
	for _, c := range f.calls {
		if c.Dir != root {
			t.Fatal("wrong source directory")
		}
		for _, e := range c.Env {
			if strings.HasPrefix(e, "GOFLAGS=") || strings.HasPrefix(e, "CGO_LDFLAGS=") {
				t.Fatal("ambient flags used")
			}
		}
	}
	before := append([]byte(nil), raw...)
	calls := len(f.calls)
	_, err = qualificationRun(t, root, q, f)
	qualificationError(t, err)
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) || len(f.calls) != calls {
		t.Fatal("existing artifacts reused/overwritten or commands retried")
	}
}

// Each closed fault preserves any public work already produced, returns no
// receipt path and never retries the native generation or later failed phase.
func TestRootQualificationFailuresRetainAndDoNotRetry(t *testing.T) {
	for _, fault := range []string{"dirty", "unsigned", "bad-head", "bad-tree", "ignored-source", "go-version", "go-platform", "archive", "swift", "owning", "foreign", "source-drift", "head-drift", "pair-drift", "helper-drift", "receipt-drift", "work-collision", "receipt-collision"} {
		t.Run(fault, func(t *testing.T) {
			root, q := qualificationFixture(t)
			f := &qualificationFake{t: t, root: root, fail: fault}
			path, err := qualificationRun(t, root, q, f)
			qualificationError(t, err)
			if path != "" || f.archives > 1 || f.owning > 1 || f.foreign > 1 {
				t.Fatal("failed build returned success/retried")
			}
			if f.stage != "" {
				if _, err = os.Stat(filepath.Join(f.stage, "libkeyvault_namecoin.a")); err != nil {
					t.Fatal("partial generation deleted")
				}
			}
			if fault == "dirty" || fault == "unsigned" || fault == "bad-head" || fault == "bad-tree" || fault == "ignored-source" {
				if f.archives != 0 {
					t.Fatal("source admission failure compiled")
				}
			}
			// A discovered executable with the wrong version/target must not reach
			// archive, Swift or role compilation, or publish a success receipt.
			if fault == "go-version" || fault == "go-platform" {
				if f.archives != 0 || f.scratch != "" || f.owning != 0 || f.foreign != 0 {
					t.Fatal("unqualified Go toolchain reached a build phase")
				}
			}
			if fault == "owning" || fault == "source-drift" || fault == "head-drift" || fault == "pair-drift" || fault == "helper-drift" || fault == "receipt-drift" || fault == "work-collision" {
				if f.foreign != 0 {
					t.Fatal("later role built after refusal")
				}
			}
			out := q.links[q.root].path
			raw, readErr := os.ReadFile(filepath.Join(out, qualificationReceiptName))
			if fault == "receipt-collision" {
				if readErr != nil || string(raw) != "PUBLIC unrelated sentinel\n" {
					t.Fatal("collided receipt changed")
				}
			} else if !os.IsNotExist(readErr) {
				t.Fatal("failure published receipt")
			}
			if _, err = os.Stat(filepath.Join(out, "build.log")); err != nil {
				t.Fatal("failure evidence not retained")
			}
		})
	}
}

// Exclusive files/dirs and real symlink/hardlink/replacement controls are PUBLIC
// filesystem evidence only, not whole-home or hostile same-UID race proof.
func TestRootQualificationNoOverwriteOrPathRepair(t *testing.T) {
	_, q := qualificationFixture(t)
	root, err := q.mkdir(0, "artifacts")
	if err != nil {
		t.Fatal("valid new dir refused")
	}
	q.root = root
	b := []byte("PUBLIC retained sentinel\n")
	if q.write(root, "receipt.json", b, false) != nil {
		t.Fatal("valid exclusive file refused")
	}
	beforeInfo, err := os.Lstat(filepath.Join(q.links[root].path, "receipt.json"))
	if err != nil {
		t.Fatal("PUBLIC initial inode")
	}
	qualificationError(t, q.write(root, "receipt.json", []byte("replacement"), false))
	afterInfo, err := os.Lstat(filepath.Join(q.links[root].path, "receipt.json"))
	if err != nil || !os.SameFile(beforeInfo, afterInfo) || afterInfo.Mode().Perm() != 0600 {
		t.Fatal("collided inode/mode changed")
	}
	got, err := q.read(root, "receipt.json", 1024)
	if err != nil || !bytes.Equal(got, b) {
		t.Fatal("collided file changed")
	}
	dir := q.links[root].path
	if os.Chmod(filepath.Join(dir, "receipt.json"), 0644) != nil {
		t.Fatal("PUBLIC mode fixture")
	}
	_, err = q.read(root, "receipt.json", 1024)
	qualificationError(t, err)
	if os.Chmod(filepath.Join(dir, "receipt.json"), 0600) != nil {
		t.Fatal("PUBLIC mode fixture restore")
	}
	if os.Symlink(filepath.Join(dir, "receipt.json"), filepath.Join(dir, "alias")) != nil {
		t.Fatal("PUBLIC symlink fixture")
	}
	qualificationError(t, q.write(root, "alias", b, false))
	_, err = q.read(root, "alias", 1024)
	qualificationError(t, err)
	if os.Link(filepath.Join(dir, "receipt.json"), filepath.Join(dir, "link")) != nil {
		t.Fatal("PUBLIC hardlink fixture")
	}
	_, err = q.read(root, "receipt.json", 1024)
	qualificationError(t, err)
	_, err = q.mkdir(0, "artifacts")
	qualificationError(t, err)
	if os.Rename(dir, dir+"-retained") != nil || os.Mkdir(dir, 0700) != nil {
		t.Fatal("PUBLIC replacement fixture")
	}
	qualificationError(t, q.check())
}

// Repeated new parents produce distinct retained real stage generations in this
// public command model. This does NOT admit a second real build/window/retry.
func TestRootQualificationFreshGenerationsAreRetained(t *testing.T) {
	root, first := qualificationFixture(t)
	f := &qualificationFake{t: t, root: root}
	path, err := qualificationRun(t, root, first, f)
	if err != nil {
		t.Fatal("first control refused")
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("first receipt")
	}
	_, second := qualificationFixture(t)
	g := &qualificationFake{t: t, root: root}
	next, err := qualificationRun(t, root, second, g)
	if err != nil {
		t.Fatal("second independent control refused")
	}
	raw, err := os.ReadFile(next)
	if err != nil {
		t.Fatal("second receipt")
	}
	var a, b qualificationBuildReceipt
	if json.Unmarshal(before, &a) != nil || json.Unmarshal(raw, &b) != nil || a.Native.Directory == b.Native.Directory {
		t.Fatal("generation reused")
	}
	current, _ := os.ReadFile(path)
	if !bytes.Equal(before, current) {
		t.Fatal("prior evidence changed")
	}
	if _, err = nativebuild.ValidateStage(root, a.Native.Directory, a.SourceSHA256); err != nil {
		t.Fatal("prior pair no longer matches")
	}
}

// Closed preflight never dispatches or creates output. The valid bounded case
// is exercised by BuildPlanAndUnsignedReceipt; this test does not run tools.
func TestRootQualificationPreflightBeforeOutput(t *testing.T) {
	root, q := qualificationFixture(t)
	valid, cancel, err := qualificationContext(context.Background())
	if err != nil {
		t.Fatal("valid bounded context refused")
	}
	defer cancel()
	stopped, stop := context.WithCancel(valid)
	stop()
	tooLong, done := context.WithTimeout(context.Background(), 2*qualificationBudget)
	defer done()
	calls := 0
	run := func(context.Context, nativebuild.Command) ([]byte, error) { calls++; return nil, errQualificationBuild }
	for _, test := range []struct {
		ctx        context.Context
		root, tool string
		output     *qualificationOutput
	}{
		{nil, root, "/public/go", q},
		{context.Background(), root, "/public/go", q},
		{stopped, root, "/public/go", q},
		{tooLong, root, "/public/go", q},
		{valid, "relative-source", "/public/go", q},
		{valid, root, "relative-tool", q},
		{valid, root, "/public/go", nil},
	} {
		path, err := runQualificationBuild(test.ctx, test.root, test.tool, test.output, run)
		qualificationError(t, err)
		if path != "" || calls != 0 || q.started {
			t.Fatal("invalid preflight dispatched/consumed attempt")
		}
	}
	if _, err := os.Lstat(filepath.Join(q.links[0].path, "artifacts")); !os.IsNotExist(err) {
		t.Fatal("preflight changed output")
	}
}
