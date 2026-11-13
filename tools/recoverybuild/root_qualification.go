package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/nativebuild"
	"golang.org/x/sys/unix"
)

var errQualificationBuild = errors.New("unsigned qualification build refused; retained work is not qualified")
var qualificationObject = regexp.MustCompile(`^[0-9a-f]{40}$`)

const qualificationBudget = 900 * time.Second
const qualificationReceiptName = "root-qualification-build.json"
const qualificationHelperPin = "github.com/relux-works/swarma-keyvault/internal/keyvault.recoveryHelperCDHash="

// Presence of another mode flag is refused even when its value is empty/false.
// Existing default release/seed/native-only flag and signing behavior is unchanged.
func validateRootQualificationFlags(out string, selected []string) error {
	if !filepath.IsAbs(out) || filepath.Clean(out) != out || filepath.Base(out) != "artifacts" {
		return errQualificationBuild
	}
	seen := map[string]bool{}
	for _, name := range selected {
		if (name != "out" && name != "root-storage-qualification-only") || seen[name] {
			return errQualificationBuild
		}
		seen[name] = true
	}
	if !seen["out"] || !seen["root-storage-qualification-only"] {
		return errQualificationBuild
	}
	return nil
}

func qualificationSwiftTarget(arch string) (string, error) {
	switch arch {
	case "arm64":
		return "arm64", nil
	case "amd64":
		return "x86_64", nil
	default:
		return "", errQualificationBuild
	}
}

func qualificationGoTool() (string, error) {
	// An explicit GOROOT remains forbidden. A -trimpath build omits the runtime's
	// embedded GOROOT, so select go through the admitted toolchain PATH instead.
	if value, present := os.LookupEnv("GOROOT"); present && value != "" {
		return "", errQualificationBuild
	}
	tool, err := exec.LookPath("go")
	if err != nil || !filepath.IsAbs(tool) || filepath.Clean(tool) != tool || filepath.Base(tool) != "go" {
		return "", errQualificationBuild
	}
	// runQualificationBuild checks the exact Go version/target before compilation;
	// finding an executable is not toolchain or custody qualification.
	return tool, nil
}

func qualificationContext(parent context.Context) (context.Context, context.CancelFunc, error) {
	if parent == nil || parent.Err() != nil {
		return nil, nil, errQualificationBuild
	}
	ctx, cancel := context.WithTimeout(parent, qualificationBudget)
	return ctx, cancel, nil // An earlier caller deadline always wins; never renewed.
}

func qualificationLink(head, tree string, foreign bool) (string, error) {
	if !qualificationObject.MatchString(head) || !qualificationObject.MatchString(tree) {
		return "", errQualificationBuild
	}
	// The unsigned helper's current hash is NOT a future signed CDHash. These
	// binaries intentionally have no private recovery helper admission pin.
	link := "-X " + qualificationHelperPin + " -X main.rootQualificationSourceHead=" + head +
		" -X main.rootQualificationSourceTree=" + tree
	if foreign {
		link += " -X main.recoveryQualificationOnly=1"
	}
	return link, nil
}

func qualificationGoArgs(goOutput, head, tree string, foreign bool) ([]string, error) {
	link, err := qualificationLink(head, tree, foreign)
	if err != nil || !filepath.IsAbs(goOutput) || filepath.Clean(goOutput) != goOutput {
		return nil, errQualificationBuild
	}
	return []string{"build", "-p", "1", "-mod=readonly", "-trimpath", "-ldflags", link,
		"-o", goOutput, "./cmd/mac-keyvault"}, nil
}

type qualificationDirectory struct {
	fd, parent int
	name, path string
	stat       unix.Stat_t
}
type qualificationOutput struct {
	uid                                 uint32
	links                               []qualificationDirectory
	root, foreign, ownWork, foreignWork int
	parent                              int
	started, closed                     bool
}

func qualificationSame(a, b unix.Stat_t) bool {
	return a.Dev == b.Dev && a.Ino == b.Ino && a.Mode == b.Mode && a.Uid == b.Uid && a.Gid == b.Gid
}
func qualificationDirectoryPolicy(path, home, parent string, st unix.Stat_t, uid uint32) bool {
	if st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return false
	}
	switch {
	case path == home || path == parent:
		return st.Uid == uid && uint32(st.Mode)&07777 == 0700
	case path == "/" || strings.HasPrefix(home, path+"/"):
		return st.Uid == 0 && uint32(st.Mode)&07777 == 0755
	case strings.HasPrefix(path, home+"/"):
		return st.Uid == uid && (uint32(st.Mode)&07777 == 0700 || uint32(st.Mode)&07777 == 0755)
	}
	return false
}

// The qualification parent already exists. Walk/hold every ancestor under the
// OS-account home policy; no HOME authority, symlink, mkdir ancestor or repair.
// Mode checks do not inspect extended filesystem ACLs or defeat a hostile UID.
func openQualificationParent(home, parent string, uid uint32) (q *qualificationOutput, err error) {
	if !filepath.IsAbs(home) || filepath.Clean(home) != home || home == "/" ||
		!filepath.IsAbs(parent) || filepath.Clean(parent) != parent || !strings.HasPrefix(parent, home+"/") {
		return nil, errQualificationBuild
	}
	q = &qualificationOutput{uid: uid}
	held := q
	defer func() {
		if err != nil {
			_ = held.close()
		}
	}()
	fd, e := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if e != nil {
		return nil, errQualificationBuild
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil {
		_ = unix.Close(fd)
		return nil, errQualificationBuild
	}
	q.links = append(q.links, qualificationDirectory{fd: fd, parent: unix.AT_FDCWD, name: "/", path: "/", stat: st})
	if !qualificationDirectoryPolicy("/", home, parent, st, uid) {
		return nil, errQualificationBuild
	}
	path := ""
	for _, name := range strings.Split(strings.TrimPrefix(parent, "/"), "/") {
		previous := q.links[len(q.links)-1].fd
		path += "/" + name
		fd, e = unix.Openat(previous, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if e != nil {
			return nil, errQualificationBuild
		}
		if unix.Fstat(fd, &st) != nil {
			_ = unix.Close(fd)
			return nil, errQualificationBuild
		}
		q.links = append(q.links, qualificationDirectory{fd: fd, parent: previous, name: name, path: path, stat: st})
		if !qualificationDirectoryPolicy(path, home, parent, st, uid) {
			return nil, errQualificationBuild
		}
	}
	if q.check() != nil {
		return nil, errQualificationBuild
	}
	q.parent = len(q.links) - 1
	return q, nil
}
func (q *qualificationOutput) check() error {
	if q == nil || q.closed || len(q.links) == 0 {
		return errQualificationBuild
	}
	for _, l := range q.links {
		var held, named unix.Stat_t
		if unix.Fstat(l.fd, &held) != nil || unix.Fstatat(l.parent, l.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil ||
			!qualificationSame(l.stat, held) || !qualificationSame(held, named) {
			return errQualificationBuild
		}
	}
	return nil
}
func (q *qualificationOutput) close() error {
	if q == nil || q.closed {
		return nil
	}
	q.closed = true
	var err error
	for i := len(q.links) - 1; i >= 0; i-- {
		if unix.Close(q.links[i].fd) != nil {
			err = errQualificationBuild
		}
	}
	return err // Close once; retain everything and never retry a failed close.
}
func (q *qualificationOutput) mkdir(parent int, name string) (int, error) {
	if q.check() != nil || parent < 0 || parent >= len(q.links) || name == "" || name == "." || name == ".." || strings.ContainsAny(name, "/\\") {
		return 0, errQualificationBuild
	}
	p := q.links[parent]
	if unix.Mkdirat(p.fd, name, 0700) != nil {
		return 0, errQualificationBuild
	}
	fd, err := unix.Openat(p.fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, errQualificationBuild
	}
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFDIR || st.Uid != q.uid || uint32(st.Mode)&07777 != 0700 {
		_ = unix.Close(fd)
		return 0, errQualificationBuild
	}
	q.links = append(q.links, qualificationDirectory{fd: fd, parent: p.fd, name: name, path: filepath.Join(p.path, name), stat: st})
	if q.check() != nil || unix.Fsync(p.fd) != nil {
		return 0, errQualificationBuild
	}
	return len(q.links) - 1, nil
}
func (q *qualificationOutput) create(name string) (*os.File, error) {
	if q.check() != nil || filepath.Base(name) != name || name == "." || name == ".." {
		return nil, errQualificationBuild
	}
	fd, err := unix.Openat(q.links[q.root].fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return nil, errQualificationBuild
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG || st.Uid != q.uid || uint32(st.Mode)&07777 != 0600 || st.Nlink != 1 {
		_ = f.Close()
		return nil, errQualificationBuild
	}
	return f, nil
}
func (q *qualificationOutput) read(dir int, name string, limit int64, modes ...uint32) ([]byte, error) {
	if q.check() != nil || dir < 0 || dir >= len(q.links) || filepath.Base(name) != name {
		return nil, errQualificationBuild
	}
	d := q.links[dir]
	fd, err := unix.Openat(d.fd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, errQualificationBuild
	}
	f := os.NewFile(uintptr(fd), name)
	var before, after, named unix.Stat_t
	if len(modes) == 0 {
		modes = []uint32{0600}
	}
	statErr := unix.Fstat(fd, &before)
	admittedMode := false
	for _, mode := range modes {
		if uint32(before.Mode)&07777 == mode {
			admittedMode = true
		}
	}
	if statErr != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Uid != q.uid || before.Nlink != 1 ||
		before.Size < 1 || before.Size > limit || !admittedMode {
		_ = f.Close()
		return nil, errQualificationBuild
	}
	b, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	statErr = unix.Fstat(fd, &after)
	nameErr := unix.Fstatat(d.fd, name, &named, unix.AT_SYMLINK_NOFOLLOW)
	closeErr := f.Close()
	if readErr != nil || statErr != nil || nameErr != nil || closeErr != nil || int64(len(b)) != before.Size || after.Size != before.Size ||
		!qualificationSame(before, after) || !qualificationSame(after, named) || q.check() != nil {
		return nil, errQualificationBuild
	}
	return b, nil
}
func qualificationSHA(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func (q *qualificationOutput) write(dir int, name string, b []byte, executable bool) error {
	if q.check() != nil || dir < 0 || dir >= len(q.links) || filepath.Base(name) != name || len(b) == 0 {
		return errQualificationBuild
	}
	d := q.links[dir]
	fd, err := unix.Openat(d.fd, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return errQualificationBuild
	}
	f := os.NewFile(uintptr(fd), name)
	var st unix.Stat_t
	valid := unix.Fstat(fd, &st) == nil && st.Mode&unix.S_IFMT == unix.S_IFREG && st.Uid == q.uid && uint32(st.Mode)&07777 == 0600 && st.Nlink == 1
	if !valid {
		_ = f.Close()
		return errQualificationBuild
	}
	count, writeErr := f.Write(b)
	var modeErr error
	if executable {
		modeErr = unix.Fchmod(fd, 0700)
	} // Only this newly owned descriptor.
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || count != len(b) || modeErr != nil || syncErr != nil || closeErr != nil || unix.Fsync(d.fd) != nil {
		return errQualificationBuild
	}
	mode := uint32(0600)
	if executable {
		mode = 0700
	}
	actual, err := q.read(dir, name, int64(len(b)), mode)
	if err != nil || !bytes.Equal(actual, b) {
		return errQualificationBuild
	}
	return nil
}

// Public unsigned artifacts only. No CDHash/DR/certificate fields are invented;
// signing changes these hashes and requires independent later signed readback.
type qualificationBuildArtifact struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type qualificationBuildReceipt struct {
	Schema              string                       `json:"schema"`
	State               string                       `json:"state"`
	Created             string                       `json:"created"`
	Head                string                       `json:"source_head"`
	Tree                string                       `json:"source_tree"`
	Go                  string                       `json:"go_version"`
	Swift               string                       `json:"swift_version"`
	SourceSHA256        string                       `json:"native_source_sha256"`
	NativeReceiptSHA256 string                       `json:"native_build_receipt_sha256"`
	Native              nativebuild.Result           `json:"native_build"`
	Artifacts           []qualificationBuildArtifact `json:"unsigned_artifacts"`
	Signing             string                       `json:"signing"`
}
type qualificationLog struct {
	output    io.Writer
	remaining int
}

func (l *qualificationLog) Write(b []byte) (int, error) {
	count := len(b)
	part := b
	if len(part) > l.remaining {
		part = part[:l.remaining]
	}
	if len(part) > 0 {
		n, err := l.output.Write(part)
		l.remaining -= n
		if err != nil {
			return n, err
		}
		if n != len(part) {
			return n, io.ErrShortWrite
		}
	}
	return count, nil // Bounded retained compiler diagnostics, never stdout.
}
func qualificationExecutor(log io.Writer) nativebuild.Executor {
	return func(ctx context.Context, c nativebuild.Command) ([]byte, error) {
		command := exec.CommandContext(ctx, c.Program, c.Args...)
		command.Dir = c.Dir
		command.Env = c.Env
		b, err := command.CombinedOutput()
		fmt.Fprintf(log, "command=%s %q exit_error=%v\n", c.Program, c.Args, err)
		_, _ = log.Write(b)
		return b, err
	}
}
func qualificationLine(b []byte) (string, error) {
	if len(b) == 0 || len(b) > 4096 || !utf8.Valid(b) || bytes.IndexByte(b, 0) >= 0 {
		return "", errQualificationBuild
	}
	s := strings.TrimSuffix(string(b), "\n")
	if strings.ContainsAny(s, "\r\n") || s == "" {
		return "", errQualificationBuild
	}
	return s, nil
}

// Git status alone ignores shadow inputs. The admitted source-tree form has
// no ignored entries; genuine generated archive/Swift work lives at root .temp,
// outside this query. Unknown ignored source-tree files refuse without cleanup.
func qualificationIgnoredSources(raw []byte) error {
	if len(raw) != 0 {
		return errQualificationBuild
	}
	return nil
}

func qualificationSource(ctx context.Context, root string, run nativebuild.Executor) (string, string, error) {
	invoke := func(args ...string) ([]byte, error) {
		if ctx == nil || ctx.Err() != nil || run == nil {
			return nil, errQualificationBuild
		}
		return run(ctx, nativebuild.Command{Program: "git", Args: append([]string{"--no-replace-objects"}, args...), Dir: root, Env: nativebuild.Environment("")})
	}
	b, err := invoke("status", "--porcelain=v1", "--untracked-files=all")
	if err != nil || len(b) != 0 {
		return "", "", errQualificationBuild
	}
	b, err = invoke("ls-files", "--others", "--ignored", "--exclude-standard", "-z", "--", "cmd", "internal", "third_party", "tools", "Package.swift", "go.mod", "go.sum")
	if err != nil || qualificationIgnoredSources(b) != nil {
		return "", "", errQualificationBuild
	}
	b, err = invoke("rev-parse", "--show-toplevel")
	if err != nil {
		return "", "", errQualificationBuild
	}
	top, err := qualificationLine(b)
	if err != nil || top != root {
		return "", "", errQualificationBuild
	}
	b, err = invoke("rev-parse", "HEAD")
	if err != nil {
		return "", "", errQualificationBuild
	}
	head, err := qualificationLine(b)
	if err != nil || !qualificationObject.MatchString(head) {
		return "", "", errQualificationBuild
	}
	b, err = invoke("rev-parse", head+"^{tree}")
	if err != nil {
		return "", "", errQualificationBuild
	}
	tree, err := qualificationLine(b)
	if err != nil || !qualificationObject.MatchString(tree) {
		return "", "", errQualificationBuild
	}
	if _, err = invoke("verify-commit", "--raw", head); err != nil {
		return "", "", errQualificationBuild
	}
	return head, tree, nil // Git verification is not independent review/admission.
}

// The caller has already held/checked the qualified ancestor chain. Kept
// separate for disposable filesystem and fake-executor orchestration controls;
// no fake proves an actual compiler, signed source or native runtime.
func runQualificationBuild(ctx context.Context, root, goTool string, q *qualificationOutput, run nativebuild.Executor) (string, error) {
	if ctx == nil || ctx.Err() != nil || q.check() != nil || q.started || !filepath.IsAbs(root) || filepath.Clean(root) != root ||
		!filepath.IsAbs(goTool) || filepath.Clean(goTool) != goTool {
		return "", errQualificationBuild
	}
	deadline, bounded := ctx.Deadline()
	if !bounded || time.Until(deadline) > qualificationBudget {
		return "", errQualificationBuild
	}
	q.started = true // One attempt on this held parent, including failures.
	rootIndex, err := q.mkdir(q.parent, "artifacts")
	if err != nil {
		return "", errQualificationBuild
	}
	q.root = rootIndex
	logFile, err := q.create("build.log")
	if err != nil {
		return "", errQualificationBuild
	}
	log := &qualificationLog{output: logFile, remaining: 16 << 20}
	logClosed := false
	defer func() {
		if !logClosed {
			logClosed = true
			_ = logFile.Close()
		}
	}()
	if run == nil {
		run = qualificationExecutor(log)
	}
	invoke := func(program string, args ...string) ([]byte, error) {
		if ctx.Err() != nil || q.check() != nil {
			return nil, errQualificationBuild
		}
		return run(ctx, nativebuild.Command{Program: program, Args: args, Dir: root, Env: nativebuild.Environment("")})
	}
	head, tree, err := qualificationSource(ctx, root, run)
	if err != nil {
		return "", errQualificationBuild
	}
	source, err := nativebuild.SourceDigest(root)
	if err != nil {
		return "", errQualificationBuild
	}
	// The actual source's declared target/toolchain is checked, not ambient GOOS.
	mod, err := os.ReadFile(filepath.Join(root, "go.mod"))
	if err != nil || !bytes.Contains(mod, []byte("\ngo 1.26.10\n")) {
		return "", errQualificationBuild
	}
	goRaw, err := invoke(goTool, "version")
	if err != nil {
		return "", errQualificationBuild
	}
	goVersion, err := qualificationLine(goRaw)
	if err != nil || goVersion != "go version go1.26.10 darwin/"+runtime.GOARCH {
		return "", errQualificationBuild
	}
	swiftRaw, err := invoke("/usr/bin/xcrun", "swift", "--version")
	if err != nil || len(swiftRaw) == 0 || len(swiftRaw) > 4096 || !utf8.Valid(swiftRaw) || bytes.IndexByte(swiftRaw, 0) >= 0 {
		return "", errQualificationBuild
	}
	swift := strings.TrimSpace(string(swiftRaw))
	target, e := qualificationSwiftTarget(runtime.GOARCH)
	if e != nil || !strings.Contains(swift, "Swift version ") || !strings.Contains(swift, "Target: "+target+"-apple-macosx") {
		return "", errQualificationBuild
	}
	// Require the pre-existing source staging parent; Build may create only its
	// fresh generation/scratch children here, never repair/create our ancestors.
	staging, err := os.Lstat(filepath.Join(root, ".temp"))
	if err != nil || !staging.IsDir() || staging.Mode()&os.ModeSymlink != 0 {
		return "", errQualificationBuild
	}
	native, err := nativebuild.Build(ctx, nativebuild.Options{Root: root, GoTool: goTool, Log: log, Execute: run})
	if err != nil {
		return "", errQualificationBuild
	}
	if native.Receipt.SourceSHA256 != source {
		return "", errQualificationBuild
	}
	recheck := func() error {
		if ctx.Err() != nil || q.check() != nil {
			return errQualificationBuild
		}
		after, e := nativebuild.SourceDigest(root)
		if e != nil || after != source {
			return errQualificationBuild
		}
		h, t, e := qualificationSource(ctx, root, run)
		if e != nil || h != head || t != tree {
			return errQualificationBuild
		}
		pair, e := nativebuild.ValidateStage(root, native.Directory, source)
		if e != nil || pair != native.Receipt {
			return errQualificationBuild
		}
		return nil
	}
	if recheck() != nil {
		return "", errQualificationBuild
	}
	out := q.links[q.root].path
	if nativebuild.CopyHelper(native, filepath.Join(out, "mac-keyvault-enclave")) != nil || recheck() != nil {
		return "", errQualificationBuild
	}
	if nativebuild.WriteReceipt(native, filepath.Join(out, "native-build-receipt.json")) != nil {
		return "", errQualificationBuild
	}
	expectedReceipt, _ := json.MarshalIndent(native, "", "  ")
	expectedReceipt = append(expectedReceipt, '\n')
	artifacts := []qualificationBuildArtifact{}
	record := func(index int, name, relative string) error {
		raw, e := q.read(index, name, 128<<20, 0700)
		if e != nil {
			return errQualificationBuild
		}
		artifacts = append(artifacts, qualificationBuildArtifact{Path: relative, SHA256: qualificationSHA(raw), Bytes: len(raw)})
		return nil
	}
	if record(q.root, "mac-keyvault-enclave", "mac-keyvault-enclave") != nil || artifacts[0].SHA256 != native.HelperSHA256 {
		return "", errQualificationBuild
	}
	checkOutputs := func() error {
		if recheck() != nil {
			return errQualificationBuild
		}
		receipt, e := q.read(q.root, "native-build-receipt.json", 64<<10)
		if e != nil || !bytes.Equal(receipt, expectedReceipt) {
			return errQualificationBuild
		}
		for _, a := range artifacts {
			index, name := q.root, a.Path
			if a.Path == "qualification/mac-keyvault" {
				index, name = q.foreign, "mac-keyvault"
			}
			b, e := q.read(index, name, 128<<20, 0700)
			if e != nil || qualificationSHA(b) != a.SHA256 || len(b) != a.Bytes {
				return errQualificationBuild
			}
		}
		return nil
	}
	if checkOutputs() != nil {
		return "", errQualificationBuild
	}
	q.foreign, err = q.mkdir(q.root, "qualification")
	if err != nil {
		return "", errQualificationBuild
	}
	work, err := q.mkdir(q.root, "build-work")
	if err != nil {
		return "", errQualificationBuild
	}
	q.ownWork, err = q.mkdir(work, "owning")
	if err != nil {
		return "", errQualificationBuild
	}
	q.foreignWork, err = q.mkdir(work, "foreign")
	if err != nil {
		return "", errQualificationBuild
	}
	for _, role := range []struct {
		foreign           bool
		work, destination int
		relative          string
	}{
		{false, q.ownWork, q.root, "mac-keyvault"}, {true, q.foreignWork, q.foreign, "qualification/mac-keyvault"},
	} {
		if checkOutputs() != nil {
			return "", errQualificationBuild
		}
		args, e := qualificationGoArgs(filepath.Join(q.links[role.work].path, "mac-keyvault"), head, tree, role.foreign)
		if e != nil {
			return "", errQualificationBuild
		}
		var existing unix.Stat_t
		if e = unix.Fstatat(q.links[role.work].fd, "mac-keyvault", &existing, unix.AT_SYMLINK_NOFOLLOW); !errors.Is(e, unix.ENOENT) {
			return "", errQualificationBuild // Never ask the compiler to overwrite a collision.
		}
		if _, e = invoke(goTool, args...); e != nil {
			return "", errQualificationBuild
		}
		if checkOutputs() != nil {
			return "", errQualificationBuild
		}
		b, e := q.read(role.work, "mac-keyvault", 128<<20, 0700, 0755)
		if e != nil || q.write(role.destination, "mac-keyvault", b, true) != nil || record(role.destination, "mac-keyvault", role.relative) != nil {
			return "", errQualificationBuild
		}
		if checkOutputs() != nil {
			return "", errQualificationBuild
		}
	}
	receiptBytes, err := q.read(q.root, "native-build-receipt.json", 64<<10)
	if err != nil {
		return "", errQualificationBuild
	}
	receipt := qualificationBuildReceipt{Schema: "keyvault-root-qualification-build/1", State: "unsigned-not-qualified", Created: time.Now().UTC().Format(time.RFC3339Nano), Head: head, Tree: tree,
		Go: goVersion, Swift: swift, SourceSHA256: source, NativeReceiptSHA256: qualificationSHA(receiptBytes), Native: native, Artifacts: artifacts,
		Signing: "No owner signing or runtime identity qualification performed; compiler/linker implicit platform signatures are not owner signing. Pre-sign hashes change on later signing."}
	b, err := json.MarshalIndent(receipt, "", "  ")
	b = append(b, '\n')
	if err != nil || len(b) > 64<<10 || checkOutputs() != nil || q.write(q.root, qualificationReceiptName, b, false) != nil {
		return "", errQualificationBuild
	}
	if checkOutputs() != nil || logFile.Sync() != nil {
		return "", errQualificationBuild
	}
	logClosed = true
	if logFile.Close() != nil {
		return "", errQualificationBuild
	}
	if ctx.Err() != nil || q.check() != nil {
		return "", errQualificationBuild
	}
	return filepath.Join(out, qualificationReceiptName), nil
}

func buildRootQualification(parent context.Context, out string) (err error) {
	if runtime.GOOS != "darwin" || runtime.Version() != "go1.26.10" || os.Getuid() != os.Geteuid() ||
		validateRootQualificationFlags(out, []string{"out", "root-storage-qualification-only"}) != nil {
		return errQualificationBuild
	}
	ctx, cancel, err := qualificationContext(parent)
	if err != nil {
		return errQualificationBuild
	}
	defer cancel()
	root, err := os.Getwd()
	if err != nil {
		return errQualificationBuild
	}
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return errQualificationBuild
	}
	q, err := openQualificationParent(account.HomeDir, filepath.Dir(out), uint32(os.Getuid()))
	if err != nil {
		return errQualificationBuild
	}
	defer func() {
		if q.close() != nil {
			err = errQualificationBuild
		}
	}()
	goTool, err := qualificationGoTool()
	if err != nil {
		return errQualificationBuild
	}
	receipt, err := runQualificationBuild(ctx, root, goTool, q, nil)
	if err != nil {
		return errQualificationBuild
	}
	if q.close() != nil {
		return errQualificationBuild
	}
	if ctx.Err() != nil {
		return errQualificationBuild
	}
	if _, err := fmt.Fprintln(os.Stdout, receipt); err != nil {
		return errQualificationBuild
	}
	return nil // Sole receipt-path output; no unsigned identity fiction.
}
