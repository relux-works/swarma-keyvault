// Package nativebuild builds the actual native package from one retained Go
// archive/header generation. It never signs, installs, runs or removes artifacts.
package nativebuild

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"syscall"
)

const InputVariable = "KEYVAULT_NATIVE_ARCHIVE_DIR"
const archiveName = "libkeyvault_namecoin.a"
const headerName = "libkeyvault_namecoin.h"
const receiptName = "archive-receipt.json"
const moduleName = "module.modulemap"

var inputPattern = regexp.MustCompile(`^\.temp/(native-archive-[a-f0-9]{32}|namecoin-native-archive)$`)
var digestPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var ErrBuild = errors.New("native package build refused")

// Command is public build input, never an account/owner authorization channel.
// Executor is an orchestration seam; a fake cannot prove Go/Swift compilation.
type Command struct {
	Program string
	Args    []string
	Dir     string
	Env     []string
}
type Executor func(context.Context, Command) ([]byte, error)
type Options struct {
	Root, GoTool string
	Log          io.Writer
	Execute      Executor
}
type Receipt struct {
	Schema        string `json:"schema"`
	Directory     string `json:"directory"`
	SourceSHA256  string `json:"source_sha256"`
	ArchiveSHA256 string `json:"archive_sha256"`
	HeaderSHA256  string `json:"header_sha256"`
	ModuleSHA256  string `json:"module_sha256"`
}
type Result struct {
	Helper, HelperSHA256, Directory, Scratch string
	Receipt                                  Receipt
}

func Environment(input string) []string {
	var env []string
	// Positive allowlist: do not inherit Go/cgo/linker flags, persisted Go config,
	// alternate Swift executables, package selectors or arbitrary build options.
	for _, key := range []string{"PATH", "HOME", "TMPDIR", "LANG", "LC_ALL"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	env = append(env, "GOOS=darwin", "GOARCH="+runtime.GOARCH, "CGO_ENABLED=1", "GOTOOLCHAIN=local", "GOWORK=off", "GOENV=off", "GOPROXY=off", "GOSUMDB=off")
	if input != "" {
		env = append(env, InputVariable+"="+input)
	}
	return env
}

func realExecutor(log io.Writer) Executor {
	return func(ctx context.Context, c Command) ([]byte, error) {
		cmd := exec.CommandContext(ctx, c.Program, c.Args...)
		cmd.Dir = c.Dir
		cmd.Env = c.Env
		out, err := cmd.CombinedOutput()
		if log != nil {
			fmt.Fprintf(log, "command=%s %q exit_error=%v\n", c.Program, c.Args, err)
			_, _ = log.Write(out)
		}
		return out, err
	}
}

// checkedPath refuses symlinks at every existing component. These are public
// task-owned build paths, not a claim of protection against a hostile same-UID
// process racing filesystem changes. Owned generations plus rechecks bound that
// assumption; receipt hashes do not certify arbitrary externally supplied code.
func checkedPath(path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrBuild
	}
	at := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(path, at), string(filepath.Separator)) {
		at = filepath.Join(at, part)
		info, err := os.Lstat(at)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return ErrBuild
		}
	}
	return nil
}
func owned(info os.FileInfo) bool {
	s, ok := info.Sys().(*syscall.Stat_t)
	return ok && s.Uid == uint32(os.Getuid())
}
func readRegular(path string, limit int64) ([]byte, error) {
	return readPublicFile(path, limit, false)
}
func readPublicFile(path string, limit int64, allowEmpty bool) ([]byte, error) {
	if checkedPath(path) != nil {
		return nil, ErrBuild
	}
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || !owned(before) || (!allowEmpty && before.Size() == 0) || before.Size() > limit {
		return nil, ErrBuild
	}
	stat, ok := before.Sys().(*syscall.Stat_t)
	if !ok || stat.Nlink != 1 {
		return nil, ErrBuild
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, ErrBuild
	}
	opened, err := f.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = f.Close()
		return nil, ErrBuild
	}
	b, readErr := io.ReadAll(io.LimitReader(f, limit+1))
	after, statErr := f.Stat()
	closeErr := f.Close()
	current, pathErr := os.Lstat(path)
	if readErr != nil || statErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(before, after) || !os.SameFile(before, current) || before.Size() != after.Size() || before.ModTime() != after.ModTime() || int64(len(b)) != before.Size() {
		return nil, ErrBuild
	}
	return b, nil
}
func sum(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

// SourceDigest freezes selected repository SOURCE bytes, including the native
// package/build declarations. No ignored stage, testdata, wallet or owner files
// are read. Additional selected source changes conservatively invalidate a build.
func SourceDigest(root string) (string, error) {
	if checkedPath(root) != nil {
		return "", ErrBuild
	}
	files := []string{"go.mod", "go.sum", "Package.swift", "cmd/mac-keyvault-namecoin-abi/module.modulemap", "internal/keyvault/recoverydata/english.txt"}
	for _, dir := range []string{"cmd/mac-keyvault-namecoin-archive", "cmd/mac-keyvault-enclave", "internal", "third_party", "tools/recoverybuild"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return ErrBuild
			}
			if d.Type()&os.ModeSymlink != 0 {
				return ErrBuild
			}
			if d.IsDir() {
				if d.Name() == "testdata" || strings.HasPrefix(d.Name(), ".") {
					return filepath.SkipDir
				}
				return nil
			}
			ext := filepath.Ext(path)
			if ext == ".go" || ext == ".swift" || ext == ".c" || ext == ".h" || ext == ".s" || ext == ".S" || ext == ".m" || ext == ".mm" || ext == ".cc" || ext == ".cpp" || ext == ".cxx" || ext == ".inc" || ext == ".syso" || d.Name() == "go.mod" || d.Name() == "go.sum" {
				rel, e := filepath.Rel(root, path)
				if e != nil {
					return ErrBuild
				}
				files = append(files, filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			return "", ErrBuild
		}
	}
	sort.Strings(files)
	digest := sha256.New()
	for _, rel := range files {
		b, err := readPublicFile(filepath.Join(root, filepath.FromSlash(rel)), 16<<20, true)
		if err != nil {
			return "", ErrBuild
		}
		fmt.Fprintf(digest, "%s\x00%s\n", rel, sum(b))
	}
	return hex.EncodeToString(digest.Sum(nil)), nil
}
func ValidInput(input string) bool { return inputPattern.MatchString(input) }
func exclusive(path string, b []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrBuild
	}
	n, writeErr := f.Write(b)
	syncErr := f.Sync()
	closeErr := f.Close()
	if writeErr != nil || n != len(b) || syncErr != nil || closeErr != nil {
		return ErrBuild
	}
	return nil
}

// ValidateStage checks the exact pair against its same-generation receipt and
// current source digest before compilation. No missing receipt is synthesized,
// no stale input is repaired, and no failure path removes retained evidence.
func ValidateStage(root, input, source string) (Receipt, error) {
	var r Receipt
	if checkedPath(root) != nil || !ValidInput(input) || !digestPattern.MatchString(source) {
		return r, ErrBuild
	}
	dir := filepath.Join(root, filepath.FromSlash(input))
	if checkedPath(dir) != nil {
		return r, ErrBuild
	}
	info, err := os.Lstat(dir)
	if err != nil || !info.IsDir() || !owned(info) || info.Mode().Perm() != 0500 {
		return r, ErrBuild
	}
	raw, err := readRegular(filepath.Join(dir, receiptName), 4096)
	if err != nil {
		return r, ErrBuild
	}
	receiptInfo, err := os.Lstat(filepath.Join(dir, receiptName))
	if err != nil || receiptInfo.Mode().Perm() != 0400 {
		return Receipt{}, ErrBuild
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 4 {
		return Receipt{}, ErrBuild
	}
	for _, entry := range entries {
		switch entry.Name() {
		case archiveName, headerName, moduleName, receiptName:
		default:
			return Receipt{}, ErrBuild
		}
	}
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&r) != nil {
		return Receipt{}, ErrBuild
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return Receipt{}, ErrBuild
	}
	if r.Schema != "keyvault-native-archive/1" || r.Directory != input || r.SourceSHA256 != source {
		return Receipt{}, ErrBuild
	}
	canonical, err := json.MarshalIndent(r, "", "  ")
	if err != nil || !bytes.Equal(raw, append(canonical, '\n')) {
		return Receipt{}, ErrBuild
	}
	for _, item := range []struct {
		name, want string
		limit      int64
	}{{archiveName, r.ArchiveSHA256, 128 << 20}, {headerName, r.HeaderSHA256, 1 << 20}, {moduleName, r.ModuleSHA256, 4096}} {
		b, e := readRegular(filepath.Join(dir, item.name), item.limit)
		info, se := os.Lstat(filepath.Join(dir, item.name))
		if e != nil || se != nil || info.Mode().Perm() != 0400 || !digestPattern.MatchString(item.want) || sum(b) != item.want {
			return Receipt{}, ErrBuild
		}
	}
	template, e := readRegular(filepath.Join(root, "cmd/mac-keyvault-namecoin-abi/module.modulemap"), 4096)
	if e != nil || sum(template) != r.ModuleSHA256 {
		return Receipt{}, ErrBuild
	}
	return r, nil
}

func Build(ctx context.Context, o Options) (Result, error) {
	var result Result
	if ctx == nil || ctx.Err() != nil {
		return result, ErrBuild
	}
	if checkedPath(o.Root) != nil || !filepath.IsAbs(o.GoTool) || filepath.Clean(o.GoTool) != o.GoTool {
		return result, ErrBuild
	}
	source, err := SourceDigest(o.Root)
	if err != nil {
		return result, ErrBuild
	}
	parent := filepath.Join(o.Root, ".temp")
	if err = os.Mkdir(parent, 0700); err != nil && !os.IsExist(err) {
		return result, ErrBuild
	}
	if checkedPath(parent) != nil {
		return result, ErrBuild
	}
	info, err := os.Lstat(parent)
	if err != nil || !info.IsDir() || !owned(info) || info.Mode().Perm()&0022 != 0 {
		return result, ErrBuild
	}
	var random [16]byte
	if _, err = rand.Read(random[:]); err != nil {
		return result, ErrBuild
	}
	suffix := hex.EncodeToString(random[:])
	input := ".temp/native-archive-" + suffix
	dir := filepath.Join(o.Root, filepath.FromSlash(input))
	scratch := filepath.Join(parent, "native-swift-"+suffix)
	if os.Mkdir(dir, 0700) != nil {
		return result, ErrBuild
	}
	if os.Mkdir(scratch, 0700) != nil {
		return result, ErrBuild
	}
	run := o.Execute
	if run == nil {
		run = realExecutor(o.Log)
	}
	invoke := func(program string, args ...string) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrBuild
		}
		return run(ctx, Command{Program: program, Args: args, Dir: o.Root, Env: Environment(input)})
	}
	if _, err = invoke(o.GoTool, "build", "-p", "1", "-mod=readonly", "-trimpath", "-buildmode=c-archive", "-o", filepath.Join(dir, archiveName), "./cmd/mac-keyvault-namecoin-archive"); err != nil {
		return result, ErrBuild
	}
	archive, err := readRegular(filepath.Join(dir, archiveName), 128<<20)
	if err != nil {
		return result, ErrBuild
	}
	header, err := readRegular(filepath.Join(dir, headerName), 1<<20)
	if err != nil {
		return result, ErrBuild
	}
	template, err := readRegular(filepath.Join(o.Root, "cmd/mac-keyvault-namecoin-abi/module.modulemap"), 4096)
	if err != nil {
		return result, ErrBuild
	}
	if exclusive(filepath.Join(dir, moduleName), template) != nil {
		return result, ErrBuild
	}
	after, err := SourceDigest(o.Root)
	if err != nil || after != source {
		return result, ErrBuild
	}
	receipt := Receipt{Schema: "keyvault-native-archive/1", Directory: input, SourceSHA256: source, ArchiveSHA256: sum(archive), HeaderSHA256: sum(header), ModuleSHA256: sum(template)}
	encoded, err := json.MarshalIndent(receipt, "", "  ")
	if err != nil || exclusive(filepath.Join(dir, receiptName), append(encoded, '\n')) != nil {
		return result, ErrBuild
	}
	for _, name := range []string{archiveName, headerName, moduleName, receiptName} {
		if os.Chmod(filepath.Join(dir, name), 0400) != nil {
			return result, ErrBuild
		}
	}
	if os.Chmod(dir, 0500) != nil {
		return result, ErrBuild
	}
	if _, err = ValidateStage(o.Root, input, source); err != nil {
		return result, ErrBuild
	}
	args := []string{"swift", "build", "--jobs", "1", "--package-path", o.Root, "--scratch-path", scratch, "--configuration", "release", "--product", "mac-keyvault-enclave"}
	if _, err = invoke("/usr/bin/xcrun", args...); err != nil {
		return result, ErrBuild
	}
	if _, err = ValidateStage(o.Root, input, source); err != nil {
		return result, ErrBuild
	}
	args = []string{"swift", "build", "--jobs", "1", "--package-path", o.Root, "--scratch-path", scratch, "--configuration", "release", "--show-bin-path"}
	raw, err := invoke("/usr/bin/xcrun", args...)
	if err != nil {
		return result, ErrBuild
	}
	bin := strings.TrimSpace(string(raw))
	if !filepath.IsAbs(bin) || filepath.Clean(bin) != bin || strings.ContainsAny(bin, "\r\n") {
		return result, ErrBuild
	}
	rel, err := filepath.Rel(scratch, bin)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return result, ErrBuild
	}
	helper := filepath.Join(bin, "mac-keyvault-enclave")
	b, err := readRegular(helper, 128<<20)
	if err != nil {
		return result, ErrBuild
	}
	helperInfo, err := os.Lstat(helper)
	if err != nil || helperInfo.Mode().Perm()&0100 == 0 {
		return result, ErrBuild
	}
	after, err = SourceDigest(o.Root)
	if err != nil || after != source {
		return result, ErrBuild
	}
	if _, err = ValidateStage(o.Root, input, source); err != nil {
		return result, ErrBuild
	}
	result = Result{Helper: helper, HelperSHA256: sum(b), Directory: input, Scratch: scratch, Receipt: receipt}
	record, err := json.MarshalIndent(result, "", "  ")
	if err != nil || exclusive(filepath.Join(scratch, "native-build-receipt.json"), append(record, '\n')) != nil {
		return Result{}, ErrBuild
	}
	return result, nil
}

// CopyHelper creates only a NEW destination, retaining the original generation.
// The build tool may subsequently sign its separate output under its existing
// policy; this operation never invokes codesign or runs the compiled helper.
func CopyHelper(result Result, destination string) error {
	if !filepath.IsAbs(destination) || filepath.Clean(destination) != destination {
		return ErrBuild
	}
	// Caller outputs may use the host's ordinary /var temporary-directory alias.
	// Resolve only their existing parent, then exclusively create the NEW leaf;
	// archive/source inputs retain the strict no-symlink rule above.
	parent, err := filepath.EvalSymlinks(filepath.Dir(destination))
	if err != nil || checkedPath(parent) != nil {
		return ErrBuild
	}
	destination = filepath.Join(parent, filepath.Base(destination))
	b, err := readRegular(result.Helper, 128<<20)
	if err != nil || sum(b) != result.HelperSHA256 {
		return ErrBuild
	}
	if err = exclusive(destination, b); err != nil {
		return ErrBuild
	}
	if os.Chmod(destination, 0700) != nil {
		return ErrBuild
	}
	actual, err := readRegular(destination, 128<<20)
	if err != nil || sum(actual) != result.HelperSHA256 {
		return ErrBuild
	}
	return nil
}

// WriteReceipt preserves public source/pair/output hashes beside a new caller
// output. It does not describe a later signed helper as the unqualified hash.
func WriteReceipt(result Result, path string) error {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return ErrBuild
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(path))
	if err != nil || checkedPath(parent) != nil {
		return ErrBuild
	}
	path = filepath.Join(parent, filepath.Base(path))
	b, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return ErrBuild
	}
	return exclusive(path, append(b, '\n'))
}
