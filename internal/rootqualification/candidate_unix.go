//go:build darwin || linux

package rootqualification

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
	"golang.org/x/sys/unix"
)

type observedArtifact struct {
	fd, parent int
	name, path string
	stat       unix.Stat_t
	role       codesignpolicy.Role
	pin        Artifact
}

// ObservedCandidate holds actual no-follow artifact descriptors and ancestor
// identities. Construction performs actual fixed-policy static verification;
// no public facts/provider callback can construct a successful observation.
// The caller separately checks the ACTUAL runtime parent/child CDHash.
type ObservedCandidate struct {
	mu        sync.Mutex
	files     *receiptFiles
	artifacts []observedArtifact
	candidate Candidate
	closed    bool
}

func ObserveCandidate(ctx context.Context, head, tree string) (out *ObservedCandidate, err error) {
	if ctx == nil || ctx.Err() != nil || !lowerHex(head, 40) || !lowerHex(tree, 40) {
		return nil, ErrReceipt
	}
	r, e := openOwnReceiptFiles()
	if e != nil {
		return nil, ErrReceipt
	}
	o := &ObservedCandidate{files: r, candidate: Candidate{SourceHead: head, SourceTree: tree}}
	defer func() {
		if err != nil {
			_ = o.Close()
		}
	}()
	base := r.dirfd()
	artifacts, e := o.openDirectory(base, "artifacts")
	if e != nil {
		return nil, ErrReceipt
	}
	exe, e := os.Executable()
	if e != nil {
		return nil, ErrReceipt
	}
	directory := filepath.Dir(exe)
	for _, entry := range []struct {
		name string
		role codesignpolicy.Role
	}{{"mac-keyvault", codesignpolicy.Vault}, {"mac-keyvault-enclave", codesignpolicy.Helper}} {
		if e := o.openArtifact(artifacts, entry.name, filepath.Join(directory, entry.name), entry.role); e != nil {
			return nil, e
		}
	}
	foreign, e := o.openDirectory(artifacts, "qualification")
	if e != nil {
		return nil, ErrReceipt
	}
	if e := o.openArtifact(foreign, "mac-keyvault", filepath.Join(directory, "qualification", "mac-keyvault"), codesignpolicy.Qualification); e != nil {
		return nil, e
	}
	for i := range o.artifacts {
		a := &o.artifacts[i]
		hash, e := o.hashArtifact(*a)
		if e != nil {
			return nil, e
		}
		cdhash, e := observeArtifactCode(ctx, a.path, a.role)
		if e != nil {
			return nil, e
		}
		a.pin = Artifact{SHA256: hash, CDHash: cdhash}
		switch a.role {
		case codesignpolicy.Vault:
			o.candidate.Vault = a.pin
		case codesignpolicy.Helper:
			o.candidate.Helper = a.pin
		case codesignpolicy.Qualification:
			o.candidate.Foreign = a.pin
		default:
			return nil, ErrReceipt
		}
	}
	if o.candidate.Validate() != nil || o.check() != nil {
		return nil, ErrReceipt
	}
	return o, nil
}

func (o *ObservedCandidate) openDirectory(parent int, name string) (int, error) {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, ErrReceipt
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || !receiptDirectoryOK(s, o.files.uid, 0700) {
		_ = unix.Close(fd)
		return -1, ErrReceipt
	}
	o.files.links = append(o.files.links, receiptLink{fd: fd, parent: parent, name: name, stat: s})
	if o.files.check() != nil {
		return -1, ErrReceipt
	}
	return fd, nil
}
func candidateArtifactOK(s unix.Stat_t, uid uint32) bool {
	mode := uint32(s.Mode) & 07777
	return s.Mode&unix.S_IFMT == unix.S_IFREG && s.Uid == uid && s.Nlink == 1 && (mode == 0700 || mode == 0755) && s.Size > 0 && s.Size <= 128<<20
}
func (o *ObservedCandidate) openArtifact(parent int, name, path string, role codesignpolicy.Role) error {
	fd, err := unix.Openat(parent, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrReceipt
	}
	var s unix.Stat_t
	if unix.Fstat(fd, &s) != nil || !candidateArtifactOK(s, o.files.uid) {
		_ = unix.Close(fd)
		return ErrReceipt
	}
	o.artifacts = append(o.artifacts, observedArtifact{fd: fd, parent: parent, name: name, path: path, stat: s, role: role})
	return nil
}
func (o *ObservedCandidate) hashArtifact(a observedArtifact) (string, error) {
	if o.closed || o.files == nil || o.files.check() != nil {
		return "", ErrReceipt
	}
	var before, after, named unix.Stat_t
	if unix.Fstat(a.fd, &before) != nil || unix.Fstatat(a.parent, a.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !candidateArtifactOK(before, o.files.uid) || !sameReceiptObject(a.stat, before) || before.Size != a.stat.Size || !sameReceiptObject(before, named) {
		return "", ErrReceipt
	}
	if _, err := unix.Seek(a.fd, 0, io.SeekStart); err != nil {
		return "", ErrReceipt
	}
	// Dup keeps ownership of the original descriptor with the observation.
	fd, err := unix.Dup(a.fd)
	if err != nil {
		return "", ErrReceipt
	}
	f := os.NewFile(uintptr(fd), a.name)
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, (128<<20)+1))
	if err != nil || n != before.Size || unix.Fstat(a.fd, &after) != nil || unix.Fstatat(a.parent, a.name, &named, unix.AT_SYMLINK_NOFOLLOW) != nil || !sameReceiptObject(before, after) || after.Size != before.Size || !sameReceiptObject(after, named) || o.files.check() != nil {
		return "", ErrReceipt
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
func (o *ObservedCandidate) check() error {
	if o == nil || o.closed || o.files == nil || len(o.artifacts) != 3 || o.candidate.Validate() != nil {
		return ErrReceipt
	}
	for _, a := range o.artifacts {
		h, err := o.hashArtifact(a)
		if err != nil || h != a.pin.SHA256 {
			return ErrReceipt
		}
	}
	return nil
}
func (o *ObservedCandidate) Candidate() (Candidate, error) {
	if o == nil {
		return Candidate{}, ErrReceipt
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.check() != nil {
		return Candidate{}, ErrReceipt
	}
	return o.candidate, nil
}
func (o *ObservedCandidate) Child(role codesignpolicy.Role) (string, string, error) {
	if o == nil {
		return "", "", ErrReceipt
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if role != codesignpolicy.Helper && role != codesignpolicy.Qualification {
		return "", "", ErrReceipt
	}
	if o.check() != nil {
		return "", "", ErrReceipt
	}
	for _, a := range o.artifacts {
		if a.role == role {
			return a.path, a.pin.CDHash, nil
		}
	}
	return "", "", ErrReceipt
}
func (o *ObservedCandidate) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	failed := false
	for _, a := range o.artifacts {
		if unix.Close(a.fd) != nil {
			failed = true
		}
	}
	if o.files != nil && o.files.close() != nil {
		failed = true
	}
	if failed {
		return ErrReceipt
	}
	return nil
}

type codeOutput struct {
	bytes.Buffer
	limit int
}

func (b *codeOutput) Write(p []byte) (int, error) {
	if len(p) > b.limit-b.Len() {
		return 0, ErrReceipt
	}
	return b.Buffer.Write(p)
}
func observeArtifactCode(ctx context.Context, path string, role codesignpolicy.Role) (string, error) {
	read := func(args []string, separate bool) ([]byte, error) {
		if ctx.Err() != nil {
			return nil, ErrReceipt
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/codesign", args...)
		cmd.Env = []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LANG=C", "LC_ALL=C"}
		out, diagnostic := &codeOutput{limit: 65536}, &codeOutput{limit: 65536}
		cmd.Stdout = out
		if separate {
			cmd.Stderr = diagnostic
		} else {
			cmd.Stderr = out
		}
		if cmd.Run() != nil {
			return nil, ErrReceipt
		}
		return bytes.Clone(out.Bytes()), nil
	}
	if _, err := read([]string{"--verify", "--strict", path}, false); err != nil {
		return "", err
	}
	info, err := read([]string{"-d", "--verbose=4", path}, false)
	if err != nil {
		return "", err
	}
	entitlements, err := read([]string{"-d", "--entitlements", "-", "--xml", path}, true)
	if err != nil {
		return "", err
	}
	pin, err := codesignpolicy.CodeInfo(role, info, entitlements)
	if err != nil {
		return "", ErrReceipt
	}
	requirement, err := read([]string{"-d", "-r-", path}, false)
	if err != nil || codesignpolicy.RequirementReadback(role, requirement) != nil || codesignpolicy.CertificateFile(path, role) != nil {
		return "", ErrReceipt
	}
	return pin, nil
}
