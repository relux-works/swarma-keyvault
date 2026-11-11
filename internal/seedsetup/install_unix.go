//go:build darwin || linux

package seedsetup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

const maxAssetSize = 128 << 20

func ownerOf(info os.FileInfo) (uint32, bool) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return st.Uid, true
}

// The runtime always uses OS ownership. Tests may project filesystem ownership
// for two synthetic accounts without changing any real account or file owner.
func (p installation) owner(path string, info os.FileInfo) (uint32, bool) {
	if p.fileOwner != nil {
		return p.fileOwner(path, info)
	}
	return ownerOf(info)
}

// Parent walking refuses symlinks and writable foreign components. Allow root
// and current-user ancestors, since the shared home base is system-owned.
func (p installation) checkDirectoryChain(dir string) error {
	for path := dir; ; path = filepath.Dir(path) {
		s, err := os.Lstat(path)
		if err != nil {
			return refused("directory_chain_missing")
		}
		owner, ok := p.owner(path, s)
		// A root-owned sticky ancestor protects its existing children's
		// names; the selected directory itself may never be shared/writable.
		stickyAncestor := path != dir && owner == 0 && s.Mode()&os.ModeSticky != 0
		if !s.IsDir() || s.Mode().Perm()&0022 != 0 && !stickyAncestor || !ok || owner != 0 && owner != p.uid {
			return refused("directory_chain_unsafe")
		}
		if filepath.Dir(path) == path {
			return nil
		}
	}
}

func (p installation) optionalOwned(path string, directory bool, mode os.FileMode) (bool, error) {
	s, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		return false, refused("private_path_unavailable")
	}
	owner, ok := p.owner(path, s)
	if !ok || owner != p.uid || s.Mode().Perm() != mode || s.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 ||
		directory && !s.IsDir() || !directory && !s.Mode().IsRegular() {
		return false, refused("private_path_unsafe")
	}
	return true, nil
}

func absent(path string) error {
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		return refused("install_destination_already_exists")
	}
	return nil
}

func (p installation) openAsset(path string) (*os.File, error) {
	if err := p.checkDirectoryChain(filepath.Dir(path)); err != nil {
		return nil, err
	}
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, refused("release_artifact_unavailable")
	}
	f := os.NewFile(uintptr(fd), path)
	s, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, refused("release_artifact_unavailable")
	}
	owner, ok := p.owner(path, s)
	if !s.Mode().IsRegular() || s.Size() < 1 || s.Size() > maxAssetSize || !ok || owner != p.uid ||
		s.Mode().Perm()&0022 != 0 || s.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		f.Close()
		return nil, refused("release_artifact_unsafe")
	}
	return f, nil
}

func hashBounded(r io.Reader, want string) error {
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(r, maxAssetSize+1))
	if err != nil || n < 1 || n > maxAssetSize || hex.EncodeToString(h.Sum(nil)) != want {
		return refused("release_artifact_hash")
	}
	return nil
}

func (p installation) verifyFile(path string, spec installFile, run runner) error {
	f, err := p.openAsset(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := hashBounded(f, spec.sha); err != nil {
		return err
	}
	if spec.code == "" {
		return nil
	}
	if reply := run("/usr/bin/codesign", "--verify", "--strict", path); !reply.started || reply.exit != 0 {
		return refused("release_artifact_signature")
	}
	reply := run("/usr/bin/codesign", "-d", "-r-", path)
	want := "# designated => cdhash H\"" + spec.code + "\""
	count := 0
	for _, line := range strings.Split(string(reply.raw), "\n") {
		if line == want {
			count++
		} else if strings.HasPrefix(line, "# designated =>") {
			return refused("release_artifact_code_identity")
		}
	}
	if !reply.started || reply.exit != 0 || count != 1 {
		return refused("release_artifact_code_identity")
	}
	opened, openedErr := f.Stat()
	current, currentErr := os.Lstat(path)
	if openedErr != nil || currentErr != nil || !os.SameFile(opened, current) {
		return refused("release_artifact_changed")
	}
	return nil
}

func (p installation) checkDestinations() error {
	if err := p.checkDirectoryChain(filepath.Dir(p.paths.Root)); err != nil {
		return err
	}
	// Home need not be private to read/search, but it belongs to this OS user.
	s, err := os.Lstat(p.paths.Home)
	if err != nil {
		return refused("home_unavailable")
	}
	owner, ok := p.owner(p.paths.Home, s)
	if !ok || owner != p.uid || !s.IsDir() || s.Mode().Perm()&0022 != 0 {
		return refused("home_ownership")
	}
	for _, dir := range p.installParents() {
		if _, err := p.optionalOwned(dir, true, 0700); err != nil {
			return err
		}
	}
	if err := p.checkLockPaths(); err != nil {
		return err
	}
	return absent(p.paths.InstallDirectory)
}

func (p installation) checkLockPaths() error {
	if len(p.paths.LockParents) != 2 || filepath.Dir(p.paths.LockParents[1]) != p.paths.LockParents[0] ||
		filepath.Dir(p.paths.Lock) != p.paths.LockParents[1] {
		return refused("invalid_lock_paths")
	}
	if err := p.checkDirectoryChain(filepath.Dir(p.paths.LockParents[0])); err != nil {
		return err
	}
	for _, dir := range p.paths.LockParents {
		if _, err := p.optionalOwned(dir, true, 0700); err != nil {
			return err
		}
	}
	_, err := p.optionalOwned(p.paths.Lock, false, 0600)
	return err
}

func (p installation) preflight(run runner) error {
	if err := p.checkDestinations(); err != nil {
		return err
	}
	for _, spec := range p.files() {
		if err := p.verifyFile(filepath.Join(p.paths.ArtifactDirectory, spec.relative), spec, run); err != nil {
			return err
		}
	}
	return nil
}

func (p installation) installFile(spec installFile, run runner) error {
	source := filepath.Join(p.paths.ArtifactDirectory, spec.relative)
	dest := filepath.Join(p.paths.InstallDirectory, spec.relative)
	src, err := p.openAsset(source)
	if err != nil {
		return err
	}
	defer src.Close()
	// Authenticate the very descriptor copied. Recheck the installed bytes
	// before any execution; partial paths are kept and never overwritten.
	if err := hashBounded(src, spec.sha); err != nil {
		return err
	}
	if _, err := src.Seek(0, io.SeekStart); err != nil {
		return refused("release_artifact_seek")
	}
	dst, err := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return refused("install_file_no_retry")
	}
	n, copyErr := io.Copy(dst, io.LimitReader(src, maxAssetSize+1))
	if n < 1 || n > maxAssetSize || copyErr != nil {
		dst.Close()
		return refused("install_copy_no_retry")
	}
	// Bytes are verified before chmod adds execute permission.
	syncErr := dst.Sync()
	closeErr := dst.Close()
	if syncErr != nil || closeErr != nil {
		return refused("install_copy_no_retry")
	}
	f, err := p.openAsset(dest)
	if err != nil {
		return err
	}
	hashErr := hashBounded(f, spec.sha)
	if hashErr == nil {
		hashErr = f.Chmod(spec.mode)
	}
	f.Close()
	if hashErr != nil {
		return refused("install_integrity_no_retry")
	}
	if exists, err := p.optionalOwned(dest, false, spec.mode); !exists || err != nil {
		return refused("installed_artifact_custody")
	}
	return p.verifyFile(dest, spec, run)
}

func (p installation) install(run runner) error {
	if err := p.checkDestinations(); err != nil {
		return err
	}
	for _, path := range p.installParents() {
		exists, err := p.optionalOwned(path, true, 0700)
		if err != nil {
			return err
		}
		if !exists {
			if err := os.Mkdir(path, 0700); err != nil {
				return refused("install_parent_no_retry")
			}
		}
	}
	for _, path := range []string{p.paths.InstallDirectory, filepath.Join(p.paths.InstallDirectory, foreignDir)} {
		if err := os.Mkdir(path, 0700); err != nil {
			return refused("install_directory_no_retry")
		}
	}
	for _, spec := range p.files() {
		if err := p.installFile(spec, run); err != nil {
			return err
		}
	}
	return nil
}

func checkCappedOutput(stdout, stderr *capped, code int, allowStderr bool) invocation {
	if stdout.full || stderr.full || !allowStderr && stderr.Len() != 0 {
		clear(stdout.Bytes())
		clear(stderr.Bytes())
		return invocation{exit: -1, started: true}
	}
	if allowStderr {
		return invocation{raw: bytes.Join([][]byte{stdout.Bytes(), stderr.Bytes()}, []byte("\n")), exit: code, started: true}
	}
	return invocation{raw: stdout.Bytes(), exit: code, started: true}
}

func execute(ctx context.Context, p installation, w workflow, c Config, ids Identities) error {
	if err := p.preflight(w.run); err != nil {
		return err
	}
	actual, err := w.plan(c)
	if err != nil {
		return err
	}
	// Disposable means a new exact slot; even if caller chose a previously used
	// qualification identity, never select a different generation for it.
	qual, err := w.plan(Config{NostrIdentity: ids.QualificationNostr, NamecoinIdentity: ids.QualificationNamecoin, Version: 1, NostrVersion: 1, NamecoinVersion: 1})
	if err != nil {
		return err
	}
	if err := w.confirm(p, actual, qual); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return refused("setup_interrupted")
	}
	if err := p.install(w.run); err != nil {
		return err
	}
	// Never retry or re-plan after consent. Both writes are rechecked by the
	// vault under its own lock at the exact confirmed addresses.
	if err := w.qualify(p.installedVault(), p.installedForeign(), qual); err != nil {
		return err
	}
	if ctx.Err() != nil {
		return refused("setup_interrupted_keep_do_not_retry")
	}
	if err := p.checkLockPaths(); err != nil {
		return err
	}
	return w.createActual(p.installedVault(), actual)
}
