//go:build darwin || linux

// Package namecoinfiles freezes bounded private-permission public request/config
// files and creates one explicit public-result descriptor for the custody child.
// It carries no key, Keychain, signing, policy or biometric authority.
package namecoinfiles

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrUnsafe = errors.New("namecoin_file_unavailable")

type directory struct {
	parent, fd int
	name       string
}
type heldPath struct {
	dirs []directory
	uid  uint32
	name string
}

func safeDirectory(fd int, uid uint32) bool {
	var s unix.Stat_t
	return unix.Fstat(fd, &s) == nil && s.Mode&unix.S_IFMT == unix.S_IFDIR && (s.Uid == 0 || s.Uid == uid) && s.Mode&0o7022 == 0
}
func walkParent(path string) (*heldPath, error) {
	if os.Getuid() != os.Geteuid() || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return nil, ErrUnsafe
	}
	h := &heldPath{uid: uint32(os.Getuid()), name: filepath.Base(path)}
	good := false
	defer func() {
		if !good {
			h.close()
		}
	}()
	root, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	h.dirs = append(h.dirs, directory{parent: -1, fd: root})
	if !safeDirectory(root, h.uid) {
		return nil, ErrUnsafe
	}
	current := root
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if component == "" {
			continue
		}
		fd, err := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, ErrUnsafe
		}
		h.dirs = append(h.dirs, directory{parent: current, fd: fd, name: component})
		if !safeDirectory(fd, h.uid) {
			return nil, ErrUnsafe
		}
		current = fd
	}
	if !h.valid() {
		return nil, ErrUnsafe
	}
	good = true
	return h, nil
}
func (h *heldPath) parent() int { return h.dirs[len(h.dirs)-1].fd }
func (h *heldPath) valid() bool {
	if h == nil || len(h.dirs) == 0 {
		return false
	}
	for _, d := range h.dirs {
		if !safeDirectory(d.fd, h.uid) {
			return false
		}
		if d.parent >= 0 {
			var path, held unix.Stat_t
			if unix.Fstatat(d.parent, d.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || unix.Fstat(d.fd, &held) != nil || path.Dev != held.Dev || path.Ino != held.Ino || path.Mode&unix.S_IFMT != unix.S_IFDIR {
				return false
			}
		}
	}
	return true
}
func (h *heldPath) close() {
	for i := len(h.dirs) - 1; i >= 0; i-- {
		_ = unix.Close(h.dirs[i].fd)
	}
	h.dirs = nil
}
func (h *heldPath) check(f *os.File) (unix.Stat_t, bool) {
	var held, path unix.Stat_t
	if !h.valid() || f == nil || unix.Fstat(int(f.Fd()), &held) != nil || held.Mode&unix.S_IFMT != unix.S_IFREG || held.Uid != h.uid || held.Mode&0o7777 != 0o600 || held.Nlink != 1 || unix.Fstatat(h.parent(), h.name, &path, unix.AT_SYMLINK_NOFOLLOW) != nil || path.Dev != held.Dev || path.Ino != held.Ino || path.Mode&unix.S_IFMT != unix.S_IFREG {
		return held, false
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	return held, err == nil && flags == unix.FD_CLOEXEC
}
func (h *heldPath) read(f *os.File, maximum int) ([]byte, error) {
	before, ok := h.check(f)
	if !ok || maximum <= 0 || before.Size <= 0 || before.Size > int64(maximum) {
		return nil, ErrUnsafe
	}
	info, err := f.Stat()
	if err != nil {
		return nil, ErrUnsafe
	}
	raw := make([]byte, int(before.Size))
	n, err := f.ReadAt(raw, 0)
	if err != nil || n != len(raw) {
		return nil, ErrUnsafe
	}
	var extra [1]byte
	n, err = f.ReadAt(extra[:], int64(len(raw)))
	if n != 0 || err != io.EOF {
		return nil, ErrUnsafe
	}
	after, ok := h.check(f)
	afterInfo, statErr := f.Stat()
	if !ok || statErr != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || !info.ModTime().Equal(afterInfo.ModTime()) {
		return nil, ErrUnsafe
	}
	return raw, nil
}

// ReadInput returns an owned single snapshot and closes every descriptor. It
// refuses unsafe ancestry/links/types/modes before reading; subsequent caller
// edits cannot change the returned bytes. This is no hostile-writer atomicity
// guarantee, and parsing/independent trusted selection remain separate checks.
func ReadInput(path string, maximum int) ([]byte, error) {
	h, err := walkParent(path)
	if err != nil {
		return nil, err
	}
	defer h.close()
	fd, err := unix.Openat(h.parent(), h.name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnsafe
	}
	f := os.NewFile(uintptr(fd), "namecoin public input")
	defer f.Close()
	return h.read(f, maximum)
}

// Output owns a new regular0600 file and held parent descriptors. The file is
// borrowed solely for exec.Cmd.ExtraFiles fixed childFD3; the child must validate
// its actual fd, set CLOEXEC and persist/verify only the engine's PUBLIC result.
// A file on disk is not proof of a completed signature or receipt. Never delete,
// truncate, chmod, overwrite or retry a partial result as part of this type.
type Output struct {
	mu     sync.Mutex
	path   *heldPath
	file   *os.File
	closed bool
}

func CreateOutput(path string) (*Output, error) {
	h, err := walkParent(path)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(h.parent(), h.name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		h.close()
		return nil, ErrUnsafe
	}
	f := os.NewFile(uintptr(fd), "namecoin public result")
	stat, ok := h.check(f)
	if !ok || stat.Size != 0 {
		f.Close()
		h.close()
		return nil, ErrUnsafe
	}
	if unix.Fsync(h.parent()) != nil {
		f.Close()
		h.close()
		return nil, ErrUnsafe
	}
	return &Output{path: h, file: f}, nil
}
func (o *Output) FileForChild() (*os.File, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, ErrUnsafe
	}
	stat, ok := o.path.check(o.file)
	if !ok || stat.Size != 0 {
		return nil, ErrUnsafe
	}
	return o.file, nil
}

// ReadResult freezes the actual retained descriptor after child completion. The
// caller separately verifies strict result/PSBT/signatures and the admitted ack;
// equal hashes alone do not establish native or protected-history provenance.
func (o *Output) ReadResult(maximum int) ([]byte, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, ErrUnsafe
	}
	raw, err := o.path.read(o.file, maximum)
	if err != nil {
		return nil, err
	}
	// A second bounded readback must match exact bytes, without changing the
	// shared descriptor offset inherited by the child.
	check, err := o.path.read(o.file, maximum)
	if err != nil || !bytes.Equal(raw, check) {
		return nil, ErrUnsafe
	}
	return raw, nil
}
func (o *Output) Close() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil
	}
	o.closed = true
	err := o.file.Close()
	o.path.close()
	if err != nil {
		return ErrUnsafe
	}
	return nil
}
