//go:build darwin || linux

// Package namecoinfiles freezes bounded private-permission public request/config
// files and creates one explicit public-result descriptor for the custody child.
// It carries no key, Keychain, signing, policy or biometric authority.
package namecoinfiles

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var ErrUnsafe = errors.New("namecoin_file_unavailable")

// refusalWithCause keeps the refusal text stable while retaining a syscall cause.
type refusalWithCause struct {
	cause error
}

func (e refusalWithCause) Error() string        { return ErrUnsafe.Error() }
func (e refusalWithCause) Unwrap() error        { return e.cause }
func (e refusalWithCause) Is(target error) bool { return target == ErrUnsafe }
func (e refusalWithCause) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, e.Error())
}

func unsafeWithCause(cause error) error {
	if cause == nil {
		return ErrUnsafe
	}
	return refusalWithCause{cause: cause}
}

type directory struct {
	parent, fd int
	name       string
}
type heldPath struct {
	dirs []directory
	uid  uint32
	name string
}

func safeDirectory(fd int, uid uint32) (bool, error) {
	var s unix.Stat_t
	if err := unix.Fstat(fd, &s); err != nil {
		return false, err
	}
	return s.Mode&unix.S_IFMT == unix.S_IFDIR && (s.Uid == 0 || s.Uid == uid) && s.Mode&0o7022 == 0, nil
}
func walkParent(path string, retainCause bool) (*heldPath, error) {
	if os.Getuid() != os.Geteuid() || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
		return nil, ErrUnsafe
	}
	refusal := func(err error) error {
		if retainCause {
			return unsafeWithCause(err)
		}
		return ErrUnsafe
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
		return nil, refusal(err)
	}
	h.dirs = append(h.dirs, directory{parent: -1, fd: root})
	if ok, err := safeDirectory(root, h.uid); err != nil {
		return nil, refusal(err)
	} else if !ok {
		return nil, ErrUnsafe
	}
	current := root
	for _, component := range strings.Split(strings.TrimPrefix(filepath.Dir(path), "/"), "/") {
		if component == "" {
			continue
		}
		fd, err := unix.Openat(current, component, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err != nil {
			return nil, refusal(err)
		}
		h.dirs = append(h.dirs, directory{parent: current, fd: fd, name: component})
		if ok, err := safeDirectory(fd, h.uid); err != nil {
			return nil, refusal(err)
		} else if !ok {
			return nil, ErrUnsafe
		}
		current = fd
	}
	if ok, err := h.validWithCause(); err != nil {
		return nil, refusal(err)
	} else if !ok {
		return nil, ErrUnsafe
	}
	good = true
	return h, nil
}
func (h *heldPath) parent() int { return h.dirs[len(h.dirs)-1].fd }
func (h *heldPath) validWithCause() (bool, error) {
	if h == nil || len(h.dirs) == 0 {
		return false, nil
	}
	for _, d := range h.dirs {
		ok, err := safeDirectory(d.fd, h.uid)
		if err != nil {
			return false, err
		}
		if !ok {
			return false, nil
		}
		if d.parent >= 0 {
			var path, held unix.Stat_t
			if err := unix.Fstatat(d.parent, d.name, &path, unix.AT_SYMLINK_NOFOLLOW); err != nil {
				return false, err
			}
			if err := unix.Fstat(d.fd, &held); err != nil {
				return false, err
			}
			if path.Dev != held.Dev || path.Ino != held.Ino || path.Mode&unix.S_IFMT != unix.S_IFDIR {
				return false, nil
			}
		}
	}
	return true, nil
}
func (h *heldPath) valid() bool {
	valid, err := h.validWithCause()
	return err == nil && valid
}
func (h *heldPath) close() {
	for i := len(h.dirs) - 1; i >= 0; i-- {
		_ = unix.Close(h.dirs[i].fd)
	}
	h.dirs = nil
}
func (h *heldPath) checkWithCause(f *os.File) (unix.Stat_t, bool, error) {
	var held, path unix.Stat_t
	valid, err := h.validWithCause()
	if err != nil {
		return held, false, err
	}
	if !valid || f == nil {
		return held, false, nil
	}
	if err := unix.Fstat(int(f.Fd()), &held); err != nil {
		return held, false, err
	}
	if held.Mode&unix.S_IFMT != unix.S_IFREG || held.Uid != h.uid || held.Mode&0o7777 != 0o600 || held.Nlink != 1 {
		return held, false, nil
	}
	if err := unix.Fstatat(h.parent(), h.name, &path, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return held, false, err
	}
	if path.Dev != held.Dev || path.Ino != held.Ino || path.Mode&unix.S_IFMT != unix.S_IFREG {
		return held, false, nil
	}
	flags, err := unix.FcntlInt(f.Fd(), unix.F_GETFD, 0)
	if err != nil {
		return held, false, err
	}
	return held, flags == unix.FD_CLOEXEC, nil
}
func (h *heldPath) check(f *os.File) (unix.Stat_t, bool) {
	stat, ok, _ := h.checkWithCause(f)
	return stat, ok
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
	h, err := walkParent(path, false)
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
	return createOutput(path, nil)
}

// CreateOutputAfterOpenForTest creates and exclusively opens the output before
// invoking afterOpen, then runs the normal output revalidation path. It exists
// only for deterministic setup-failure controls in internal package tests.
func CreateOutputAfterOpenForTest(path string, afterOpen func(*os.File)) (*Output, error) {
	if afterOpen == nil {
		return nil, ErrUnsafe
	}
	return createOutput(path, afterOpen)
}

func createOutput(path string, afterOpen func(*os.File)) (*Output, error) {
	h, err := walkParent(path, true)
	if err != nil {
		return nil, err
	}
	fd, err := unix.Openat(h.parent(), h.name, unix.O_RDWR|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0o600)
	if err != nil {
		h.close()
		return nil, unsafeWithCause(err)
	}
	f := os.NewFile(uintptr(fd), "namecoin public result")
	if afterOpen != nil {
		afterOpen(f)
	}
	stat, ok, cause := h.checkWithCause(f)
	if !ok || stat.Size != 0 {
		f.Close()
		h.close()
		return nil, unsafeWithCause(cause)
	}
	if err := unix.Fsync(h.parent()); err != nil {
		f.Close()
		h.close()
		return nil, unsafeWithCause(err)
	}
	return &Output{path: h, file: f}, nil
}
func (o *Output) FileForChild() (*os.File, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, ErrUnsafe
	}
	stat, ok, cause := o.path.checkWithCause(o.file)
	if !ok || stat.Size != 0 {
		return nil, unsafeWithCause(cause)
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
