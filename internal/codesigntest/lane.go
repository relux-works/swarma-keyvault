// Package codesigntest coordinates the opt-in public code-identity fixtures.
package codesigntest

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
)

const (
	OptInEnv  = "KEYVAULT_CODESIGN_TESTS"
	RunEnv    = "KEYVAULT_CODESIGN_RUN"
	ParentEnv = "KEYVAULT_CODESIGN_PARENT"
	LockFD    = 3 // First descriptor passed by the runner through exec.Cmd.ExtraFiles.
)

var ErrBusy = errors.New("codesign test lane is busy")

// StateDir resolves a fixed location in the real account home and verifies
// its parents without following Library or Application Support symlinks.
func StateDir(prepare bool) (string, error) {
	home, err := AccountHome()
	if err != nil {
		return "", err
	}
	library := filepath.Join(home, "Library")
	support := filepath.Join(library, "Application Support")
	for _, parent := range []string{library, support} {
		if err := ownedDir(parent, false); err != nil {
			return "", err
		}
	}
	tool := filepath.Join(support, "swarma-keyvault-codesigntest")
	if prepare {
		if err := os.Mkdir(tool, 0700); err != nil && !os.IsExist(err) {
			return "", err
		}
	}
	if err := ownedDir(tool, true); err != nil {
		return "", err
	}
	return filepath.Join(tool, "test-lane"), nil
}

func AccountHome() (string, error) {
	account, err := user.LookupId(strconv.Itoa(os.Getuid()))
	if err != nil {
		return "", err
	}
	if !filepath.IsAbs(account.HomeDir) {
		return "", errors.New("codesign lane requires an absolute account home")
	}
	home, err := filepath.EvalSymlinks(account.HomeDir)
	if err != nil {
		return "", err
	}
	if err := ownedDir(home, false); err != nil {
		return "", err
	}
	return home, nil
}

func BootID() (string, error) {
	if runtime.GOOS != "darwin" {
		return "", errors.New("native code-signing fixtures require macOS")
	}
	out, err := exec.Command("/usr/sbin/sysctl", "-n", "kern.bootsessionuuid").Output()
	if err != nil {
		return "", fmt.Errorf("read macOS boot identity: %w", err)
	}
	boot := strings.TrimSpace(string(out))
	if boot == "" {
		return "", errors.New("missing macOS boot identity")
	}
	return boot, nil
}

func ownedDir(path string, private bool) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || !ok || st.Uid != uint32(os.Getuid()) ||
		info.Mode().Perm()&0022 != 0 || (private && info.Mode().Perm() != 0700) {
		return fmt.Errorf("unsafe codesign directory: %s", path)
	}
	return nil
}

func validLock(st *syscall.Stat_t) bool {
	return st.Mode&syscall.S_IFMT == syscall.S_IFREG && st.Mode&0777 == 0600 &&
		st.Uid == uint32(os.Getuid()) && st.Nlink == 1
}

func Lock(dir string) (*os.File, error) {
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return nil, err
	}
	if err := ownedDir(dir, true); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0600)
	if err != nil {
		return nil, err
	}
	var st syscall.Stat_t
	if err := syscall.Fstat(int(f.Fd()), &st); err != nil || !validLock(&st) {
		f.Close()
		return nil, errors.New("codesign lane lock must be an owned mode-0600 regular file with one link")
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return nil, ErrBusy
		}
		return nil, err
	}
	return f, nil
}

func runName(name string) bool {
	return filepath.Base(name) == name && strings.HasPrefix(name, "run-") &&
		len(name) > len("run-")
}

// BuildOnce preserves one build attempt and its result for a test executable,
// including a failed attempt.
type BuildOnce struct {
	once sync.Once
	path string
	err  error
}

func (b *BuildOnce) Get(build func() (string, error)) (string, error) {
	b.once.Do(func() { b.path, b.err = build() })
	return b.path, b.err
}
