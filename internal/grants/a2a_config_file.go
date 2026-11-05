package grants

import (
	"errors"
	"io"
	"os"
	"syscall"
)

// A2AConfigLimit is the largest accepted public trust configuration.
const A2AConfigLimit = 196608

// ErrA2AConfigFile refuses a trust configuration file that is not admitted.
var ErrA2AConfigFile = errors.New("a2a-trust-configuration-file-refused")

// LoadA2AExecutorConfig reads the public trust configuration, the executor's
// root of trust. It admits only a regular file, opened without following a
// final symlink, owned by the caller's uid or by root (an installed
// configuration, as for the pinned executables) and writable by nobody else
// (no group/other write bit). Read-only and owner-only modes such as 0600,
// 0644, 0400 and 0444 are accepted; integrity, not secrecy, is the concern.
// This prevents accidental shared or redirected configuration, not same-UID
// rewriting.
func LoadA2AExecutorConfig(path string) ([]byte, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrA2AConfigFile
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o022 != 0 {
		return nil, ErrA2AConfigFile
	}
	identity, ok := info.Sys().(*syscall.Stat_t)
	if !ok || (identity.Uid != uint32(os.Getuid()) && identity.Uid != 0) {
		return nil, ErrA2AConfigFile
	}
	raw, err := io.ReadAll(io.LimitReader(file, A2AConfigLimit+1))
	if err != nil {
		return nil, ErrA2AConfigFile
	}
	if len(raw) > A2AConfigLimit {
		return nil, errInputLimit
	}
	return raw, nil
}
