package codesigntest

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Kept private so tests can exercise public admission with isolated account
// homes. Production always resolves the registered account, never ambient HOME.
var accountHomeForHealth = AccountHome

// CheckHostHealth checks the fixed host-watch flag under the registered account
// home. Every existing directory must be owned, physical and non-writable by
// other users. Every present flag entry refuses work, including a symlink.
func CheckHostHealth() error {
	home, err := accountHomeForHealth()
	if err != nil {
		return err
	}
	return checkHostHealth(home)
}

// RunHealthy rechecks admission immediately before an individual action. Flag
// publication and action execution are separate operations.
func RunHealthy(action func() error) error {
	home, err := accountHomeForHealth()
	if err != nil {
		return err
	}
	return runHealthy(home, action)
}

func runHealthy(home string, action func() error) error {
	if err := checkHostHealth(home); err != nil {
		return err
	}
	return action()
}

func checkHostHealth(home string) error {
	const flags = unix.O_RDONLY | unix.O_DIRECTORY | unix.O_NOFOLLOW | unix.O_CLOEXEC
	fd, err := unix.Open(home, flags, 0)
	if err != nil {
		return fmt.Errorf("cannot inspect host-health home: %w", err)
	}
	defer func() { _ = unix.Close(fd) }()
	if err := safeHealthDirectory(fd); err != nil {
		return err
	}
	for _, name := range []string{"Library", "Application Support", "host-health"} {
		next, err := unix.Openat(fd, name, flags, 0)
		if errors.Is(err, unix.ENOENT) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("cannot inspect host-health directory %s: %w", name, err)
		}
		_ = unix.Close(fd)
		fd = next
		if err := safeHealthDirectory(fd); err != nil {
			return err
		}
	}
	var info unix.Stat_t
	err = unix.Fstatat(fd, "exec-degraded", &info, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot inspect host-watch exec-degraded: %w", err)
	}
	return errors.New("host-watch exec-degraded is present; codesign fixture work cannot start")
}

func safeHealthDirectory(fd int) error {
	var info unix.Stat_t
	if err := unix.Fstat(fd, &info); err != nil {
		return fmt.Errorf("cannot inspect host-health directory metadata: %w", err)
	}
	if info.Uid != uint32(os.Getuid()) || info.Mode&0022 != 0 || info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("host-health directories must be owned physical directories without group or world write access")
	}
	return nil
}
