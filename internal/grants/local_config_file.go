package grants

import (
	"io"
	"os"
	"syscall"
)

// LoadLocalEnrollment admits only a regular owner-private config descriptor.
// This prevents accidental public/symlink configuration, not same-UID rewriting.
// It never creates a configuration or enrolls caller-supplied request fields.
func LoadLocalEnrollment(path string) (*LocalEnrollment, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrLocalState
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !privateLocalFile(file, 0600) {
		return nil, ErrLocalState
	}
	raw, err := io.ReadAll(io.LimitReader(file, 8193))
	if err != nil {
		return nil, ErrLocalState
	}
	if len(raw) > 8192 {
		return nil, errInputLimit
	}
	return ParseLocalEnrollment(raw)
}
