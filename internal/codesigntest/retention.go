package codesigntest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	DegradedFile     = "host-degraded"
	minimumRetention = 10 * time.Minute
	cleanupPrefix    = "cleanup-"
)

type runRecord struct {
	Boot        string
	Group       int
	Started     time.Time
	Observed    bool
	Certificate bool
}

type Lane struct {
	dir  string
	boot string
	lock *os.File
}

func Open(dir, boot string) (*Lane, error) {
	if boot == "" {
		return nil, errors.New("missing boot identity")
	}
	lock, err := Lock(dir)
	if err != nil {
		return nil, err
	}
	return &Lane{dir: dir, boot: boot, lock: lock}, nil
}

func (l *Lane) Close() error {
	return l.lock.Close()
}

func (l *Lane) ChildLock() *os.File {
	return l.lock
}

func healthy(dir string) error {
	if _, err := os.Lstat(filepath.Join(dir, DegradedFile)); !os.IsNotExist(err) {
		if err != nil {
			return fmt.Errorf("cannot read host-health flag: %w", err)
		}
		return errors.New("host-degraded is present")
	}
	return nil
}

// Begin cleans up a completed, eligible earlier routine run under the same
// lock, or refuses to start a second run while any retained state is uncertain.
func (l *Lane) Begin(group int, observed, certificate bool, now time.Time) (string, error) {
	if err := healthy(l.dir); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return "", err
	}
	pending := make(map[string]bool)
	for _, entry := range entries {
		name := entry.Name()
		switch {
		case runName(name):
			pending[name] = true
		case strings.HasPrefix(name, cleanupPrefix) && strings.HasSuffix(name, ".json"):
			name = strings.TrimSuffix(strings.TrimPrefix(name, cleanupPrefix), ".json")
			if !runName(name) {
				return "", errors.New("unknown cleanup state")
			}
			pending[name] = true
		case strings.HasPrefix(name, "reap-") || strings.HasPrefix(name, cleanupPrefix):
			return "", fmt.Errorf("unknown cleanup state: %s", name)
		}
	}
	if len(pending) > 1 {
		return "", errors.New("multiple retained fixture runs")
	}
	for name := range pending {
		if err := l.Cleanup(name, false, now); err != nil {
			return "", err
		}
	}
	if group <= 1 {
		return "", errors.New("expected an isolated fixture process group")
	}
	run, err := os.MkdirTemp(l.dir, "run-")
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(runRecord{Boot: l.boot, Group: group, Started: now.UTC(), Observed: observed, Certificate: certificate})
	if err != nil {
		return "", err
	}
	return run, os.WriteFile(filepath.Join(run, "run.json"), raw, 0600)
}

func (l *Lane) Finish(run string, now time.Time) error {
	return os.WriteFile(filepath.Join(run, "finished"), []byte(now.UTC().Format(time.RFC3339Nano)), 0600)
}

// ObserveExit records the earliest proven quiet boundary after the worker
// exits. If the lock is still held by a descendant, the next cleanup can
// establish the boundary once that process group is gone.
func (l *Lane) ObserveExit(group int, now time.Time) error {
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !runName(entry.Name()) {
			continue
		}
		path := filepath.Join(l.dir, entry.Name())
		if err := ownedDir(path, true); err != nil {
			return err
		}
		record, err := readRun(path)
		if err != nil {
			return err
		}
		if record.Group == group && record.Boot == l.boot && !record.Observed {
			_, err := l.exitBoundary(path, record, now, groupGone)
			return err
		}
	}
	return nil
}

func (l *Lane) exitBoundary(path string, record runRecord, now time.Time, gone func(int) (bool, error)) (time.Time, error) {
	raw, err := readState(path, "exited")
	if err == nil {
		exited, err := time.Parse(time.RFC3339Nano, string(raw))
		if err != nil || exited.Before(record.Started) || exited.After(now) {
			return time.Time{}, errors.New("invalid process exit record")
		}
		return exited, nil
	}
	if !os.IsNotExist(err) {
		return time.Time{}, err
	}
	// A previous boot cannot leave live processes in this boot.
	if record.Boot == l.boot {
		if err := requireGroupGone(record.Group, gone); err != nil {
			return time.Time{}, err
		}
		raw, err := readState(path, "finished")
		if err != nil {
			return time.Time{}, errors.New("no known finish")
		}
		finished, err := time.Parse(time.RFC3339Nano, string(raw))
		if err != nil || finished.Before(record.Started) || finished.After(now) {
			return time.Time{}, errors.New("invalid finish record")
		}
	}
	return now, writeState(filepath.Join(path, "exited"), []byte(now.UTC().Format(time.RFC3339Nano)))
}

func requireGroupGone(group int, gone func(int) (bool, error)) error {
	exited, err := gone(group)
	if err != nil || !exited {
		return errors.New("live or unknown process group")
	}
	return nil
}

func readRun(path string) (runRecord, error) {
	var record runRecord
	raw, err := readState(path, "run.json")
	if err != nil {
		return record, err
	}
	if err := json.Unmarshal(raw, &record); err != nil {
		return record, err
	}
	if record.Boot == "" || record.Group <= 1 || record.Started.IsZero() {
		return record, errors.New("invalid retained run record")
	}
	return record, nil
}

func readState(dir, name string) ([]byte, error) {
	path := filepath.Join(dir, name)
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok || !validLock(st) || info.Size() > 4096 {
		return nil, errors.New("invalid codesign lane state file")
	}
	return os.ReadFile(path)
}

func writeState(path string, raw []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		f.Close()
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}

func groupGone(group int) (bool, error) {
	err := syscall.Kill(-group, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true, nil
	}
	return false, err
}
