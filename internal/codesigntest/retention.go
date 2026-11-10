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
	cleanupPrefix    = "reap-"
)

type runRecord struct {
	Boot     string
	Group    int
	Started  time.Time
	Observed bool
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

func (l *Lane) healthy() error {
	if _, err := os.Lstat(filepath.Join(l.dir, DegradedFile)); !os.IsNotExist(err) {
		if err != nil {
			return fmt.Errorf("cannot read host-health flag: %w", err)
		}
		return errors.New("host-degraded is present")
	}
	return nil
}

// Begin cleans up a completed, eligible earlier routine run under the same
// lock, or refuses to start a second run while any retained state is uncertain.
func (l *Lane) Begin(group int, observed bool, now time.Time) (string, error) {
	if err := l.healthy(); err != nil {
		return "", err
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		return "", err
	}
	for _, entry := range entries {
		name := strings.TrimPrefix(entry.Name(), cleanupPrefix)
		if runName(name) {
			if err := l.Cleanup(name, false, now); err != nil {
				return "", err
			}
		}
	}
	if group <= 1 {
		return "", errors.New("expected an isolated fixture process group")
	}
	run, err := os.MkdirTemp(l.dir, "run-")
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(runRecord{Boot: l.boot, Group: group, Started: now.UTC(), Observed: observed})
	if err != nil {
		return "", err
	}
	return run, os.WriteFile(filepath.Join(run, "run.json"), raw, 0600)
}

func (l *Lane) Finish(run string, now time.Time) error {
	return os.WriteFile(filepath.Join(run, "finished"), []byte(now.UTC().Format(time.RFC3339Nano)), 0600)
}

func (l *Lane) Cleanup(name string, observed bool, now time.Time) error {
	return l.cleanup(name, observed, now, groupGone, os.RemoveAll)
}

func (l *Lane) cleanup(name string, observed bool, now time.Time, gone func(int) (bool, error), remove func(string) error) error {
	if !runName(name) {
		return errors.New("expected the exact retained run name")
	}
	if err := l.healthy(); err != nil {
		return err
	}
	path := filepath.Join(l.dir, name)
	reap := filepath.Join(l.dir, cleanupPrefix+name)
	if err := ownedDir(reap, true); err == nil {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			return fmt.Errorf("retained codesign run %s has conflicting cleanup state", name)
		}
		return remove(reap)
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := ownedDir(path, true); err != nil {
		return err
	}
	record, err := readRun(path)
	if err != nil || record.Started.After(now) {
		return fmt.Errorf("retained codesign run %s has unknown state", name)
	}
	if record.Observed && !observed {
		return fmt.Errorf("retained codesign run %s requires observed cleanup", name)
	}
	if record.Boot == l.boot {
		exited, err := gone(record.Group)
		if err != nil || !exited {
			return fmt.Errorf("retained codesign run %s has a live or unknown process group", name)
		}
	}
	if !observed {
		ageFrom := record.Started
		raw, err := readState(path, "finished")
		switch {
		case err == nil:
			ageFrom, err = time.Parse(time.RFC3339Nano, string(raw))
			if err != nil || ageFrom.Before(record.Started) {
				return fmt.Errorf("retained codesign run %s has an invalid finish record", name)
			}
		case !os.IsNotExist(err) || record.Boot == l.boot:
			return fmt.Errorf("retained codesign run %s has no known finish", name)
		}
		if now.Sub(ageFrom) < minimumRetention {
			return fmt.Errorf("retained codesign run %s is still within its 10-minute retention period", name)
		}
	}
	if err := l.healthy(); err != nil {
		return err
	}
	// Record that the checks passed before deletion. If RemoveAll is
	// interrupted after removing metadata, the next cleanup can still finish.
	if err := os.Rename(path, reap); err != nil {
		return err
	}
	return remove(reap)
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

func groupGone(group int) (bool, error) {
	err := syscall.Kill(-group, 0)
	if errors.Is(err, syscall.ESRCH) {
		return true, nil
	}
	return false, err
}
