package codesigntest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

type cleanupRecord struct {
	Name             string
	Run              runRecord
	Approved, Exited time.Time
	Device, Inode    uint64
}

func (l *Lane) Cleanup(name string, observed bool, now time.Time) error {
	return l.cleanup(name, observed, now, groupGone, os.RemoveAll)
}

func (l *Lane) cleanup(name string, observed bool, now time.Time, gone func(int) (bool, error), remove func(string) error) error {
	if !runName(name) {
		return errors.New("expected the exact retained run name")
	}
	if err := healthy(l.dir); err != nil {
		return err
	}
	path := filepath.Join(l.dir, name)
	approval := cleanupPrefix + name + ".json"
	raw, err := readState(l.dir, approval)
	switch {
	case err == nil:
		return l.resumeCleanup(path, approval, now, raw, remove)
	case !os.IsNotExist(err):
		return err
	}
	if err := ownedDir(path, true); err != nil {
		return err
	}
	record, err := readRun(path)
	if err != nil || record.Started.After(now) {
		return fmt.Errorf("retained codesign run %s has unknown state", name)
	}
	if record.Observed != observed {
		return fmt.Errorf("cleanup mode does not match retained codesign run %s", name)
	}
	exited := now
	if observed {
		if record.Boot == l.boot {
			if err := requireGroupGone(record.Group, gone); err != nil {
				return fmt.Errorf("retained codesign run %s: %w", name, err)
			}
		}
	} else {
		exited, err = l.exitBoundary(path, record, now, gone)
		if err != nil {
			return fmt.Errorf("retained codesign run %s: %w", name, err)
		}
		if now.Sub(exited) < minimumRetention {
			return fmt.Errorf("retained codesign run %s is still within its 10-minute post-exit retention period", name)
		}
	}
	dev, ino, err := dirIdentity(path)
	if err != nil {
		return err
	}
	raw, err = json.Marshal(cleanupRecord{Name: name, Run: record, Exited: exited, Approved: now, Device: dev, Inode: ino})
	if err != nil {
		return err
	}
	if err := writeState(filepath.Join(l.dir, approval), raw); err != nil {
		return err
	}
	return l.resumeCleanup(path, approval, now, raw, remove)
}

// The sidecar survives an interrupted removal and binds the approved decision
// to one directory inode. A replacement directory never inherits approval.
func (l *Lane) resumeCleanup(path, approval string, now time.Time, raw []byte, remove func(string) error) error {
	var record cleanupRecord
	if err := json.Unmarshal(raw, &record); err != nil ||
		record.Name != filepath.Base(path) || record.Run.Boot == "" ||
		record.Run.Group <= 1 || record.Run.Started.IsZero() ||
		record.Exited.Before(record.Run.Started) || record.Approved.Before(record.Exited) ||
		record.Approved.After(now) || record.Inode == 0 ||
		(!record.Run.Observed && record.Approved.Sub(record.Exited) < minimumRetention) {
		return errors.New("invalid retained cleanup authorization")
	}
	dev, ino, err := dirIdentity(path)
	switch {
	case err == nil && (dev != record.Device || ino != record.Inode):
		return errors.New("retained cleanup directory identity changed")
	case err != nil && !os.IsNotExist(err):
		return err
	}
	if err := healthy(l.dir); err != nil {
		return err
	}
	if ino != 0 {
		if err := remove(path); err != nil {
			return err
		}
	}
	return os.Remove(filepath.Join(l.dir, approval))
}

func dirIdentity(path string) (uint64, uint64, error) {
	if err := ownedDir(path, true); err != nil {
		return 0, 0, err
	}
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		return 0, 0, err
	}
	return uint64(st.Dev), uint64(st.Ino), nil
}
