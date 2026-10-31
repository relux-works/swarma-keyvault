package kek

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// AuditEntry is one answered or refused request. It never holds a KEK or a
// payload: only who asked, for what, and what the broker did.
type AuditEntry struct {
	Time       time.Time `json:"time"`
	Op         string    `json:"op"`
	Address    string    `json:"address"`
	Generation int       `json:"generation,omitempty"`
	// Caller is the peer's cdhash, empty when it could not be identified.
	Caller  string `json:"caller,omitempty"`
	Verdict string `json:"verdict"`
	Code    string `json:"code,omitempty"`
	// Requirement is the new binding of an answered rebind.
	Requirement string `json:"requirement,omitempty"`
	// Prev is the SHA-256 of the previous line, or 64 zeros for the first.
	Prev string `json:"prev"`
}

// genesis is Prev of the first entry.
var genesis = hex.EncodeToString(make([]byte, sha256.Size))

// Audit is an append-only JSON-lines log in which every line names the hash
// of the line before it, so a removed or edited line breaks the chain. It
// shows a same-user change; it cannot prevent one.
type Audit struct {
	Path string
}

// DefaultAuditPath is the broker's log in the user's Application Support.
func DefaultAuditPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, "Library", "Application Support", "mac-keyvault-kek", "audit.jsonl"), nil
}

// Append writes entry at now, chained to the last line, and syncs it.
func (a *Audit) Append(entry AuditEntry, now time.Time) error {
	if a == nil || a.Path == "" {
		return errors.New("no audit log configured")
	}
	dir := filepath.Dir(a.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if err := privateDir(dir); err != nil {
		return err
	}
	f, err := os.OpenFile(a.Path, os.O_RDWR|os.O_CREATE|os.O_APPEND|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		return err
	}
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("audit log %s is not a private regular file", a.Path)
	}
	prev, err := lastHash(f)
	if err != nil {
		return err
	}
	entry.Time, entry.Prev = now.UTC(), prev
	line, err := json.Marshal(entry)
	if err != nil {
		return err
	}
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	return syncFile(f)
}

// syncFile makes an appended entry durable before the broker answers; tests
// replace it to prove a failed sync answers nothing.
var syncFile = func(f *os.File) error { return f.Sync() }

// lastHash hashes the last complete line, or returns genesis for an empty
// log. A log whose last line is torn is refused rather than chained over.
func lastHash(f *os.File) (string, error) {
	data, err := os.ReadFile(f.Name())
	if err != nil {
		return "", err
	}
	if len(data) == 0 {
		return genesis, nil
	}
	if data[len(data)-1] != '\n' {
		return "", errors.New("the audit log ends in a torn line")
	}
	data = data[:len(data)-1]
	last := data[bytes.LastIndexByte(data, '\n')+1:]
	sum := sha256.Sum256(last)
	return hex.EncodeToString(sum[:]), nil
}

// Verify reads the log and checks every link of the chain under the same
// framing Append requires: every entry is one complete line ending in a
// newline, so a log Append would refuse never verifies. It returns the
// number of entries and the chain head, the hash of the last line. The
// chain shows an edit inside the log; a same-user rewrite of the whole log
// passes it, so the head is posted with every window record and compared
// with the posted one later.
func (a *Audit) Verify() (int, string, error) {
	info, err := os.Lstat(a.Path)
	if err != nil {
		return 0, "", err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return 0, "", fmt.Errorf("%s is not a private regular file", a.Path)
	}
	data, err := os.ReadFile(a.Path)
	if err != nil {
		return 0, "", err
	}
	if len(data) > 0 && data[len(data)-1] != '\n' {
		return 0, "", errors.New("the audit log ends in a torn line")
	}
	prev, n := genesis, 0
	for _, line := range bytes.Split(bytes.TrimSuffix(data, []byte("\n")), []byte("\n")) {
		if len(data) == 0 {
			break
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err != nil {
			return n, "", fmt.Errorf("line %d: %v", n+1, err)
		}
		if entry.Prev != prev {
			return n, "", fmt.Errorf("line %d does not follow line %d", n+1, n)
		}
		sum := sha256.Sum256(line)
		prev, n = hex.EncodeToString(sum[:]), n+1
	}
	return n, prev, nil
}

func privateDir(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	if !info.IsDir() || info.Mode().Perm()&0o077 != 0 || !ok || int(st.Uid) != os.Getuid() {
		return fmt.Errorf("%s is not a private directory of this user", dir)
	}
	return nil
}
