package keyvault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"sync"
	"syscall"
	"time"

	"golang.org/x/crypto/ssh"
)

// sshsigMagic starts the blob that ssh-keygen -Y sign hands to an agent
// (OpenSSH PROTOCOL.sshsig, "signed data"). An authentication request starts
// with a length-prefixed session identifier instead.
const sshsigMagic = "SSHSIG"

var sshsigNamespacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9@._-]{0,63}$`)

var errNotSSHSig = errors.New("request is not an SSHSIG signature")

// SSHSig is the public header of an SSHSIG request: the namespace and the
// hash of the message. The message itself never reaches the agent.
type SSHSig struct {
	Namespace     string
	HashAlgorithm string
	MessageHash   []byte
}

// ValidSSHSigNamespace accepts the namespaces the agent can be restricted to.
func ValidSSHSigNamespace(namespace string) bool {
	return sshsigNamespacePattern.MatchString(namespace)
}

// ParseSSHSig strictly parses the signed-data blob of ssh-keygen -Y sign:
// the magic, a valid namespace, an empty reserved field, sha256 or sha512 and
// a hash of exactly that length, with nothing after it.
func ParseSSHSig(data []byte) (SSHSig, error) {
	if !bytes.HasPrefix(data, []byte(sshsigMagic)) {
		return SSHSig{}, errNotSSHSig
	}
	var blob struct {
		Namespace     string
		Reserved      string
		HashAlgorithm string
		Hash          []byte
		Rest          []byte `ssh:"rest"`
	}
	if ssh.Unmarshal(data[len(sshsigMagic):], &blob) != nil || len(blob.Rest) != 0 || blob.Reserved != "" || !ValidSSHSigNamespace(blob.Namespace) {
		return SSHSig{}, errNotSSHSig
	}
	size := map[string]int{"sha256": 32, "sha512": 64}[blob.HashAlgorithm]
	if size == 0 || len(blob.Hash) != size {
		return SSHSig{}, errNotSSHSig
	}
	return SSHSig{Namespace: blob.Namespace, HashAlgorithm: blob.HashAlgorithm, MessageHash: blob.Hash}, nil
}

// Audit outcomes and refusal reasons.
const (
	SSHAuditSigned  = "signed"
	SSHAuditRefused = "refused"
)

// SSHAuditRecord is one line of the agent's audit log. It holds public
// metadata and hash prefixes, never the signed data or the message.
type SSHAuditRecord struct {
	Time              string `json:"time"`
	Outcome           string `json:"outcome"`
	Reason            string `json:"reason,omitempty"`
	Address           string `json:"address,omitempty"`
	Version           int    `json:"version,omitempty"`
	Fingerprint       string `json:"fingerprint,omitempty"`
	Namespace         string `json:"namespace,omitempty"`
	HashAlgorithm     string `json:"hash_algorithm,omitempty"`
	MessageHashPrefix string `json:"message_hash_prefix,omitempty"`
	DigestPrefix      string `json:"digest_prefix"`
	ClientPID         int    `json:"client_pid,omitempty"`
}

// sshHashPrefix is enough to correlate a record with a signature or a git
// object without storing the full value.
func sshHashPrefix(hash []byte) string {
	if len(hash) > 8 {
		hash = hash[:8]
	}
	return hex.EncodeToString(hash)
}

// SSHAuditLog appends one JSON line per record to a private file. A write
// or sync that fails is reported, so the agent withholds the signature it
// covers, and it disables the log for good: a partly written line is never
// continued by a later record.
type SSHAuditLog struct {
	mu     sync.Mutex
	file   *os.File
	write  func([]byte) (int, error)
	sync   func() error
	broken bool
}

// OpenSSHAuditLog opens or creates an append-only 0600 file owned by the
// current user and holds an exclusive lock on it until Close. It refuses
// symlinks, hard links, files others can write, a file another agent holds,
// a file whose last record is incomplete, and a file it cannot sync.
func OpenSSHAuditLog(path string) (*SSHAuditLog, error) {
	return openSSHAuditLog(path, (*os.File).Sync, nil)
}

// openSSHAuditLog takes the sync function and a hook that runs just before
// the lock is taken; tests use them to inject faults and races.
func openSSHAuditLog(path string, syncFile func(*os.File) error, beforeLock func()) (*SSHAuditLog, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("SSH audit log path must be absolute")
	}
	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND|os.O_CREATE|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, errors.New("cannot open SSH audit log")
	}
	st, err := file.Stat()
	if err != nil {
		file.Close()
		return nil, errors.New("cannot inspect SSH audit log")
	}
	stat, ok := st.Sys().(*syscall.Stat_t)
	if !ok || !st.Mode().IsRegular() || stat.Uid != uint32(os.Getuid()) || st.Mode().Perm()&0077 != 0 || stat.Nlink != 1 {
		file.Close()
		return nil, errors.New("SSH audit log must be a regular 0600 file owned by you with one link")
	}
	if beforeLock != nil {
		beforeLock()
	}
	// One agent per log: a second writer could continue a line the first
	// one left incomplete. The lock is released when the file is closed.
	if syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB) != nil {
		file.Close()
		return nil, errors.New("SSH audit log is in use by another agent")
	}
	// The previous holder may have written until it released the lock, so
	// the tail is checked against the size seen under the lock.
	if st, err = file.Stat(); err != nil {
		file.Close()
		return nil, errors.New("cannot inspect SSH audit log")
	}
	if st.Size() > 0 {
		last := make([]byte, 1)
		if _, err := file.ReadAt(last, st.Size()-1); err != nil || last[0] != '\n' {
			file.Close()
			return nil, errors.New("SSH audit log ends with an incomplete record; inspect it before reuse")
		}
	}
	if err := syncFile(file); err != nil {
		file.Close()
		return nil, errors.New("SSH audit log cannot be synced")
	}
	return &SSHAuditLog{file: file, write: file.Write, sync: func() error { return syncFile(file) }}, nil
}

// Append writes and syncs one record as a single line.
func (l *SSHAuditLog) Append(record SSHAuditRecord) error {
	line, err := json.Marshal(record)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.broken {
		return errors.New("SSH audit log failed earlier")
	}
	if _, err := l.write(append(line, '\n')); err != nil {
		l.broken = true
		return err
	}
	if err := l.sync(); err != nil {
		l.broken = true
		return err
	}
	return nil
}

func (l *SSHAuditLog) Close() error { return l.file.Close() }

func sshAuditTime() string { return sshNow().UTC().Format(time.RFC3339Nano) }
