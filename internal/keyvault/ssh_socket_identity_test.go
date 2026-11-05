package keyvault

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Claim: cleanup unlinks only the exact socket it recorded. The recorded
// socket itself is owned (positive control); a regular file with the same
// device and inode, the same socket with another change time, another
// inode or another device, and a recorded identity that is not a socket are
// all refused. The rule does not depend on the platform reusing inodes, so
// it holds on macOS as well as Linux.
func TestSSHSocketIdentityOwns(t *testing.T) {
	base := socketIdentity{dev: 7, ino: 42, mode: unix.S_IFSOCK | 0600, ctime: unix.Timespec{Sec: 100, Nsec: 5}}
	if !base.owns(base) {
		t.Fatal("recorded socket not owned")
	}
	regular := base
	regular.mode = unix.S_IFREG | 0600
	later := base
	later.ctime.Nsec++
	otherIno := base
	otherIno.ino++
	otherDev := base
	otherDev.dev++
	for name, c := range map[string]socketIdentity{"regular-file": regular, "later-ctime": later, "other-inode": otherIno, "other-device": otherDev} {
		if base.owns(c) {
			t.Error("foreign entry owned", name)
		}
	}
	if regular.owns(regular) {
		t.Error("non-socket recorded identity owns itself")
	}
}

// Claim: a foreign socket bound at our path after our socket was unlinked
// survives our cleanup. Limit: on a filesystem that does not reuse the
// inode at once (macOS APFS) this passes even with an inode-only check; the
// unit test above witnesses the rule independently of the platform.
func TestSSHAgentCleanupKeepsForeignSocket(t *testing.T) {
	path := filepath.Join(sshTempDir(t), "private", "agent.sock")
	ln, cleanup, err := ListenSSH(path)
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
	os.Remove(path)
	foreign, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer foreign.Close()
	cleanup()
	st, err := os.Lstat(path)
	if err != nil || st.Mode()&os.ModeSocket == 0 {
		t.Fatal("cleanup removed foreign socket", err)
	}
}

// Claim: cleanup still removes the socket this listener made, after the
// final chmod and after a client connected, so a restart can bind the path
// again (positive control for the identity rule).
func TestSSHAgentCleanupRemovesOwnSocket(t *testing.T) {
	path := filepath.Join(sshTempDir(t), "private", "agent.sock")
	ln, cleanup, err := ListenSSH(path)
	if err != nil {
		t.Fatal(err)
	}
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if s, err := ln.Accept(); err == nil {
		s.Close()
	}
	c.Close()
	cleanup()
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("own socket left behind", err)
	}
	ln2, cleanup2, err := ListenSSH(path)
	if err != nil {
		t.Fatal("rebind after cleanup refused", err)
	}
	ln2.Close()
	cleanup2()
}
