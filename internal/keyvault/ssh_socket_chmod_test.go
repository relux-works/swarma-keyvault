package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// The overlay calls this hook immediately after a successful chmod. Keeping
// instrumentation in the test avoids adding mutable hooks to the SSH agent.
var sshSocketAfterChmodTestHook func(string, *net.UnixListener)

// Claim: if the path disappears or its inode changes after chmod, ListenSSH
// returns no listener or cleanup, closes its listener, and preserves the foreign
// entry. The unchanged control still succeeds and cleans up. A temporary source
// overlay provides a deterministic scheduling point; no production file changes.
func TestSSHAgentSwapAfterChmod(t *testing.T) {
	_, here, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate package source")
	}
	sourcePath := filepath.Join(filepath.Dir(here), "ssh_agent.go")
	source, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	const point = "\t// chmod changes the change time; record the final identity.\n"
	if bytes.Count(source, []byte(point)) != 1 {
		t.Fatal("cannot identify unique post-chmod instrumentation point")
	}
	instrumented := bytes.Replace(source, []byte(point), []byte("\tsshSocketAfterChmodTestHook(path, listener)\n"+point), 1)
	dir := t.TempDir()
	replacement := filepath.Join(dir, "ssh_agent.go")
	if err := os.WriteFile(replacement, instrumented, 0600); err != nil {
		t.Fatal(err)
	}
	overlay, err := json.Marshal(struct{ Replace map[string]string }{map[string]string{sourcePath: replacement}})
	if err != nil {
		t.Fatal(err)
	}
	overlayPath := filepath.Join(dir, "overlay.json")
	if err := os.WriteFile(overlayPath, overlay, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, "go", "test", "-p", "2", "-overlay", overlayPath, "-count=1", "-run", "^TestSSHAgentSwapAfterChmodOverlay$", "-v", ".")
	cmd.WaitDelay = 5 * time.Second
	cmd.Dir = filepath.Dir(here)
	cmd.Env = append(os.Environ(), "GOMAXPROCS=2", "MAC_KEYVAULT_SKIP_KEYCHAIN=1", "KEYVAULT_SSH_CHMOD_OVERLAY=1")
	out, err := cmd.CombinedOutput()
	t.Logf("post-chmod overlay test:\n%s", out)
	if err != nil {
		t.Fatalf("post-chmod overlay test failed: %v", err)
	}
}

// This helper runs only in the instrumented child, never against native custody.
func TestSSHAgentSwapAfterChmodOverlay(t *testing.T) {
	if os.Getenv("KEYVAULT_SSH_CHMOD_OVERLAY") != "1" {
		t.Skip("requires the temporary post-chmod source overlay")
	}
	for _, kind := range []string{"unchanged", "missing", "foreign-file", "foreign-socket"} {
		t.Run(kind, func(t *testing.T) {
			path := filepath.Join(sshTempDir(t), "private", "agent.sock")
			var captured *net.UnixListener
			var foreign *net.UnixListener
			sshSocketAfterChmodTestHook = func(path string, listener *net.UnixListener) {
				captured = listener
				t.Cleanup(func() { listener.Close() })
				st, err := os.Lstat(path)
				if err != nil || st.Mode().Perm() != 0600 {
					t.Fatal("hook did not run after chmod", err)
				}
				if kind == "unchanged" {
					return
				}
				// Rename keeps the original inode allocated, so replacements
				// cannot reuse it even on filesystems that recycle inodes fast.
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				switch kind {
				case "foreign-file":
					if err := os.WriteFile(path, []byte("foreign"), 0600); err != nil {
						t.Fatal(err)
					}
				case "foreign-socket":
					foreign, err = net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
					if err != nil {
						t.Fatal(err)
					}
					foreign.SetUnlinkOnClose(false)
					t.Cleanup(func() { foreign.Close() })
				}
			}
			t.Cleanup(func() { sshSocketAfterChmodTestHook = nil })
			ln, cleanup, err := ListenSSH(path)
			if ln != nil {
				t.Cleanup(func() { ln.Close() })
			}
			if captured == nil {
				t.Fatal("post-chmod point was not reached")
			}
			if kind == "unchanged" {
				if err != nil || ln != captured || cleanup == nil {
					t.Fatal("unchanged socket refused", err)
				}
				cleanup()
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("unchanged socket not removed", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), "cannot inspect SSH socket") || ln != nil || cleanup != nil {
				t.Fatalf("changed path accepted: listener %v, cleanup present %t, error %v", ln, cleanup != nil, err)
			}
			// A deadline prevents a leaked listener from hanging the test.
			captured.SetDeadline(time.Now().Add(time.Second))
			conn, acceptErr := captured.AcceptUnix()
			if conn != nil {
				conn.Close()
			}
			if !errors.Is(acceptErr, net.ErrClosed) {
				t.Fatal("failed setup left listener open", acceptErr)
			}
			switch kind {
			case "missing":
				if _, err := os.Lstat(path); !os.IsNotExist(err) {
					t.Fatal("missing path was recreated", err)
				}
			case "foreign-file":
				data, err := os.ReadFile(path)
				if err != nil || string(data) != "foreign" {
					t.Fatal("failure removed or changed foreign file", err)
				}
			case "foreign-socket":
				if st, err := os.Lstat(path); err != nil || st.Mode()&os.ModeSocket == 0 {
					t.Fatal("failure removed foreign socket", err)
				}
				foreign.SetDeadline(time.Now().Add(time.Second))
				client, err := net.DialTimeout("unix", path, time.Second)
				if err != nil {
					t.Fatal("foreign socket no longer reachable", err)
				}
				defer client.Close()
				server, err := foreign.AcceptUnix()
				if err != nil {
					t.Fatal("foreign listener no longer usable", err)
				}
				server.Close()
			}
		})
	}
}
