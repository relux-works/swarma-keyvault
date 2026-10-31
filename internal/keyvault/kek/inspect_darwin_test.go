//go:build darwin && cgo

package kek

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

// fixtureClient connects to the socket named by its first argument and
// waits for the server to close the connection.
const fixtureClient = `package main

import (
	"net"
	"os"
	"strconv"
	"syscall"
)

func main() {
	if len(os.Args) == 3 && os.Args[1] == "inherited" {
		fd, err := strconv.Atoi(os.Args[2]); if err != nil { os.Exit(2) }
		f := os.NewFile(uintptr(fd), "inherited-socket")
		f.Write([]byte{'r'})
		f.Read(make([]byte,1))
		return
	}
	c, err := net.Dial("unix", os.Args[1])
	if err != nil {
		os.Exit(1)
	}
	buf := make([]byte, 1)
	c.Read(buf)
	if len(os.Args) == 3 {
		f, err := c.(*net.UnixConn).File(); if err != nil { os.Exit(3) }
		fd := f.Fd()
		if _,_,errno := syscall.Syscall(syscall.SYS_FCNTL,fd,syscall.F_SETFD,0); errno!=0 { os.Exit(4) }
		if err := syscall.Exec(os.Args[2], []string{os.Args[2],"inherited",strconv.Itoa(int(fd))}, os.Environ()); err!=nil { os.Exit(5) }
	}
}
`

const getTaskAllow = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
`

// buildSigned builds the fixture client once per test and signs a copy per
// variant with codesign's ad-hoc identity (no Keychain is used).
func buildSigned(t *testing.T, dir, name string, signArgs ...string) string {
	t.Helper()
	src := filepath.Join(dir, "src")
	if _, err := os.Stat(filepath.Join(src, "client")); os.IsNotExist(err) {
		os.MkdirAll(src, 0o700)
		os.WriteFile(filepath.Join(src, "main.go"), []byte(fixtureClient), 0o600)
		os.WriteFile(filepath.Join(src, "go.mod"), []byte("module fixture\n\ngo 1.25\n"), 0o600)
		cmd := exec.Command("go", "build", "-o", "client", ".")
		cmd.Dir = src
		cmd.Env = append(os.Environ(), "GOWORK=off", "GOFLAGS=")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("build fixture: %v\n%s", err, out)
		}
	}
	path := filepath.Join(dir, name)
	data, _ := os.ReadFile(filepath.Join(src, "client"))
	os.WriteFile(path, data, 0o700)
	args := append([]string{"--force", "--sign", "-", "--identifier", "works.relux.kek-fixture." + name}, signArgs...)
	if out, err := exec.Command("/usr/bin/codesign", append(args, path)...).CombinedOutput(); err != nil {
		t.Fatalf("codesign %s: %v\n%s", name, err, out)
	}
	return path
}

// A public Apple binary supplies real validated certificate facts without a
// signing identity or Keychain access. codesign extracts its public DER and
// identifier independently, Go hashes/parses that DER, and both exact and
// mismatched certificate/identifier bindings exercise those native facts.
// The exec-level wrapper also denies trustd: its known trust refusal must
// expose no attested facts. The positive fixture additionally runs after the
// read-only canary with the init-level gate (Keychain denied, trustd allowed).
// Both lanes are required; the wrapper refusal is not certificate coverage.
// This is a file fixture, not a signed-proxy socket or release-key test.
func TestCodeInspectorPublicCertificate(t *testing.T) {
	const path = "/usr/bin/true"
	t.Logf("native fixture gate: Applied=%v Confined=%v", keychaingate.Applied(), keychaingate.Confined())
	id, err := (CodeInspector{}).File(path)
	if err != nil && keychaingate.Confined() && err.Error() == "code identity of /usr/bin/true: OSStatus -2147409622" {
		if id != (CodeIdentity{}) {
			t.Fatalf("confined trust refusal exposed facts: %+v", id)
		}
		t.Log("wrapper denies trustd; exact trust refusal and zero attested facts verified; certificate positive remains a separate required lane")
		return
	}
	if err != nil || !id.Valid || id.CertificateSHA1 == "" || id.Identifier == "" {
		t.Fatalf("public code identity = %+v, %v", id, err)
	}
	dir := privateTemp(t)
	prefix := filepath.Join(dir, "cert")
	out, err := exec.Command("/usr/bin/codesign", "--display", "--extract-certificates="+prefix, "--verbose=4", path).CombinedOutput()
	if err != nil {
		t.Fatalf("extract public signature: %v\n%s", err, out)
	}
	der, err := os.ReadFile(prefix + "0")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		t.Fatalf("public leaf DER: %v", err)
	}
	digest := sha1.Sum(der)
	if id.CertificateSHA1 != hex.EncodeToString(digest[:]) {
		t.Fatalf("native certificate differs from public DER: %+v", id)
	}
	identifierLine := regexp.MustCompile(`(?m)^Identifier=(.+)$`).FindSubmatch(out)
	if len(identifierLine) != 2 || id.Identifier != string(identifierLine[1]) {
		t.Fatalf("native identifier differs: %+v\n%s", id, out)
	}
	for name, pins := range map[string][2]string{
		"exact":             {id.Identifier, id.CertificateSHA1},
		"other certificate": {id.Identifier, strings.Repeat("0", 40)},
		"other identifier":  {"other.identifier", id.CertificateSHA1},
	} {
		req, err := kekclient.RequirementForCertificate(pins[0], pins[1])
		if err != nil {
			t.Fatal(err)
		}
		if id.matches(req) != (name == "exact") {
			t.Fatalf("%s binding verdict wrong", name)
		}
	}
	t.Log("validated public certificate/identifier, independent public DER SHA-1, exact positive and both pin/identifier mismatches PASS")
	t.Run("signed public socket peer", func(t *testing.T) {
		// The shipped curl connects only to this owned Unix socket. Disable
		// curlrc and proxy selection; no TLS, cookies, network endpoint or key.
		const binary = "/usr/bin/curl"
		file, err := (CodeInspector{}).File(binary)
		if err != nil || !file.Valid || file.CertificateSHA1 == "" || file.Identifier == "" {
			t.Fatalf("public curl identity: %+v %v", file, err)
		}
		sock := filepath.Join(privateTemp(t), "signed.sock")
		l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
		if err != nil {
			t.Fatal(err)
		}
		defer l.Close()
		l.SetDeadline(time.Now().Add(5 * time.Second))
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, binary, "--disable", "--silent", "--show-error", "--max-time", "5", "--noproxy", "*", "--proxy", "", "--unix-socket", sock, "http://localhost/")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Logf("owned public Unix-socket fixture PID%d", cmd.Process.Pid)
		defer func() {
			if err := cmd.Wait(); err != nil {
				t.Errorf("public socket fixture PID%d: %v %s", cmd.Process.Pid, err, &stderr)
			}
		}()
		conn, err := l.AcceptUnix()
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(5 * time.Second))
		peer, err := (CodeInspector{}).Peer(conn)
		if err != nil || peer != file {
			t.Fatalf("signed peer %+v %v differs from validated file %+v", peer, err, file)
		}
		for name, pins := range map[string][2]string{"exact": {file.Identifier, file.CertificateSHA1}, "wrong certificate": {file.Identifier, strings.Repeat("0", 40)}, "wrong identifier": {"other.identifier", file.CertificateSHA1}} {
			req, err := kekclient.RequirementForCertificate(pins[0], pins[1])
			if err != nil {
				t.Fatal(err)
			}
			if peer.matches(req) != (name == "exact") {
				t.Fatalf("native peer %s verdict wrong", name)
			}
		}
		if _, err := conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")); err != nil {
			t.Fatal(err)
		}
		t.Log("actual audit-token public signed peer: exact certificate+identifier match and both mismatch refusals PASS; this is not a proxy hardening/adoption test")
	})
}

// A real owned ad-hoc process execs a separately signed image while preserving
// its connected socket. The second audit-token observation must fail or report
// changed code; the server's paired fake-observation tests prove its refusal.
// This does not prevent an exec after the final observation.
func TestCodeInspectorPeerExec(t *testing.T) {
	dir := privateTemp(t)
	first := buildSigned(t, dir, "before-exec", "--options", "runtime,library")
	second := buildSigned(t, dir, "after-exec", "--options", "runtime,library")
	sock := filepath.Join(dir, "exec.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, first, sock, second)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Logf("owned exec fixture PID%d", cmd.Process.Pid)
	defer func() {
		if err := cmd.Wait(); err != nil {
			t.Errorf("owned exec fixture PID%d: %v: %s", cmd.Process.Pid, err, &stderr)
		}
	}()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	before, err := (CodeInspector{}).Peer(conn)
	if err != nil || before.Problem() != "" {
		t.Fatalf("before exec: %+v %v", before, err)
	}
	if before.CDHash != codesignCDHash(t, first) {
		t.Fatal("wrong initial code identity")
	}
	if _, err := conn.Write([]byte{'x'}); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if n, err := conn.Read(ready[:]); err != nil || n != 1 || ready[0] != 'r' {
		t.Fatalf("post-exec acknowledgement: %d %v %q", n, err, ready)
	}
	after, err := (CodeInspector{}).Peer(conn)
	if err == nil && after == before {
		t.Fatalf("exec kept an unchanged peer observation: %+v", after)
	}
	if err == nil && after.CDHash != codesignCDHash(t, second) {
		t.Fatalf("unexpected new code identity: %+v", after)
	}
	t.Log(fmt.Sprintf("real exec: initial %s; subsequent %+v, %v", before.CDHash, after, err))
}

var cdhashLine = regexp.MustCompile(`(?m)^CDHash=([0-9a-f]{40})$`)

func codesignCDHash(t *testing.T, path string) string {
	t.Helper()
	out, _ := exec.Command("/usr/bin/codesign", "-dvvv", path).CombinedOutput()
	m := cdhashLine.FindSubmatch(out)
	if m == nil {
		t.Fatalf("no CDHash for %s:\n%s", path, out)
	}
	return string(m[1])
}

// peerOf runs the binary as a client of a fresh socket and identifies it
// from the server side by audit token.
func peerOf(t *testing.T, dir, binary string) (CodeIdentity, error) {
	t.Helper()
	sock := filepath.Join(dir, "p.sock")
	os.Remove(sock)
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	cmd := exec.Command(binary, sock)
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return CodeInspector{}.Peer(conn)
}

// The inspector reads what codesign wrote: the cdhash codesign prints, the
// hardened-runtime and library-validation flags, and get-task-allow, both
// for a file and for the same binary running as a socket peer. A copy with
// one byte changed after signing is not valid. The runtime,library variant
// without the entitlement is the positive control.
func TestCodeInspectorReadsSignatures(t *testing.T) {
	dir, err := os.MkdirTemp("", "ki")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	ents := filepath.Join(dir, "gta.plist")
	os.WriteFile(ents, []byte(getTaskAllow), 0o600)
	variants := []struct {
		name  string
		args  []string
		want  CodeIdentity
		bound bool
	}{
		{"hardened", []string{"--options", "runtime,library"}, CodeIdentity{Valid: true, Runtime: true, LibraryValidation: true}, true},
		{"plain", nil, CodeIdentity{Valid: true}, false},
		{"runtime-only", []string{"--options", "runtime"}, CodeIdentity{Valid: true, Runtime: true}, false},
		{"debuggable", []string{"--options", "runtime,library", "--entitlements", ents}, CodeIdentity{Valid: true, Runtime: true, LibraryValidation: true, GetTaskAllow: true}, false},
	}
	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			path := buildSigned(t, dir, v.name, v.args...)
			v.want.CDHash = codesignCDHash(t, path)
			v.want.Identifier = "works.relux.kek-fixture." + v.name
			file, err := CodeInspector{}.File(path)
			if err != nil || file != v.want {
				t.Fatalf("file = %+v, %v; want %+v", file, err, v.want)
			}
			if (file.Problem() == "") != v.bound {
				t.Fatalf("problem %q for %s", file.Problem(), v.name)
			}
			peer, err := peerOf(t, dir, path)
			if err != nil || peer != v.want {
				t.Fatalf("peer = %+v, %v; want %+v", peer, err, v.want)
			}
		})
	}
	t.Run("changed after signing", func(t *testing.T) {
		path := buildSigned(t, dir, "changed", "--options", "runtime,library")
		data, _ := os.ReadFile(path)
		data[len(data)/2] ^= 1
		os.WriteFile(path, data, 0o700)
		file, err := CodeInspector{}.File(path)
		if err == nil && file.Valid {
			t.Fatalf("a changed binary is valid: %+v", file)
		}
		if file.Identifier != "" || file.CertificateSHA1 != "" || file.CDHash != "" {
			t.Fatalf("invalid code returned attested facts: %+v", file)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		path := buildSigned(t, dir, "target", "--options", "runtime,library")
		link := filepath.Join(dir, "link")
		os.Symlink(path, link)
		if id, err := (CodeInspector{}).File(link); err == nil {
			t.Fatalf("a symlink was identified: %+v", id)
		}
	})
}
