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
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/codesigntest"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/keychaingate"
	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

const getTaskAllow = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>com.apple.security.get-task-allow</key><true/></dict></plist>
`

var kekClientBuild codesigntest.BuildOnce

// buildSigned builds the fixture client once per run and ad-hoc signs a copy per variant.
func buildSigned(t *testing.T, run, dir, name string, signArgs ...string) string {
	t.Helper()
	client, err := kekClientBuild.Get(func() (string, error) {
		src, err := os.MkdirTemp(run, "kek-base-")
		if err != nil {
			return "", err
		}
		cmd := exec.Command(filepath.Join(runtime.GOROOT(), "bin", "go"), "build", "-p", "1", "-o", filepath.Join(src, "client"), "./testdata/codesignclient")
		if out, err := codesigntest.NativeOutput(t, "build KEK socket client", cmd); err != nil {
			return "", fmt.Errorf("build fixture: %w\n%s", err, out)
		}
		return filepath.Join(src, "client"), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(client)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, data, 0700); err != nil {
		t.Fatal(err)
	}
	args := append([]string{"--force", "--sign", "-", "--identifier", "works.relux.kek-fixture." + name}, signArgs...)
	if out, err := codesigntest.NativeOutput(t, "sign KEK socket client", exec.Command("/usr/bin/codesign", append(args, path)...)); err != nil {
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
	run := codesigntest.Require(t, codesigntest.KEKSelection, codesigntest.CertificateSelection)
	const path = "/usr/bin/true"
	t.Logf("native fixture gate: Applied=%v Confined=%v", keychaingate.Applied(), keychaingate.Confined())
	id, err := inspectFixtureFile(t, path)
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
	dir := codesigntest.FixtureDir(t, run, "certificate")
	prefix := filepath.Join(dir, "cert")
	out, err := codesigntest.NativeOutput(t, "extract public certificate", exec.Command("/usr/bin/codesign", "--display", "--extract-certificates="+prefix, "--verbose=4", path))
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
		file, err := inspectFixtureFile(t, binary)
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
		if err := codesigntest.NativeAttempt(t, "execute public curl socket client", cmd.Start); err != nil {
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
		peer, err := inspectFixturePeer(t, conn)
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
	run := codesigntest.Require(t, codesigntest.KEKSelection)
	dir := codesigntest.FixtureDir(t, run, "kek-exec")
	first := buildSigned(t, run, dir, "before-exec", "--options", "runtime,library")
	second := buildSigned(t, run, dir, "after-exec", "--options", "runtime,library")
	sock := filepath.Join(privateTemp(t), "exec.sock")
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
	if err := codesigntest.NativeAttempt(t, "execute KEK socket client", cmd.Start); err != nil {
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
	before, err := inspectFixturePeer(t, conn)
	if err != nil || before.Problem() != "" {
		t.Fatalf("before exec: %+v %v", before, err)
	}
	if before.CDHash != codesignCDHash(t, first) {
		t.Fatal("wrong initial code identity")
	}
	if err := codesigntest.NativeAttempt(t, "authorize KEK client exec", func() error {
		_, err := conn.Write([]byte{'x'})
		return err
	}); err != nil {
		t.Fatal(err)
	}
	var ready [1]byte
	if n, err := conn.Read(ready[:]); err != nil || n != 1 || ready[0] != 'r' {
		t.Fatalf("post-exec acknowledgement: %d %v %q", n, err, ready)
	}
	after, err := inspectFixturePeer(t, conn)
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
	out, err := codesigntest.NativeOutput(t, "inspect KEK code signature", exec.Command("/usr/bin/codesign", "-dvvv", path))
	if err != nil {
		t.Fatalf("inspect KEK code signature: %v", err)
	}
	m := cdhashLine.FindSubmatch(out)
	if m == nil {
		t.Fatalf("no CDHash for %s:\n%s", path, out)
	}
	return string(m[1])
}

// peerOf runs the binary as a client of a fresh socket and identifies it
// from the server side by audit token.
func peerOf(t *testing.T, binary string) (CodeIdentity, error) {
	t.Helper()
	sock := filepath.Join(privateTemp(t), "p.sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	l.SetDeadline(time.Now().Add(10 * time.Second))
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, binary, sock)
	if err := codesigntest.NativeAttempt(t, "execute KEK socket client", cmd.Start); err != nil {
		t.Fatal(err)
	}
	defer cmd.Wait()
	conn, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	return inspectFixturePeer(t, conn)
}

func inspectFixtureFile(t *testing.T, path string) (CodeIdentity, error) {
	t.Helper()
	var identity CodeIdentity
	err := codesigntest.NativeAttempt(t, "assess fixture file", func() error {
		var err error
		identity, err = (CodeInspector{}).File(path)
		return err
	})
	return identity, err
}

func inspectFixturePeer(t *testing.T, conn *net.UnixConn) (CodeIdentity, error) {
	t.Helper()
	var identity CodeIdentity
	err := codesigntest.NativeAttempt(t, "assess fixture peer", func() error {
		var err error
		identity, err = (CodeInspector{}).Peer(conn)
		return err
	})
	return identity, err
}

// The inspector reads what codesign wrote: the cdhash codesign prints, the
// hardened-runtime and library-validation flags, and get-task-allow, both
// for a file and for the same binary running as a socket peer. A copy with
// one byte changed after signing is not valid. The runtime,library variant
// without the entitlement is the positive control.
func TestCodeInspectorReadsSignatures(t *testing.T) {
	run := codesigntest.Require(t, codesigntest.KEKSelection)
	dir := codesigntest.FixtureDir(t, run, "kek-signatures")
	ents := filepath.Join(dir, "gta.plist")
	if err := os.WriteFile(ents, []byte(getTaskAllow), 0600); err != nil {
		t.Fatal(err)
	}
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
			path := buildSigned(t, run, dir, v.name, v.args...)
			v.want.CDHash = codesignCDHash(t, path)
			v.want.Identifier = "works.relux.kek-fixture." + v.name
			file, err := inspectFixtureFile(t, path)
			if err != nil || file != v.want {
				t.Fatalf("file = %+v, %v; want %+v", file, err, v.want)
			}
			if (file.Problem() == "") != v.bound {
				t.Fatalf("problem %q for %s", file.Problem(), v.name)
			}
			peer, err := peerOf(t, path)
			if err != nil || peer != v.want {
				t.Fatalf("peer = %+v, %v; want %+v", peer, err, v.want)
			}
		})
	}
	t.Run("changed after signing", func(t *testing.T) {
		path := buildSigned(t, run, dir, "changed", "--options", "runtime,library")
		data, err := os.ReadFile(path)
		if err != nil || len(data) == 0 {
			t.Fatalf("read signed fixture: %v", err)
		}
		data[len(data)/2] ^= 1
		if err := os.WriteFile(path, data, 0700); err != nil {
			t.Fatal(err)
		}
		file, err := inspectFixtureFile(t, path)
		if err == nil && file.Valid {
			t.Fatalf("a changed binary is valid: %+v", file)
		}
		if file.Identifier != "" || file.CertificateSHA1 != "" || file.CDHash != "" {
			t.Fatalf("invalid code returned attested facts: %+v", file)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		path := buildSigned(t, run, dir, "target", "--options", "runtime,library")
		link := filepath.Join(dir, "link")
		os.Symlink(path, link)
		if id, err := inspectFixtureFile(t, link); err == nil {
			t.Fatalf("a symlink was identified: %+v", id)
		}
	})
}
