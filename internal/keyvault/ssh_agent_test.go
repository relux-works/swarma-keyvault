package keyvault

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// This deterministic test-only backend uses a PUBLIC fixed scalar and nonce.
// It proves wire stability; it must never be used for production signing.
type sshFixedStore struct{ *fakeStore }

func (s *sshFixedStore) Sign(label string, digest []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signs = append(s.signs, label)
	if _, ok := s.keys[label]; !ok {
		return nil, ErrNotFound
	}
	n := elliptic.P256().Params().N
	x, _ := elliptic.P256().ScalarBaseMult([]byte{11})
	r := new(big.Int).Mod(x, n)
	v := new(big.Int).Mul(r, big.NewInt(7))
	v.Add(v, new(big.Int).SetBytes(digest))
	v.Mul(v, new(big.Int).ModInverse(big.NewInt(11), n))
	v.Mod(v, n)
	return (Signature{r, v}).LowS().Encode(FormatSignatureDERLowS)
}
func sshFixture(t *testing.T) (*SSHAgent, *sshFixedStore, Address) {
	t.Helper()
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "ssh-agent", Version: 1}
	store := &sshFixedStore{newFakeStore(addr.Label())}
	x, y := elliptic.P256().ScalarBaseMult([]byte{7})
	spki, err := x509.MarshalPKIXPublicKey(&ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y})
	if err != nil {
		t.Fatal(err)
	}
	item := store.keys[addr.Label()]
	item.SPKI = spki
	store.keys[addr.Label()] = item
	a, err := NewSSHAgent(NewManager(store, nil, testOrigin), []Address{addr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, store, addr
}
func sshClient(t *testing.T, a *SSHAgent) agent.ExtendedAgent {
	t.Helper()
	client, server := net.Pipe()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(func() { cancel(); client.Close() })
	go a.ServeConn(ctx, server)
	return agent.NewClient(client)
}

// Darwin limits Unix socket paths to 104 bytes; testing.T.TempDir includes
// the full test name and may exceed it before the socket suffix is added.
func sshTempDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "kv-ssh-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
func sshSocket(t *testing.T, a *SSHAgent) (string, context.CancelFunc, <-chan struct{}) {
	t.Helper()
	path := filepath.Join(sshTempDir(t), "private", "agent.sock")
	listener, cleanup, err := ListenSSH(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	var serveErr error
	go func() { defer close(done); defer cleanup(); serveErr = a.Serve(ctx, listener) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
			if serveErr != nil {
				t.Error(serveErr)
			}
		case <-time.After(3 * time.Second):
			t.Error("agent did not stop")
		}
	})
	return path, cancel, done
}
func sshCommand(t *testing.T, env []string, input []byte, program string, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, program, args...)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(input)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v: %s", program, args, err, out)
	}
	return out
}

// OpenSSH signs through the socket and verifies the byte-exact golden. The
// adjacent altered-message control must be rejected by that same verifier.
func TestSSHAgentOpenSSHGolden(t *testing.T) {
	a, _, _ := sshFixture(t)
	socket, _, _ := sshSocket(t, a)
	dir := t.TempDir()
	pub := SSHPublicBytes(t, a)
	key := filepath.Join(dir, "key.pub")
	if err := os.WriteFile(key, pub, 0600); err != nil {
		t.Fatal(err)
	}
	data := []byte("mac-keyvault SSH agent golden\n")
	input := filepath.Join(dir, "message")
	os.WriteFile(input, data, 0600)
	env := append(os.Environ(), "SSH_AUTH_SOCK="+socket)
	sshCommand(t, env, nil, "/usr/bin/ssh-keygen", "-Y", "sign", "-f", key, "-n", "git", input)
	signature, err := os.ReadFile(input + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	golden := filepath.Join("testdata", "ssh-agent", "message.sig")
	if *updateGolden {
		os.MkdirAll(filepath.Dir(golden), 0755)
		if err := os.WriteFile(golden, signature, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(want, signature) {
		t.Fatal("OpenSSH signature differs from golden")
	}
	allowed := filepath.Join(dir, "allowed_signers")
	os.WriteFile(allowed, append([]byte("test@example.test "), pub...), 0600)
	args := []string{"-Y", "verify", "-f", allowed, "-I", "test@example.test", "-n", "git", "-s", input + ".sig"}
	sshCommand(t, env, data, "/usr/bin/ssh-keygen", args...)
	cmd := exec.Command("/usr/bin/ssh-keygen", args...)
	cmd.Env = env
	cmd.Stdin = bytes.NewReader(append(data, byte('!')))
	out, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(out, []byte("Could not verify signature.")) {
		t.Fatalf("modified-data control: %v %s", err, out)
	}
}
func SSHPublicBytes(t *testing.T, a *SSHAgent) []byte {
	t.Helper()
	pub, err := SSHPublicKey(a.identities[0].key.SPKI)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

// Authentication-style signatures use the selected P-256 key. Unknown keys,
// all mutations, flags and extensions cannot reach any private operation.
func TestSSHAgentClosedProtocol(t *testing.T) {
	a, store, _ := sshFixture(t)
	client := sshClient(t, a)
	keys, err := client.List()
	if err != nil || len(keys) != 1 || keys[0].Format != ssh.KeyAlgoECDSA256 {
		t.Fatalf("identities: %v %v", keys, err)
	}
	pub := a.identities[0].public
	data := []byte("forwarded-style arbitrary authentication request")
	sig, err := client.Sign(pub, data)
	if err != nil || pub.Verify(data, sig) != nil {
		t.Fatalf("sign: %v", err)
	}
	unknown, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := ssh.NewPublicKey(&unknown.PublicKey)
	if _, err := client.Sign(other, data); err == nil {
		t.Fatal("unknown key accepted")
	}
	for name, fn := range map[string]func() error{
		"add":    func() error { return client.Add(agent.AddedKey{PrivateKey: unknown}) },
		"remove": func() error { return client.Remove(pub) }, "remove-all": client.RemoveAll,
		"lock": func() error { return client.Lock([]byte("test")) }, "unlock": func() error { return client.Unlock([]byte("test")) },
		"flags":              func() error { _, err := client.SignWithFlags(pub, data, agent.SignatureFlagRsaSha256); return err },
		"forwarding-binding": func() error { _, err := client.Extension("session-bind@openssh.com", []byte("forwarded")); return err },
		"export":             func() error { _, err := client.Extension("export-private", nil); return err },
	} {
		t.Run(name, func(t *testing.T) {
			if fn() == nil {
				t.Fatal("forbidden request accepted")
			}
		})
	}
	after, err := client.List()
	if err != nil || len(after) != 1 {
		t.Fatal("refusals changed identities")
	}
	if len(store.signs) != 1 || len(store.creates) != 0 || len(store.deletes) != 0 || len(store.updates) != 0 {
		t.Fatalf("forbidden backend effects: %+v", store.signs)
	}
}

// Bad framing is bounded and closes that connection. Malformed complete
// requests fail without signing; the same agent still handles a valid request.
func TestSSHAgentMalformedPackets(t *testing.T) {
	a, store, _ := sshFixture(t)
	for name, data := range map[string][]byte{
		"empty": {0, 0, 0, 0}, "oversized": {0, 4, 0, 1}, "truncated-header": {0, 0}, "truncated-body": {0, 0, 0, 5, 13},
	} {
		t.Run(name, func(t *testing.T) {
			server, client := net.Pipe()
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			defer client.Close()
			finished := make(chan struct{})
			go func() { a.ServeConn(ctx, server); close(finished) }()
			client.SetDeadline(time.Now().Add(time.Second))
			client.Write(data)
			client.Close()
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("malformed connection did not finish")
			}
		})
	}
	for _, packet := range [][]byte{{11, 0}, {13}, {13, 0, 0, 0, 200}, {13, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 99}, {255}} {
		if got := a.handleSSH(context.Background(), packet); !bytes.Equal(got, []byte{5}) {
			t.Fatalf("malformed request accepted: %x", packet)
		}
	}
	if len(store.signs) != 0 {
		t.Fatal("malformed input signed")
	}
	client := sshClient(t, a)
	if _, err := client.Sign(a.identities[0].public, []byte("valid control")); err != nil {
		t.Fatal(err)
	}
}

// Real git invokes ssh-keygen and signs an isolated commit using only the
// agent's public identity; changing the signed commit invalidates verification.
func TestSSHAgentGitSigning(t *testing.T) {
	a, _, _ := sshFixture(t)
	socket, _, _ := sshSocket(t, a)
	dir := t.TempDir()
	pub := SSHPublicBytes(t, a)
	key := filepath.Join(dir, "key.pub")
	os.WriteFile(key, pub, 0600)
	allowed := filepath.Join(dir, "allowed_signers")
	os.WriteFile(allowed, append([]byte("test@example.test "), pub...), 0600)
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "SSH_AUTH_SOCK=" + socket, "GIT_AUTHOR_DATE=2026-10-15T00:00:00Z", "GIT_COMMITTER_DATE=2026-10-15T00:00:00Z"}
	run := func(args ...string) []byte {
		return sshCommand(t, env, nil, "/usr/bin/git", append([]string{"-C", dir}, args...)...)
	}
	run("init", "-q")
	run("config", "user.name", "Keyvault Test")
	run("config", "user.email", "test@example.test")
	run("config", "gpg.format", "ssh")
	run("config", "user.signingkey", key)
	run("config", "gpg.ssh.allowedSignersFile", allowed)
	run("commit", "--allow-empty", "-S", "-m", "agent signing integration")
	out := run("verify-commit", "HEAD")
	if !bytes.Contains(out, []byte("Good \"git\" signature")) {
		t.Fatalf("unverified git commit: %s", out)
	}
	raw := run("cat-file", "commit", "HEAD")
	bad := bytes.Replace(raw, []byte("agent signing integration"), []byte("modified signing integration"), 1)
	hash := strings.TrimSpace(string(sshCommand(t, env, bad, "/usr/bin/git", "-C", dir, "hash-object", "-t", "commit", "-w", "--stdin")))
	cmd := exec.Command("/usr/bin/git", "-C", dir, "verify-commit", hash)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err == nil || !bytes.Contains(out, []byte("Could not verify signature.")) {
		t.Fatalf("modified commit control: %v %s", err, out)
	}
}

// Socket permissions are private, no existing files/sockets/symlinks are
// replaced, and cleanup only unlinks the inode created by this listener.
func TestSSHAgentSocketPrivacy(t *testing.T) {
	dir := sshTempDir(t)
	path := filepath.Join(dir, "private", "agent.sock")
	ln, cleanup, err := ListenSSH(path)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	for _, p := range []string{filepath.Dir(path), path} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		want := os.FileMode(0600)
		if st.IsDir() {
			want = 0700
		}
		if st.Mode().Perm() != want {
			t.Fatalf("%s mode %o", p, st.Mode().Perm())
		}
	}
	if _, _, err := ListenSSH(path); err == nil {
		t.Fatal("live socket replaced")
	}
	ln.Close()
	if _, _, err := ListenSSH(path); err == nil {
		t.Fatal("stale socket replaced")
	}
	os.Remove(path)
	os.WriteFile(path, []byte("foreign"), 0600)
	cleanup()
	data, _ := os.ReadFile(path)
	if string(data) != "foreign" {
		t.Fatal("cleanup removed foreign replacement")
	}
	if _, _, err := ListenSSH(path); err == nil {
		t.Fatal("foreign file replaced")
	}
	os.Remove(path)
	os.Symlink(filepath.Join(dir, "missing"), path)
	if _, _, err := ListenSSH(path); err == nil {
		t.Fatal("symlink replaced")
	}
	os.Remove(path)
	os.Chmod(filepath.Dir(path), 0755)
	if _, _, err := ListenSSH(path); err == nil {
		t.Fatal("public directory accepted")
	}
	os.Chmod(filepath.Dir(path), 0700)
	os.Remove(filepath.Dir(path))
	os.Symlink(dir, filepath.Dir(path))
	if _, _, err := ListenSSH(path); err == nil {
		t.Fatal("symlink directory accepted")
	}
	if _, _, err := ListenSSH("relative.sock"); err == nil {
		t.Fatal("relative socket accepted")
	}
}

// Cancellation closes idle connected clients and the listener. A replacement
// path is preserved, and an already canceled request cannot reach the backend.
func TestSSHAgentCancellation(t *testing.T) {
	a, store, _ := sshFixture(t)
	socket, cancel, done := sshSocket(t, a)
	conn, err := net.Dial("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancellation did not stop server")
	}

	ctx, c := context.WithCancel(context.Background())
	c()
	req := append([]byte{13}, ssh.Marshal(struct {
		Key, Data []byte
		Flags     uint32
	}{a.identities[0].public.Marshal(), []byte("no"), 0})...)
	if !bytes.Equal(a.handleSSH(ctx, req), []byte{5}) || len(store.signs) != 0 {
		t.Fatal("canceled request signed")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	var b [1]byte
	if _, err := conn.Read(b[:]); err == nil {
		t.Fatal("idle client survived cancellation")
	}
}

// Policies are checked on every signature: revocation, expiry and malformed
// metadata cannot be bypassed by an identity already listed by the agent.
func TestSSHAgentPolicyChanges(t *testing.T) {
	for _, kind := range []string{"verify-only", "expired", "forged", "replaced", "deleted"} {
		t.Run(kind, func(t *testing.T) {
			a, store, addr := sshFixture(t)
			client := sshClient(t, a)
			if _, err := client.Sign(a.identities[0].public, []byte("before")); err != nil {
				t.Fatal(err)
			}
			store.mu.Lock()
			item := store.keys[addr.Label()]
			rec := testRecord(addr.Label())
			switch kind {
			case "verify-only":
				rec.Usages = []string{"verify"}
			case "expired":
				expired := NewTime(time.Unix(1, 0))
				rec.Validity.NotAfter = &expired
			case "forged":
				rec.Schema = 9
			case "replaced":
				item.SPKI = []byte("changed")
			case "deleted":
				delete(store.keys, addr.Label())
			}
			item.Tag, _ = EncodeRecord(rec)
			if kind != "deleted" {
				store.keys[addr.Label()] = item
			}
			store.mu.Unlock()
			if _, err := client.Sign(a.identities[0].public, []byte("after")); err == nil {
				t.Fatal("changed policy accepted")
			}
			if len(store.signs) != 1 {
				t.Fatal("changed policy reached private backend")
			}
		})
	}
	a, _, addr := sshFixture(t)
	addr.Version = 0
	if _, err := NewSSHAgent(a.manager, []Address{addr}, nil); err == nil {
		t.Fatal("unpinned key accepted")
	}
}

// A denied or canceled confirmation never reaches the private backend; a
// granted use receives public identity metadata and the message's digest.
func TestSSHAgentConfirmation(t *testing.T) {
	a, store, _ := sshFixture(t)
	client := sshClient(t, a)
	count := 0
	a.confirm = func(ctx context.Context, req SSHConfirmation) error {
		count++
		sum := sha256.Sum256([]byte("message"))
		if req.Purpose != SSHConfirmSign || req.SHA256 != fmt.Sprintf("%x", sum) || req.Version != 1 || req.Until != "" {
			t.Error("wrong confirmation metadata")
		}
		return errors.New("secret hook output must never be emitted")
	}
	if _, err := client.Sign(a.identities[0].public, []byte("message")); err == nil {
		t.Fatal("denied signature accepted")
	}
	if len(store.signs) != 0 || count != 1 {
		t.Fatal("denial reached backend")
	}
	a.confirm = func(context.Context, SSHConfirmation) error { return nil }
	if _, err := client.Sign(a.identities[0].public, []byte("message")); err != nil {
		t.Fatal(err)
	}
}

// The executable hook has literal arguments, no inherited secrets, discarded
// output and bounded cancellation. Both explicit denial and timeout fail shut.
func TestSSHConfirmHook(t *testing.T) {
	for _, tc := range []struct {
		path    string
		args    []string
		timeout time.Duration
		accept  bool
	}{
		{"/usr/bin/true", nil, time.Second, true}, {"/usr/bin/false", nil, time.Second, false},
		{"/bin/sleep", []string{"5"}, 30 * time.Millisecond, false},
	} {
		t.Run(filepath.Base(tc.path), func(t *testing.T) {
			hook, err := SSHConfirmHook(tc.path, tc.args, tc.timeout)
			if err != nil {
				t.Fatal(err)
			}
			start := time.Now()
			err = hook(context.Background(), SSHConfirmation{})
			if (err == nil) != tc.accept {
				t.Fatalf("hook verdict %v", err)
			}
			if time.Since(start) > 2*time.Second {
				t.Fatal("hook deadline not enforced")
			}
		})
	}
	for _, path := range []string{"true", "/missing"} {
		if _, err := SSHConfirmHook(path, nil, time.Second); err == nil {
			t.Fatal("invalid hook accepted")
		}
	}
	if _, err := SSHConfirmHook("/usr/bin/true", nil, 2*time.Minute); err == nil {
		t.Fatal("unbounded hook accepted")
	}
}

// Parallel clients serialize their signing operations and remain valid.
func TestSSHAgentConcurrentClients(t *testing.T) {
	a, _, _ := sshFixture(t)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		client := sshClient(t, a)
		wg.Add(1)
		go func() {
			defer wg.Done()
			sig, err := client.Sign(a.identities[0].public, []byte("parallel"))
			if err != nil || a.identities[0].public.Verify([]byte("parallel"), sig) != nil {
				t.Errorf("parallel signature: %v", err)
			}
		}()
	}
	wg.Wait()
}

// Raw framing controls prove the production parser rejects oversize lengths
// without waiting for a body, and accepts an adjacent valid identities frame.
func TestSSHAgentOversizeImmediate(t *testing.T) {
	a, _, _ := sshFixture(t)
	server, client := net.Pipe()
	defer client.Close()
	go a.ServeConn(context.Background(), server)
	var head [4]byte
	binary.BigEndian.PutUint32(head[:], SSHMaxPacket+1)
	client.Write(head[:])
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(client, head[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("oversize not closed immediately: %v", err)
	}
	valid := sshClient(t, a)
	if _, err := valid.List(); err != nil {
		t.Fatal(err)
	}
}

// The hook helper is a separate test process receiving only explicit args.
// Its observation file contains synthetic metadata, never user information.
func TestSSHConfirmHelper(t *testing.T) {
	for i, arg := range os.Args {
		if arg == "keyvault-hook-fixture" && i+2 < len(os.Args) {
			var req SSHConfirmation
			if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
				os.Exit(2)
			}
			value := struct {
				Literal, Inherited string
				Request            SSHConfirmation
			}{os.Args[i+2], os.Getenv("KEYVAULT_SYNTHETIC_SECRET"), req}
			data, _ := json.Marshal(value)
			if os.WriteFile(os.Args[i+1], data, 0600) != nil {
				os.Exit(2)
			}
			os.Exit(0)
		}
	}
}

// A literal shell-looking argument is not interpreted, and a synthetic
// inherited secret is absent from the confirmation subprocess environment.
func TestSSHConfirmHookLiteralArgumentsAndEnvironment(t *testing.T) {
	t.Setenv("KEYVAULT_SYNTHETIC_SECRET", "synthetic-control")
	path := filepath.Join(t.TempDir(), "hook-observation.json")
	literal := "$(exit 99); `exit 98` $KEYVAULT_SYNTHETIC_SECRET"
	hook, err := SSHConfirmHook(os.Args[0], []string{"-test.run=^TestSSHConfirmHelper$", "--", "keyvault-hook-fixture", path, literal}, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req := SSHConfirmation{Address: "test/hook", Version: 1, Fingerprint: "SHA256:public", SHA256: "digest"}
	if err := hook(context.Background(), req); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value struct {
		Literal, Inherited string
		Request            SSHConfirmation
	}
	if json.Unmarshal(raw, &value) != nil || value.Literal != literal || value.Inherited != "" || value.Request != req {
		t.Fatalf("hook arguments/environment changed: %s", raw)
	}
}

// A real OpenSSH client authenticates via the agent and performs git push to
// an isolated local SSH server. The server accepts only the selected key and
// executes receive-pack only for this test's bare repository, never GitHub.
func TestSSHAgentGitPushOverSSH(t *testing.T) {
	a, store, _ := sshFixture(t)
	socket, _, _ := sshSocket(t, a)
	dir := t.TempDir()
	bare := filepath.Join(dir, "remote.git")
	local := filepath.Join(dir, "local")
	pub := SSHPublicBytes(t, a)
	keyPath := filepath.Join(dir, "key.pub")
	os.WriteFile(keyPath, pub, 0600)
	hostKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		t.Fatal(err)
	}
	config := &ssh.ServerConfig{PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
		if meta.User() != "git" || !bytes.Equal(key.Marshal(), a.identities[0].public.Marshal()) {
			return nil, errors.New("test key required")
		}
		return nil, nil
	}}
	config.AddHostKey(hostSigner)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	hostPub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(hostSigner.PublicKey())))
	known := filepath.Join(dir, "known_hosts")
	os.WriteFile(known, []byte("[127.0.0.1]:"+port+" "+hostPub+"\n"), 0600)
	env := []string{"PATH=/usr/bin:/bin:/usr/sbin:/sbin", "HOME=" + dir, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL=/dev/null", "SSH_AUTH_SOCK=" + socket}
	sshCommand(t, env, nil, "/usr/bin/git", "init", "--bare", "-q", bare)
	sshCommand(t, env, nil, "/usr/bin/git", "init", "-q", local)
	sshCommand(t, env, nil, "/usr/bin/git", "-C", local, "-c", "user.name=SSH Test", "-c", "user.email=test@example.test", "commit", "--allow-empty", "-m", "push through agent")
	serverDone := make(chan error, 1)
	serverEnv := append([]string(nil), env...)
	go func() {
		raw, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer raw.Close()
		raw.SetDeadline(time.Now().Add(10 * time.Second))
		connection, channels, requests, err := ssh.NewServerConn(raw, config)
		if err != nil {
			serverDone <- err
			return
		}
		defer connection.Close()
		go ssh.DiscardRequests(requests)
		for incoming := range channels {
			if incoming.ChannelType() != "session" {
				incoming.Reject(ssh.UnknownChannelType, "session required")
				continue
			}
			ch, reqs, err := incoming.Accept()
			if err != nil {
				serverDone <- err
				return
			}
			for req := range reqs {
				var command struct{ Command string }
				if req.Type != "exec" || ssh.Unmarshal(req.Payload, &command) != nil || command.Command != "git-receive-pack 'project'" {
					req.Reply(false, nil)
					continue
				}
				req.Reply(true, nil)
				cmd := exec.Command("/usr/bin/git", "receive-pack", bare)
				cmd.Env = serverEnv
				cmd.Stdin = ch
				cmd.Stdout = ch
				cmd.Stderr = ch.Stderr()
				err := cmd.Run()
				status := uint32(0)
				if err != nil {
					status = 1
				}
				ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{status}))
				ch.Close()
				serverDone <- err
				return
			}
			ch.Close()
		}
		serverDone <- errors.New("no receive-pack request")
	}()
	// Git calls this fixed wrapper with argv; ssh never consults ~/.ssh/config.
	wrapper := filepath.Join(dir, "ssh-client")
	script := "#!/bin/sh\nexec /usr/bin/ssh -F /dev/null -o BatchMode=yes -o IdentitiesOnly=yes -o IdentityAgent=\"$SSH_AUTH_SOCK\" -i '" + keyPath + "' -o UserKnownHostsFile='" + known + "' -o StrictHostKeyChecking=yes -p " + port + " \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	env = append(env, "GIT_SSH="+wrapper, "GIT_SSH_VARIANT=ssh")
	sshCommand(t, env, nil, "/usr/bin/git", "-C", local, "push", "git@127.0.0.1:project", "HEAD:refs/heads/main")
	select {
	case err := <-serverDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("test SSH server did not finish")
	}
	want := sshCommand(t, env, nil, "/usr/bin/git", "-C", local, "rev-parse", "HEAD")
	got := sshCommand(t, env, nil, "/usr/bin/git", "--git-dir", bare, "rev-parse", "refs/heads/main")
	if !bytes.Equal(want, got) || len(store.signs) != 1 {
		t.Fatalf("git push did not use agent identity: signatures=%d", len(store.signs))
	}
}

// The production accepted-peer path serves the kernel-attested owner UID,
// refuses a different expected owner and fails shut on a closed connection.
// The mismatch control does not require another account or mutate host ACLs.
func TestSSHAgentKernelPeerCredentials(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		t.Run(fmt.Sprint(mismatch), func(t *testing.T) {
			a, store, _ := sshFixture(t)
			socket := filepath.Join(sshTempDir(t), "agent.sock")
			listener, cleanup, err := ListenSSH(socket)
			if err != nil {
				t.Fatal(err)
			}
			defer cleanup()
			client, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: socket, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			server, err := listener.AcceptUnix()
			if err != nil {
				t.Fatal(err)
			}
			uid, err := sshPeerUID(server)
			if err != nil || uid != uint32(os.Getuid()) {
				t.Fatalf("kernel credentials: %d %v", uid, err)
			}
			expected := uid
			if mismatch {
				expected++
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			go a.serveSSHPeer(ctx, server, expected)
			client.SetDeadline(time.Now().Add(time.Second))
			keys, err := agent.NewClient(client).List()
			if mismatch {
				if err == nil {
					t.Fatal("foreign UID received identities")
				}
				if len(store.signs) != 0 {
					t.Fatal("foreign UID reached private operation")
				}
			} else if err != nil || len(keys) != 1 {
				t.Fatalf("owner UID refused: %v", err)
			}
			server.Close()
			if _, err := sshPeerUID(server); err == nil {
				t.Fatal("closed socket yielded credentials")
			}
		})
	}
}

// Claim: ConfirmUnlock asks the hook once per pinned identity with purpose
// unlock, the deadline and no digest; any refusal refuses the unlock, and a
// missing hook is refused. Granting is the positive control. No signature is
// made while confirming.
func TestSSHAgentConfirmUnlock(t *testing.T) {
	a, store, addr := sshFixture(t)
	until := time.Date(2026, 10, 18, 17, 0, 0, 0, time.UTC)
	var seen []SSHConfirmation
	grant := func(_ context.Context, req SSHConfirmation) error { seen = append(seen, req); return nil }
	if err := a.ConfirmUnlock(context.Background(), grant, until); err != nil {
		t.Fatal(err)
	}
	if len(seen) != 1 || seen[0].Purpose != SSHConfirmUnlock || seen[0].Until != "2026-10-18T17:00:00Z" || seen[0].SHA256 != "" ||
		seen[0].Address != addr.Service+"/"+addr.Purpose || seen[0].Version != 1 || !strings.HasPrefix(seen[0].Fingerprint, "SHA256:") {
		t.Fatalf("unlock requests = %+v", seen)
	}
	deny := func(context.Context, SSHConfirmation) error { return errors.New("no") }
	if err := a.ConfirmUnlock(context.Background(), deny, until); err == nil {
		t.Fatal("denied unlock accepted")
	}
	if err := a.ConfirmUnlock(context.Background(), nil, until); err == nil {
		t.Fatal("unlock without a hook accepted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := a.ConfirmUnlock(cancelled, grant, until); err == nil {
		t.Fatal("unlock confirmed after cancellation")
	}
	if len(store.signs) != 0 {
		t.Fatal("unlock confirmation signed")
	}
}

// Claim: an agent served with a deadline signs before it and, once it
// passes, stops serving on its own (Serve returns nil, the listener is
// closed) and refuses a signing request that is still handled.
func TestSSHAgentStopsAtDeadline(t *testing.T) {
	a, store, _ := sshFixture(t)
	path := filepath.Join(sshTempDir(t), "private", "agent.sock")
	listener, cleanup, err := ListenSSH(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { err := a.Serve(ctx, listener); cleanup(); done <- err }()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := agent.NewClient(conn)
	if _, err := client.Sign(a.identities[0].public, []byte("before")); err != nil || len(store.signs) != 1 {
		t.Fatalf("control: sign before the deadline: %v", err)
	}
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("serve at deadline: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent kept serving past its deadline")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket survived the deadline")
	}
	req := append([]byte{13}, ssh.Marshal(struct {
		Key, Data []byte
		Flags     uint32
	}{a.identities[0].public.Marshal(), []byte("after"), 0})...)
	if !bytes.Equal(a.handleSSH(ctx, req), []byte{sshFailure}) || len(store.signs) != 1 {
		t.Fatal("signed after the deadline")
	}
}

// gatedStore blocks List (record resolution) or Sign once armed, until the
// gate is closed, to hold a request inside the agent across its deadline.
type gatedStore struct {
	*sshFixedStore
	gate       chan struct{}
	blockList  atomic.Bool
	blockSign  atomic.Bool
	listCalled chan struct{}
	signCalled chan struct{}
	// listSkip lets this many armed List calls pass before one blocks.
	listSkip atomic.Int32
}

func (s *gatedStore) List() ([]Item, error) {
	if s.blockList.Load() && s.listSkip.Add(-1) < 0 {
		select {
		case s.listCalled <- struct{}{}:
		default:
		}
		<-s.gate
	}
	return s.sshFixedStore.List()
}

func (s *gatedStore) Sign(label string, digest []byte) ([]byte, error) {
	if s.blockSign.Load() {
		select {
		case s.signCalled <- struct{}{}:
		default:
		}
		<-s.gate
	}
	return s.sshFixedStore.Sign(label, digest)
}

func gatedFixture(t *testing.T) (*SSHAgent, *gatedStore) {
	t.Helper()
	_, fixed, addr := sshFixture(t)
	store := &gatedStore{sshFixedStore: fixed, gate: make(chan struct{}), listCalled: make(chan struct{}, 1), signCalled: make(chan struct{}, 1)}
	t.Cleanup(func() {
		select {
		case <-store.gate:
		default:
			close(store.gate)
		}
	})
	a, err := NewSSHAgent(NewManager(store, nil, testOrigin), []Address{addr}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return a, store
}

// Claim: the unlock deadline is enforced by the agent's own wall-clock check
// and watchdog, not only by the caller's context timer: with a context that
// never expires, Serve stops by itself shortly after ExpireAt's time, the
// socket is gone and signing is refused. (Sleep itself cannot be simulated
// here; this proves the expiry does not depend on a monotonic timer firing.)
func TestSSHAgentWallClockExpiry(t *testing.T) {
	a, store := gatedFixture(t)
	a.ExpireAt(time.Now().Add(300 * time.Millisecond))
	path := filepath.Join(sshTempDir(t), "private", "agent.sock")
	listener, cleanup, err := ListenSSH(path)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { err := a.Serve(context.Background(), listener); cleanup(); done <- err }()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.NewClient(conn).Sign(a.identities[0].public, []byte("before")); err != nil {
		t.Fatalf("control: sign before expiry: %v", err)
	}
	conn.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("agent kept serving past ExpireAt with a context that never expires")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket survived expiry")
	}
	before := len(store.signs)
	req := append([]byte{13}, ssh.Marshal(struct {
		Key, Data []byte
		Flags     uint32
	}{a.identities[0].public.Marshal(), []byte("after"), 0})...)
	if !bytes.Equal(a.handleSSH(context.Background(), req), []byte{sshFailure}) || len(store.signs) != before {
		t.Fatal("signed after expiry")
	}
}

// Claim: a request whose record resolution blocks across the deadline never
// reaches the private signing operation once it resumes, whether it blocks
// in the agent's own Describe (first resolution) or in Manager.Sign's
// resolution right before the backend call (second).
func TestSSHAgentNoPrivateOperationAfterExpiry(t *testing.T) {
	for name, skip := range map[string]int32{"agent describe": 0, "manager sign resolution": 1} {
		t.Run(name, func(t *testing.T) {
			a, store := gatedFixture(t)
			a.ExpireAt(time.Now().Add(200 * time.Millisecond))
			store.listSkip.Store(skip)
			store.blockList.Store(true)
			result := make(chan []byte, 1)
			req := append([]byte{13}, ssh.Marshal(struct {
				Key, Data []byte
				Flags     uint32
			}{a.identities[0].public.Marshal(), []byte("late"), 0})...)
			go func() { result <- a.handleSSH(context.Background(), req) }()
			select {
			case <-store.listCalled:
			case <-time.After(3 * time.Second):
				t.Fatal("the request never blocked in the chosen resolution")
			}
			time.Sleep(400 * time.Millisecond)
			close(store.gate)
			if got := <-result; !bytes.Equal(got, []byte{sshFailure}) || len(store.signs) != 0 {
				t.Fatalf("response %v, private signs %d", got, len(store.signs))
			}
		})
	}
}

// Claim: a private operation that was already running when the deadline
// passed (here: the backend blocks across it, with no context cancellation
// and no watchdog) completes but its signature is not returned.
func TestSSHAgentDiscardsSignatureFinishedAfterExpiry(t *testing.T) {
	a, store := gatedFixture(t)
	a.ExpireAt(time.Now().Add(200 * time.Millisecond))
	store.blockSign.Store(true)
	result := make(chan []byte, 1)
	req := append([]byte{13}, ssh.Marshal(struct {
		Key, Data []byte
		Flags     uint32
	}{a.identities[0].public.Marshal(), []byte("inflight"), 0})...)
	go func() { result <- a.handleSSH(context.Background(), req) }()
	select {
	case <-store.signCalled:
	case <-time.After(3 * time.Second):
		t.Fatal("the request never reached the backend")
	}
	time.Sleep(400 * time.Millisecond)
	close(store.gate)
	if got := <-result; !bytes.Equal(got, []byte{sshFailure}) || len(store.signs) != 1 {
		t.Fatalf("response %v, private signs %d (want the computed signature discarded)", got, len(store.signs))
	}
}

// Claim: a private operation that blocks past the deadline does not keep
// Serve (and so the socket) alive: Serve returns within the shutdown grace
// and the blocked request's client gets no signature.
func TestSSHAgentShutdownDoesNotWaitForBlockedSign(t *testing.T) {
	a, store := gatedFixture(t)
	store.blockSign.Store(true)
	path := filepath.Join(sshTempDir(t), "private", "agent.sock")
	listener, cleanup, err := ListenSSH(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { err := a.Serve(ctx, listener); cleanup(); done <- err }()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	signErr := make(chan error, 1)
	go func() {
		_, err := agent.NewClient(conn).Sign(a.identities[0].public, []byte("blocked"))
		signErr <- err
	}()
	select {
	case <-done:
	case <-time.After(300*time.Millisecond + SSHShutdownGrace + 2*time.Second):
		t.Fatal("Serve waited for a blocked private operation")
	}
	if _, err := os.Lstat(path); !os.IsNotExist(err) {
		t.Fatal("socket survived shutdown")
	}
	if err := <-signErr; err == nil {
		t.Fatal("the blocked request returned a signature")
	}
}
