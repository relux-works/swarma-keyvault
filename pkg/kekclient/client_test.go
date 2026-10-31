package kekclient

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The test binary doubles as a fake broker: with fakeBrokerEnv set it
// behaves like `mac-keyvault-kek <op> --address A --socket S` and answers
// with the line in fakeAnswerEnv (or, for "echo-kek", a well-formed unwrap
// result for the request's envelope).
const (
	fakeBrokerEnv = "KEKCLIENT_FAKE_BROKER"
	fakeAnswerEnv = "KEKCLIENT_FAKE_ANSWER"
	fakeReadyEnv  = "KEKCLIENT_FAKE_READY"
	fakeLingerEnv = "KEKCLIENT_FAKE_LINGER"
	fakeChildEnv  = "KEKCLIENT_FAKE_CHILD"
	// fakeAfterReadEnv makes the fake stall ("stall") or answer 350 ms late
	// ("delay") after reading the request; it writes fakeMarkerEnv first.
	fakeAfterReadEnv = "KEKCLIENT_FAKE_AFTER_READ"
	fakeMarkerEnv    = "KEKCLIENT_FAKE_MARKER"
	// fakeNoNewlineEnv makes the fake send its answer without the newline
	// and close: the client reads a whole answer and an EOF.
	fakeNoNewlineEnv = "KEKCLIENT_FAKE_NO_NEWLINE"
	fakeStartedEnv   = "KEKCLIENT_FAKE_STARTED"
)

func TestMain(m *testing.M) {
	if os.Getenv(fakeBrokerEnv) != "" {
		os.Exit(fakeBroker(os.Args[1:]))
	}
	os.Exit(m.Run())
}

func fakeBroker(args []string) int {
	fs := flag.NewFlagSet("fake", flag.ContinueOnError)
	address := fs.String("address", "", "")
	sock := fs.String("socket", "", "")
	if len(args) < 1 || fs.Parse(args[1:]) != nil || *address == "" {
		return 2
	}
	if marker := os.Getenv(fakeStartedEnv); marker != "" {
		if err := os.WriteFile(marker, []byte(fmt.Sprintf("%d", os.Getpid())), 0600); err != nil {
			return 2
		}
	}
	l, err := net.Listen("unix", *sock)
	if err != nil {
		return 1
	}
	defer l.Close()
	if linger := os.Getenv(fakeLingerEnv); linger != "" {
		// A descendant that stays in our process group and outlives us
		// unless the group is killed; it inherits stdout and stderr except
		// in success-closed. Its pid goes to fakeChildEnv for the test.
		child := exec.Command("/bin/sleep", "30")
		if linger != "success-closed" {
			child.Stdout, child.Stderr = os.Stdout, os.Stderr
		}
		if child.Start() != nil {
			return 1
		}
		// The child's birth identity, so the test never signals a reused pid.
		id, _ := processIdentity(child.Process.Pid)
		os.WriteFile(os.Getenv(fakeChildEnv), []byte(id), 0o600)
		if linger == "silent" {
			time.Sleep(30 * time.Second)
			return 0
		}
	}
	if ready := os.Getenv(fakeReadyEnv); ready != "" {
		fmt.Println(ready)
	} else {
		fmt.Printf("listening %s\n", *sock)
	}
	conn, err := l.Accept()
	if err != nil {
		return 1
	}
	defer conn.Close()
	line, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		return 1
	}
	// After the request: tell the test, then stall or answer late.
	switch os.Getenv(fakeAfterReadEnv) {
	case "stall":
		os.WriteFile(os.Getenv(fakeMarkerEnv), []byte("read"), 0o600)
		time.Sleep(30 * time.Second)
		return 0
	case "delay":
		os.WriteFile(os.Getenv(fakeMarkerEnv), []byte("read"), 0o600)
		time.Sleep(350 * time.Millisecond)
	}
	answer := os.Getenv(fakeAnswerEnv)
	if answer == "echo-kek" {
		var req Request
		json.Unmarshal(line, &req)
		env, _ := ParseEnvelope(req.Envelope)
		b, _ := json.Marshal(Response{Contract: Contract, OK: true, Result: &Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, KEK: testKEK()}})
		answer = string(b)
	}
	if os.Getenv(fakeNoNewlineEnv) != "" {
		fmt.Fprint(conn, answer)
		return 0
	}
	fmt.Fprintln(conn, answer)
	return 0
}

// shortDir is a private directory with a path short enough for a socket.
func shortDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "kc")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func fakeOptions(t *testing.T, answer, ready string) Options {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(fakeBrokerEnv, "1")
	t.Setenv(fakeAnswerEnv, answer)
	t.Setenv(fakeReadyEnv, ready)
	t.Setenv(fakeLingerEnv, "")
	t.Setenv(fakeAfterReadEnv, "")
	t.Setenv(fakeNoNewlineEnv, "")
	t.Setenv(fakeStartedEnv, "")
	// The fake broker is this test binary. Under -race its runtime sleeps
	// a second at exit by default, longer than exitGrace, and a correctly
	// answering fake would be killed; a real broker is not race-built.
	t.Setenv("GORACE", "atexit_sleep_ms=0")
	return Options{Broker: exe, SocketDir: shortDir(t), Timeout: 10 * time.Second}
}

func testEnvelope(t *testing.T) ([]byte, Envelope) {
	t.Helper()
	k := newTestKey(t)
	sealed, err := Wrap(testSpec(k), testKEK())
	if err != nil {
		t.Fatal(err)
	}
	env, _ := ParseEnvelope(sealed)
	return sealed, env
}

// Unwrap runs the broker, waits for its ready line, sends one request and
// returns the KEK of a well-formed answer about the envelope's key whose
// check value matches the envelope's.
func TestUnwrapReturnsTheKEKOfAContractAnswer(t *testing.T) {
	sealed, _ := testEnvelope(t)
	kek, err := Unwrap(context.Background(), fakeOptions(t, "echo-kek", ""), sealed)
	if err != nil || !bytes.Equal(kek, testKEK()) {
		t.Fatalf("kek=%x err=%v", kek, err)
	}
}

// Answers outside the contract are refused as ErrProtocol and a declared
// refusal comes back as *Error with its code; nothing in them is used.
func TestUnwrapRefusesAnswersOutsideTheContract(t *testing.T) {
	sealed, env := testEnvelope(t)
	ok := func(r Result) string {
		b, _ := json.Marshal(Response{Contract: Contract, OK: true, Result: &r})
		return string(b)
	}
	good := Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, KEK: testKEK()}
	short, otherKey, otherGen, withEnvelope, chosen := good, good, good, good, good
	chosen.KEK = bytes.Repeat([]byte{7}, KEKLen)
	short.KEK = short.KEK[:16]
	otherKey.Fingerprint = "other"
	otherGen.Generation = 2
	withEnvelope.Envelope = json.RawMessage(`{}`)
	protocol := map[string]string{
		"kek of its choice": ok(chosen),
		"short kek":         ok(short),
		"other key":         ok(otherKey),
		"other generation":  ok(otherGen),
		"kek and envelope":  ok(withEnvelope),
		"wrong contract":    `{"contract":"kek-2","ok":true,"result":` + strings.TrimPrefix(ok(good), `{"contract":"kek-1","ok":true,"result":`),
		"undeclared code":   `{"contract":"kek-1","ok":false,"error":{"code":"teapot","message":"x"}}`,
		"refusal no error":  `{"contract":"kek-1","ok":false}`,
		"ok with error":     `{"contract":"kek-1","ok":true,"result":{"address":"` + env.Address + `","generation":1,"fingerprint":"` + env.Fingerprint + `"},"error":{"code":"security","message":"x"}}`,
		"unknown member":    strings.Replace(ok(good), `{"contract"`, `{"debug":1,"contract"`, 1),
		"repeated member":   strings.Replace(ok(good), `{"contract":"kek-1"`, `{"contract":"kek-1","contract":"kek-1"`, 1),
		"not json":          `kek: 0707`,
		"nested repeat":     strings.Replace(ok(good), `"generation":1`, `"generation":999,"generation":1`, 1),
		"escaped repeat":    strings.Replace(ok(good), `"generation":1`, `"gen\u0065ration":999,"generation":1`, 1),
		"case alias":        strings.Replace(ok(good), `"generation":1`, `"GENERATION":1`, 1),
		"error null":        strings.Replace(ok(good), `{"contract":"kek-1","ok":true`, `{"contract":"kek-1","ok":true,"error":null`, 1),
		"refusal no ok":     `{"contract":"kek-1","error":{"code":"caller_refused","message":"x"}}`,
		"ok as string":      strings.Replace(ok(good), `"ok":true`, `"ok":"true"`, 1),
		"error extra":       `{"contract":"kek-1","ok":false,"error":{"code":"caller_refused","message":"x","debug":1}}`,
		"code not string":   `{"contract":"kek-1","ok":false,"error":{"code":7,"message":"x"}}`,
		"result unknown":    strings.Replace(ok(good), `"address"`, `"note":"x","address"`, 1),
		"trailing brace":    ok(good) + `}`,
		"trailing bracket":  ok(good) + `]`,
		"second document":   ok(good) + ` {}`,
	}
	for name, answer := range protocol {
		t.Run(name, func(t *testing.T) {
			kek, err := Unwrap(context.Background(), fakeOptions(t, answer, ""), sealed)
			if kek != nil || !errors.Is(err, ErrProtocol) {
				t.Fatalf("kek=%x err=%v", kek, err)
			}
		})
	}
	t.Run("declared refusal", func(t *testing.T) {
		kek, err := Unwrap(context.Background(), fakeOptions(t, `{"contract":"kek-1","ok":false,"error":{"code":"caller_refused","message":"bound to other code"}}`, ""), sealed)
		var e *Error
		if kek != nil || !errors.As(err, &e) || e.Code != CodeCallerRefused {
			t.Fatalf("kek=%x err=%v", kek, err)
		}
	})
	t.Run("wrong ready line", func(t *testing.T) {
		kek, err := Unwrap(context.Background(), fakeOptions(t, ok(good), "listening /elsewhere"), sealed)
		if kek != nil || !errors.Is(err, ErrProtocol) {
			t.Fatalf("kek=%x err=%v", kek, err)
		}
	})
}

// Limit witness, not a guarantee: the clear KCV is the client's only
// reference, so a rewritten envelope whose KCV matches a chosen KEK, served
// by a substituted broker, is accepted (the service's store check is the
// backstop, see kek.md). The control beside it: the same edited envelope
// with a broker that answers the real KEK is refused, so the KCV check runs.
func TestUnwrapTrustsTheEnvelopeItIsGiven(t *testing.T) {
	sealed, _ := testEnvelope(t)
	chosen := bytes.Repeat([]byte{9}, KEKLen)
	var m map[string]json.RawMessage
	json.Unmarshal(sealed, &m)
	kcv, _ := json.Marshal(KeyCheckValue(chosen))
	m["kcv"] = kcv
	edited, _ := json.Marshal(m)
	env, err := ParseEnvelope(edited)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := json.Marshal(Response{Contract: Contract, OK: true, Result: &Result{Address: env.Address, Generation: env.Generation, Fingerprint: env.Fingerprint, KEK: chosen}})
	kek, err := Unwrap(context.Background(), fakeOptions(t, string(answer), ""), edited)
	if err != nil || !bytes.Equal(kek, chosen) {
		t.Fatalf("limit not as documented: kek=%x err=%v", kek, err)
	}
	if kek, err := Unwrap(context.Background(), fakeOptions(t, "echo-kek", ""), edited); kek != nil || !errors.Is(err, ErrProtocol) {
		t.Fatalf("control: the real KEK against an edited KCV: kek=%x err=%v", kek, err)
	}
}

// A broker that leaves a descendant in its process group does not keep it
// alive past Unwrap, however the exchange ends: after a correct answer
// (the KEK is returned, the descendant's pipes closed or inherited), after
// a protocol error, and at the deadline. Unwrap also returns within its
// bound. The descendant is a /bin/sleep whose birth identity (pid, start
// time, command) the fake broker records; the test checks that exactly
// that process is gone, and its cleanup, registered before any assertion
// can stop the test, signals only a process with that identity.
func TestUnwrapLeavesNoDescendantBehind(t *testing.T) {
	if _, ok := processIdentity(os.Getpid()); !ok {
		t.Skip("process identity needs darwin")
	}
	sealed, _ := testEnvelope(t)
	cases := []struct {
		mode, ready string
		wantKEK     bool
	}{
		{"success-closed", "", true},
		{"success-inherit", "", true},
		{"bad-ready", "not a ready line", false},
		{"silent", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.mode, func(t *testing.T) {
			opts := fakeOptions(t, "echo-kek", tc.ready)
			opts.Timeout = 2 * time.Second
			idFile := filepath.Join(t.TempDir(), "child")
			t.Setenv(fakeLingerEnv, tc.mode)
			t.Setenv(fakeChildEnv, idFile)
			start := time.Now()
			kek, err := Unwrap(context.Background(), opts, sealed)
			elapsed := time.Since(start)
			recorded, _ := os.ReadFile(idFile)
			var pid int
			fmt.Sscan(string(recorded), &pid)
			t.Cleanup(func() {
				if id, ok := processIdentity(pid); ok && pid > 1 && id == string(recorded) {
					syscall.Kill(pid, syscall.SIGKILL)
				}
			})
			if pid <= 1 {
				t.Fatalf("the fake broker recorded no descendant: %q", recorded)
			}
			if tc.wantKEK != (err == nil && bytes.Equal(kek, testKEK())) {
				t.Fatalf("kek=%x err=%v", kek, err)
			}
			if elapsed > opts.Timeout+waitDelay+exitGrace {
				t.Fatalf("returned after %v", elapsed)
			}
			deadline := time.Now().Add(2 * time.Second)
			for {
				id, ok := processIdentity(pid)
				if !ok || id != string(recorded) {
					break
				}
				if time.Now().After(deadline) {
					t.Fatalf("descendant %s outlived Unwrap (%v)", recorded, elapsed)
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}

// The one group signal is sent while the broker is not yet reaped, in every
// way an exchange ends, so its pid, which is the group id, cannot have been
// reused. The kill hook waits 100 ms first, as a late goroutine would, then
// requires the broker still present as itself (alive or a zombie). Review
// r3's witness: a Cancel callback run by os/exec could fire after Wait had
// reaped the broker.
func TestGroupSignalPrecedesReaping(t *testing.T) {
	if _, ok := processIdentity(os.Getpid()); !ok {
		t.Skip("process identity needs darwin")
	}
	sealed, _ := testEnvelope(t)
	saved := killGroup
	t.Cleanup(func() { killGroup = saved })
	var calls, late int
	killGroup = func(pgid int) {
		calls++
		time.Sleep(100 * time.Millisecond)
		if _, ok := processIdentity(pgid); !ok {
			late++
			return
		}
		syscall.Kill(-pgid, syscall.SIGKILL)
	}
	for _, tc := range []struct{ answer, ready, linger string }{
		{"echo-kek", "", ""},
		{"echo-kek", "not a ready line", ""},
		{"echo-kek", "", "silent"},
	} {
		opts := fakeOptions(t, tc.answer, tc.ready)
		opts.Timeout = time.Second
		t.Setenv(fakeLingerEnv, tc.linger)
		t.Setenv(fakeChildEnv, filepath.Join(t.TempDir(), "child"))
		Unwrap(context.Background(), opts, sealed)
	}
	if calls != 3 || late != 0 {
		t.Fatalf("group signals: %d, after the broker was reaped: %d", calls, late)
	}
}

// Cancelling the caller's context ends an exchange that is already
// connected, long before the deadline, and yields no KEK: when the broker
// stalls after reading the request, and when it would still answer
// correctly 350 ms later. Review r4's witness. The deadline is far away
// (10 s), so only cancellation can explain a quick return.
func TestUnwrapStopsOnCancellationAfterConnect(t *testing.T) {
	sealed, _ := testEnvelope(t)
	for _, mode := range []string{"stall", "delay"} {
		t.Run(mode, func(t *testing.T) {
			opts := fakeOptions(t, "echo-kek", "")
			opts.Timeout = 10 * time.Second
			marker := filepath.Join(t.TempDir(), "read")
			t.Setenv(fakeAfterReadEnv, mode)
			t.Setenv(fakeMarkerEnv, marker)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			type outcome struct {
				kek []byte
				err error
				at  time.Time
			}
			done := make(chan outcome, 1)
			go func() {
				kek, err := Unwrap(ctx, opts, sealed)
				done <- outcome{kek, err, time.Now()}
			}()
			deadline := time.Now().Add(5 * time.Second)
			for {
				if _, err := os.Stat(marker); err == nil {
					break
				}
				if time.Now().After(deadline) {
					t.Fatal("the fake broker never read the request")
				}
				time.Sleep(5 * time.Millisecond)
			}
			cancelled := time.Now()
			cancel()
			o := <-done
			if o.kek != nil || o.err == nil {
				t.Fatalf("after cancellation: kek=%x err=%v", o.kek, o.err)
			}
			if took := o.at.Sub(cancelled); took > 300*time.Millisecond {
				t.Fatalf("cancellation took effect after %v", took)
			}
		})
	}
}

// A refused answer leaves no KEK bytes in the client's own buffers: the
// whole read buffer (the only one the answer is read into; no bufio copy)
// is cleared, also when the read ends with an error after a whole
// KEK-bearing answer arrived without its newline, and a KEK decoded from a
// well-formed answer naming another contract is cleared. Review r5's
// witnesses. Controls: a valid answer is returned (the read buffer still
// cleared), and an answer about another key clears its decoded KEK.
func TestRefusedAnswersAreCleared(t *testing.T) {
	sealed, env := testEnvelope(t)
	savedRead, savedDecoded := answerRead, responseDecoded
	t.Cleanup(func() { answerRead, responseDecoded = savedRead, savedDecoded })
	var buffers [][]byte
	var decoded []*Response
	answerRead = func(b []byte) { buffers = append(buffers, b) }
	responseDecoded = func(r *Response) { decoded = append(decoded, r) }
	zero := func(b []byte) bool {
		for _, c := range b {
			if c != 0 {
				return false
			}
		}
		return len(b) > 0
	}
	answerFor := func(contract, fingerprint string) string {
		b, _ := json.Marshal(Response{Contract: contract, OK: true, Result: &Result{Address: env.Address, Generation: env.Generation, Fingerprint: fingerprint, KEK: testKEK()}})
		return string(b)
	}
	cases := []struct {
		name, answer string
		noNewline    bool
		wantKEK      bool
		checkDecoded bool
	}{
		{"partial answer", answerFor(Contract, env.Fingerprint), true, false, false},
		{"wrong contract", answerFor("kek-2", env.Fingerprint), false, false, true},
		{"control: other key", answerFor(Contract, "other"), false, false, true},
		{"control: valid answer", answerFor(Contract, env.Fingerprint), false, true, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			buffers, decoded = nil, nil
			opts := fakeOptions(t, tc.answer, "")
			if tc.noNewline {
				t.Setenv(fakeNoNewlineEnv, "1")
			}
			kek, err := Unwrap(context.Background(), opts, sealed)
			if tc.wantKEK != (err == nil && bytes.Equal(kek, testKEK())) {
				t.Fatalf("kek=%x err=%v", kek, err)
			}
			if len(buffers) != 1 || !zero(buffers[0]) {
				t.Fatalf("answer buffer not cleared: %d buffers %q", len(buffers), buffers)
			}
			if tc.checkDecoded {
				if len(decoded) != 1 || decoded[0].Result == nil || !zero(decoded[0].Result.KEK) {
					t.Fatalf("decoded KEK not cleared")
				}
			}
		})
	}
}

// Unwrap refuses before starting anything when the broker path is relative,
// the socket directory is reachable by others or is a symlink, or the
// envelope is not a contract envelope.
func TestUnwrapRefusesUnsafeOptionsBeforeStarting(t *testing.T) {
	sealed, _ := testEnvelope(t)
	opts := fakeOptions(t, "echo-kek", "")
	open := shortDir(t)
	os.Chmod(open, 0o755)
	link := filepath.Join(shortDir(t), "l")
	os.Symlink(opts.SocketDir, link)
	cases := map[string]Options{
		"relative broker": {Broker: "mac-keyvault-kek", SocketDir: opts.SocketDir},
		"open socket dir": {Broker: opts.Broker, SocketDir: open},
		"symlink dir":     {Broker: opts.Broker, SocketDir: link},
		"relative dir":    {Broker: opts.Broker, SocketDir: "run"},
		"missing dir":     {Broker: opts.Broker, SocketDir: filepath.Join(opts.SocketDir, "none")},
	}
	for name, o := range cases {
		if kek, err := Unwrap(context.Background(), o, sealed); err == nil || kek != nil {
			t.Fatalf("%s: kek=%x err=%v", name, kek, err)
		}
	}
	if kek, err := Unwrap(context.Background(), opts, []byte(`{"format":"x"}`)); err == nil || kek != nil {
		t.Fatalf("bad envelope: kek=%x err=%v", kek, err)
	}
	entries, _ := os.ReadDir(opts.SocketDir)
	if len(entries) != 0 {
		t.Fatalf("a refused call left %v behind", entries)
	}
}
