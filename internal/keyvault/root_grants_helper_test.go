package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

// Inert, package-private IO/process fixtures. No child executable, real code
// verification, tty, native key operation or owner material is used here.
type rootGrantsWriter46 struct {
	closes             int
	mu                 sync.Mutex
	data               bytes.Buffer
	writeErr, closeErr error
	short              bool
	onWrite            func()
	closed             chan struct{}
}

func (w *rootGrantsWriter46) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.onWrite != nil {
		w.onWrite()
		w.onWrite = nil
	}
	if w.closes > 0 {
		return 0, io.ErrClosedPipe
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if w.short {
		return 0, nil
	}
	return w.data.Write(p)
}
func (w *rootGrantsWriter46) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.closes++
	if w.closes == 1 && w.closed != nil {
		close(w.closed)
	}
	return w.closeErr
}
func (w *rootGrantsWriter46) closeCount() int { w.mu.Lock(); defer w.mu.Unlock(); return w.closes }
func (w *rootGrantsWriter46) bytes() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return bytes.Clone(w.data.Bytes())
}

type rootGrantsHost46 struct {
	mu                                             sync.Mutex
	calls                                          []int
	starts, terms, kills, waits                    int
	ownErr, beforeErr, afterErr, startErr, exitErr error
	child                                          *rootGrantsHelperChild
	onVerify                                       func(int, int)
	onStart                                        func()
}

func (h *rootGrantsHost46) verify(pid int, pin []byte) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls = append(h.calls, pid)
	if h.onVerify != nil {
		h.onVerify(pid, len(h.calls))
	}
	if pid == 0 {
		if len(pin) != 0 {
			return errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
		}
		return h.ownErr
	}
	if pid != 73 || !bytes.Equal(pin, bytes.Repeat([]byte{9}, 20)) {
		return errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	}
	if len(h.calls) == 2 {
		return h.beforeErr
	}
	return h.afterErr
}
func (h *rootGrantsHost46) start() (*rootGrantsHelperChild, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.starts++
	if h.onStart != nil {
		h.onStart()
	}
	return h.child, h.startErr
}
func rootGrantsHostFixture46(raw []byte) (*rootGrantsHost46, *rootGrantsWriter46) {
	h := &rootGrantsHost46{}
	w := &rootGrantsWriter46{closed: make(chan struct{})}
	h.child = &rootGrantsHelperChild{pid: 73, input: w, output: &rootGrantsCompletionReader48{reader: bytes.NewReader(raw), raw: bytes.Clone(raw), input: w},
		term: func() error { h.mu.Lock(); defer h.mu.Unlock(); h.terms++; return nil },
		kill: func() error { h.mu.Lock(); defer h.mu.Unlock(); h.kills++; return nil },
		wait: func() error { h.mu.Lock(); defer h.mu.Unlock(); h.waits++; return h.exitErr }}
	return h, w
}
func rootGrantsFrame46(status byte, payload []byte) []byte {
	raw := make([]byte, 5+len(payload))
	raw[0] = status
	binary.BigEndian.PutUint32(raw[1:5], uint32(len(payload)))
	copy(raw[5:], payload)
	return raw
}
func rootGrantsExchange46(t *testing.T, ctx context.Context, request []byte, h *rootGrantsHost46) ([]byte, int, error) {
	t.Helper()
	return rootGrantsHelperExchange(ctx, request, bytes.Repeat([]byte{9}, 20), h)
}

// Claim: v1/v2 request BE32/body stays OPEN for the bounded response; full
// bindings/live-PID check precede exact ACK/close, then EOF/exit. The reader
// enforces that order. Limit: fake process/code, not native qualification.
func TestRootGrantsHelper46TransportValid(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		request, sealed, _, _ := rootGrantsSealedFixture46(t, schema)
		h, w := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
		payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
		if err != nil || pid != 73 || !bytes.Equal(payload, sealed) {
			t.Fatal("legitimate frame refused")
		}
		want := make([]byte, 4+len(request))
		binary.BigEndian.PutUint32(want[:4], uint32(len(request)))
		copy(want[4:], request)
		want = append(want, rootGrantsReferenceACK48(request, sealed)...)
		if w.closeCount() != 1 || !bytes.Equal(w.bytes(), want) || !reflect.DeepEqual(h.calls, []int{0, 73, 73}) || h.waits != 1 || h.terms != 0 || h.starts != 1 {
			t.Fatal("request/code/exit ordering failed")
		}
	}
}

// Claim: wrong own/PID/hash admission has zero request bytes; a changed peer
// after output cannot yield a result. All public errors remain fixed/sanitized.
// Limit: exercising verifier ordering with an inert fake does not prove OS code.
func TestRootGrantsHelper46CodeRefusals(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	for _, mode := range []string{"own", "before", "pid", "hash", "after", "start", "nil-child", "canceled-before"} {
		h, w := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
		ctx, cancel := context.WithCancel(context.Background())
		sentinel := errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
		switch mode {
		case "own":
			h.ownErr = sentinel
		case "before":
			h.beforeErr = sentinel
		case "pid":
			h.child.pid = 74
		case "after":
			h.afterErr = sentinel
		case "start":
			h.startErr = sentinel
		case "nil-child":
			h.child = nil
		case "canceled-before":
			cancel()
		}
		pin := bytes.Repeat([]byte{9}, 20)
		if mode == "hash" {
			pin[0] = 8
		}
		payload, pid, err := rootGrantsHelperExchange(ctx, request, pin, h)
		cancel()
		if payload != nil || pid != 0 || err == nil || strings.Contains(err.Error(), "SENTINEL") {
			t.Fatalf("code refusal escaped: %s", mode)
		}
		var refusal *Refusal
		if !errors.As(err, &refusal) {
			t.Fatal("untyped refusal")
		}
		wantCode := "recovery_code_not_admitted"
		if mode == "start" || mode == "nil-child" {
			wantCode = "recovery_operation_unavailable"
		}
		if mode == "canceled-before" {
			wantCode = "recovery_canceled"
		}
		if refusal.Code != wantCode {
			t.Fatal("auth/start/cancel code outside agreed closed mapping")
		}

		if mode != "after" && len(w.bytes()) != 0 {
			t.Fatal("request disclosed before admission")
		}
		if mode == "after" && len(w.bytes()) == 0 {
			t.Fatal("after-code case did not reach response")
		}
		if h.starts > 1 || h.waits > 1 || h.terms > 1 || h.kills != 0 {
			t.Fatal("retry/duplicate cleanup")
		}
	}
}

// Claim: status/length/read/write/EOF/exit failures refuse without output,
// bounded allocations, or retries. Limit: deterministic IO, not real OS pipes.
func TestRootGrantsHelper46TransportRefusals(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	valid := rootGrantsFrame46(0, sealed)
	cases := map[string][]byte{"header-eof": nil, "header-short": valid[:4], "payload-short": valid[:len(valid)-1], "trailing-byte": append(bytes.Clone(valid), 0), "status2": rootGrantsFrame46(2, nil), "success-zero": rootGrantsFrame46(0, nil), "refusal-zero": rootGrantsFrame46(1, nil), "refusal3": rootGrantsFrame46(1, make([]byte, 3)), "refusal5": rootGrantsFrame46(1, make([]byte, 5)), "code0": rootGrantsFrame46(1, []byte{0, 0, 0, 0}), "code21": rootGrantsFrame46(1, []byte{0, 0, 0, 21}), "codehuge": rootGrantsFrame46(1, []byte{255, 255, 255, 255}), "refusal-trailing": append(rootGrantsFrame46(1, []byte{0, 0, 0, 1}), 0)}
	for _, n := range []uint32{131073, 0xffffffff} {
		raw := make([]byte, 5)
		binary.BigEndian.PutUint32(raw[1:], n)
		cases["oversize"+string(rune(n%1000))] = raw
	}
	for name, raw := range cases {
		if bytes.Equal(raw, valid) {
			t.Fatalf("no-op frame negative: %s", name)
		}
		h, _ := rootGrantsHostFixture46(raw)
		payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
		if payload != nil || pid != 0 || err == nil {
			t.Fatalf("bad frame accepted: %s", name)
		}
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Code != "recovery_private_protocol_error" {
			t.Fatal("bad frame returned wrong fixed refusal")
		}
		if h.starts != 1 || h.waits != 1 || h.terms != 1 || h.kills != 0 {
			t.Fatal("bad frame did not terminate once")
		}
	}
	for _, mode := range []string{"write", "short-write", "close", "exit", "read"} {
		h, w := rootGrantsHostFixture46(valid)
		sentinel := errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
		switch mode {
		case "write":
			w.writeErr = sentinel
		case "short-write":
			w.short = true
		case "close":
			w.closeErr = sentinel
		case "exit":
			h.exitErr = sentinel
		case "read":
			h.child.output = &rootGrantsReadFailure46{}
		}
		payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
		if payload != nil || pid != 0 || err == nil || strings.Contains(err.Error(), "SENTINEL") {
			t.Fatalf("IO/exit failure admitted: %s", mode)
		}
		var refusal *Refusal
		if !errors.As(err, &refusal) || refusal.Code != "recovery_private_protocol_error" {
			t.Fatal("IO/exit failure returned wrong fixed refusal")
		}
		if h.waits != 1 || h.starts != 1 {
			t.Fatal("failure retried/reaped twice")
		}
	}
}

type rootGrantsReadFailure46 struct{}

func (*rootGrantsReadFailure46) Read([]byte) (int, error) {
	return 0, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
}
func (*rootGrantsReadFailure46) Close() error { return errors.New("PUBLIC_TEST_PRIVATE_SENTINEL") }

// Claim: every ROOT1..20 maps to the exact accepted fixed class, including
// input_canceled20 versus canceled14/timeout15. Refusals never yield a plan.
// Limit: framed fixture classes, not actual native/owner refusals.
func TestRootGrantsHelper46FixedCodes(t *testing.T) {
	request, _, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/1")
	expected := []string{"invalid_arguments", "terminal_required", "invalid_word_number", "invalid_word_count", "invalid_mnemonic", "invalid_checksum", "invalid_derivation", "retained_record_mismatch", "public_pin_mismatch", "operation_unavailable", "wrapping_policy_refused", "invalid_envelope", "binding_mismatch", "canceled", "timeout", "private_protocol_error", "limit_exceeded", "unsupported_version", "unsupported_operation", "input_canceled"}
	for i, name := range expected {
		var code [4]byte
		binary.BigEndian.PutUint32(code[:], uint32(i+1))
		h, _ := rootGrantsHostFixture46(rootGrantsFrame46(1, code[:]))
		payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
		var r *Refusal
		if payload != nil || pid != 0 || !errors.As(err, &r) || r.Code != "recovery_"+name {
			t.Fatal("wrong fixed ROOT mapping")
		}
		failure := rootGrantsHelperAttachError(err).(*rootGrantsAttachError)
		if failure.public.Code != name || failure.public.Outcome != "not_applied" {
			t.Fatal("wrong attach refusal")
		}
	}
}

// Claim: cancellation while IO/wait is active uses TERM and one wait with no
// retry/output. Limits: in-memory pipes/process callbacks, not tty restoration.
func TestRootGrantsHelper46Cancellation(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	for _, phase := range []string{"read", "write", "eof", "wait"} {
		h, w := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
		ctx, cancel := context.WithCancel(context.Background())
		entered := make(chan struct{})
		done := make(chan struct{})
		if phase == "read" {
			reader, writer := io.Pipe()
			h.child.output = reader
			w.onWrite = func() { close(entered) }
			defer writer.Close()
		}
		if phase == "write" {
			reader, writer := io.Pipe()
			h.child.input = &rootGrantsNotifyWriter46{WriteCloser: writer, entered: entered}
			h.child.output = io.NopCloser(bytes.NewReader(nil))
			defer reader.Close()
			w.onWrite = nil
		}
		if phase == "eof" {
			reader, writer := io.Pipe()
			h.child.output = &rootGrantsReadClose46{Reader: io.MultiReader(bytes.NewReader(rootGrantsFrame46(0, sealed)), &rootGrantsNotifyReader46{Reader: reader, entered: entered}), Closer: reader}
			defer writer.Close()
		}
		if phase == "wait" {
			terminated := make(chan struct{})
			h.child.term = func() error { h.mu.Lock(); h.terms++; h.mu.Unlock(); close(terminated); return nil }
			h.child.wait = func() error {
				h.mu.Lock()
				h.waits++
				h.mu.Unlock()
				close(entered)
				<-terminated
				return nil
			}
		}
		go func() {
			defer close(done)
			payload, pid, err := rootGrantsExchange46(t, ctx, request, h)
			if payload != nil || pid != 0 || err == nil {
				t.Error("canceled IO/wait returned output")
			}
		}()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("fixture did not enter")
		}
		cancel()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("cancellation cleanup stalled")
		}
		h.mu.Lock()
		terms, starts, waits := h.terms, h.starts, h.waits
		h.mu.Unlock()
		if starts != 1 || waits != 1 || terms != 1 {
			t.Fatal("canceled phase retried or skipped TERM/wait")
		}
	}
}

type rootGrantsCleanupClock46 struct {
	*rootGrantsClock44
	armed chan struct{}
}

func (c rootGrantsCleanupClock46) AfterFunc(d time.Duration, f func()) rootGrantsTimer {
	timer := c.rootGrantsClock44.AfterFunc(d, f)
	close(c.armed)
	return timer
}

// Claim: the ACTUAL cleanup function gives exactly2s before one kill of its
// owned child, even if TERM/kill report failure; no kill before grace. Fake time
// drives production cleanup; no real sleep/process/TTY/native qualification.
func TestRootGrantsHelper46ShutdownGrace(t *testing.T) {
	for _, fail := range []bool{false, true} {
		h, _ := rootGrantsHostFixture46(nil)
		exit := make(chan struct{})
		reaped := make(chan struct{})
		terminated := make(chan struct{})
		killed := make(chan struct{})
		h.child.term = func() error {
			h.mu.Lock()
			h.terms++
			h.mu.Unlock()
			close(terminated)
			if fail {
				return errors.New("fixture")
			}
			return nil
		}
		h.child.kill = func() error {
			h.mu.Lock()
			h.kills++
			h.mu.Unlock()
			close(killed)
			if fail {
				return errors.New("fixture")
			}
			close(exit)
			return nil
		}
		h.child.wait = func() error {
			h.mu.Lock()
			h.waits++
			h.mu.Unlock()
			<-exit
			close(reaped)
			return nil
		}
		clock := rootGrantsCleanupClock46{rootGrantsNewClock44(), make(chan struct{})}
		done := make(chan struct{})
		go func() { rootGrantsStopChildWithClock(h.child, nil, clock); close(done) }()
		select {
		case <-terminated:
		case <-time.After(time.Second):
			t.Fatal("TERM missing")
		}
		select {
		case <-clock.armed:
		case <-time.After(time.Second):
			t.Fatal("timer missing")
		}
		clock.Advance(2*time.Second - time.Nanosecond)
		select {
		case <-killed:
			t.Fatal("killed before grace")
		default:
		}
		clock.Advance(time.Nanosecond)
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Fatal("grace did not complete")
		}
		if fail {
			close(exit)
		}
		select {
		case <-reaped:
		case <-time.After(time.Second):
			t.Fatal("eventual reaper missing")
		}
		h.mu.Lock()
		terms, kills, waits := h.terms, h.kills, h.waits
		h.mu.Unlock()
		if terms != 1 || kills != 1 || waits != 1 {
			t.Fatal("cleanup signaled/reaped another attempt")
		}
	}
}

// Static source boundary witness complements dynamic fake tests: production
// fixes the paired executable/build pin/verifier; no test host is configurable.
// Limits: source-text regression check, not signed OS execution/conformance.
func TestRootGrantsHelper46FixedProductionBoundary(t *testing.T) {
	read := func(name string) string {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	shared := read("root_grants_helper.go")
	native := read("root_grants_helper_darwin.go")
	for _, required := range []string{`"--root-grants-private-v2"`, `[]string{"PATH=/usr/bin:/bin"}`, `cmd.Stderr = io.Discard`, `verifyRecoveryCode(pid, pin)`, `"mac-keyvault-enclave"`, `hex.DecodeString(recoveryHelperCDHash)`, `cmd.Process.Signal(syscall.SIGTERM)`, `kill: cmd.Process.Kill`} {
		if !strings.Contains(shared, required) {
			t.Fatalf("fixed boundary missing: %s", required)
		}
	}
	for _, forbidden := range []string{"CommandContext(", "Getenv(", "ExtraFiles", `"--recovery-private"`, `"--root-grants-private"`} {
		if strings.Contains(shared, forbidden) {
			t.Fatal("alternate/old process capability introduced")
		}
	}
	if !strings.Contains(native, "rootGrantsExecHost{path: path}") || !strings.Contains(native, "rootGrantsHelperPin()") || !strings.Contains(native, "rootGrantsHelperCompletion{") {
		t.Fatal("factory is not actual fixed production route")
	}
	if strings.Index(shared, "preflight, err := beginRootGrantsAttach") > strings.Index(shared, "result, err := invokeRootGrantsHelper") {
		t.Fatal("helper before guard")
	}
	if strings.Count(shared, "invokeRootGrantsHelper(ctx, owned)") != 1 {
		t.Fatal("helper retry or missing call")
	}
}

// Notifications occur at the actual blocked I/O boundary, never before start.
type rootGrantsNotifyWriter46 struct {
	io.WriteCloser
	entered chan struct{}
	once    sync.Once
}

func (w *rootGrantsNotifyWriter46) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	return w.WriteCloser.Write(p)
}

type rootGrantsNotifyReader46 struct {
	io.Reader
	entered chan struct{}
	once    sync.Once
}

func (r *rootGrantsNotifyReader46) Read(p []byte) (int, error) {
	r.once.Do(func() { close(r.entered) })
	return r.Reader.Read(p)
}

type rootGrantsReadClose46 struct {
	io.Reader
	io.Closer
}

// Claim: an earlier caller deadline governs blocked response I/O and is mapped
// to timeout15; an already expired call performs no admission/start/write.
// Limit: inert IO and a short real deadline; no900s/native timing measurement.
func TestRootGrantsHelper46EarlierDeadline(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	for _, expired := range []bool{false, true} {
		h, w := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
		deadline := time.Now().Add(30 * time.Millisecond)
		if expired {
			deadline = time.Unix(1, 0)
		} else {
			reader, writer := io.Pipe()
			h.child.output = reader
			defer writer.Close()
		}
		ctx, cancel := context.WithDeadline(context.Background(), deadline)
		payload, pid, err := rootGrantsExchange46(t, ctx, request, h)
		cancel()
		var refusal *Refusal
		if payload != nil || pid != 0 || !errors.As(err, &refusal) || refusal.Code != "recovery_timeout" {
			t.Fatal("earlier deadline was renewed or mislabeled")
		}
		if expired && (h.starts != 0 || len(w.bytes()) != 0 || len(h.calls) != 0) {
			t.Fatal("expired request started process")
		}
	}
}

// This inert peer enforces request -> response while stdin OPEN -> ACK/close
// -> next stdout read. An early EOF read cannot pass using a preclosed fixture.
// A success plus buffered extra byte still sees the ACK before that byte.
type rootGrantsCompletionReader48 struct {
	reader    *bytes.Reader
	raw       []byte
	input     *rootGrantsWriter46
	offset    int
	postReads int
	ackSeen   bool
}

func (*rootGrantsCompletionReader48) Close() error { return nil }
func (r *rootGrantsCompletionReader48) Read(p []byte) (int, error) {
	wire := r.input.bytes()
	if len(wire) < 4 {
		return 0, errors.New("missing framed request")
	}
	n := int(binary.BigEndian.Uint32(wire[:4]))
	if n < 1 || n > 262144 || len(wire) < 4+n {
		return 0, errors.New("missing request body")
	}
	end := uint64(len(r.raw)) + 1
	if len(r.raw) >= 5 {
		end = 5 + uint64(binary.BigEndian.Uint32(r.raw[1:5]))
	}
	if uint64(r.offset) < end {
		if r.input.closeCount() != 0 || len(wire) != 4+n {
			return 0, errors.New("request prematurely closed or ACK before frame")
		}
	} else {
		r.postReads++
		// Model a helper waiting for ACK+EOF, not an already closed pipe.
		if r.input.closed != nil {
			select {
			case <-r.input.closed:
			case <-time.After(time.Second):
				return 0, errors.New("modeled helper still waiting for ACK/EOF")
			}
		}
		wire = r.input.bytes()
		if r.input.closeCount() != 1 {
			return 0, errors.New("post-frame read before stdin EOF")
		}
		want := wire[:4+n]
		if r.raw[0] == 0 {
			want = append(bytes.Clone(want), rootGrantsReferenceACK48(wire[4:4+n], r.raw[5:end])...)
		}
		if !bytes.Equal(wire, want) {
			return 0, errors.New("wrong ACK or ACK on refusal")
		}
		r.ackSeen = r.raw[0] == 0
	}
	got, err := r.reader.Read(p)
	r.offset += got
	return got, err
}

// Independent fixture encoding uses one contiguous explicit preimage, anchored
// by a literal digest below; it never calls the production ACK constructor.
func rootGrantsReferenceACK48(request, sealed []byte) []byte {
	preimage := append([]byte("keyvault-root-grants-completion/2"), 0)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(request)))
	preimage = append(preimage, request...)
	preimage = append(preimage, 0)
	preimage = binary.BigEndian.AppendUint32(preimage, uint32(len(sealed)))
	preimage = append(preimage, sealed...)
	digest := sha256.Sum256(preimage)
	return append([]byte("KVG2"), digest[:]...)
}

// Claim: exact 36-byte public ACK encoding, independently anchored by a literal
// SHA256 preimage/digest, with each exchanged byte/length/domain/status bound.
// Limit: a PUBLIC primitive vector, not a valid51 request or native execution.
func TestRootGrantsHelper48ACKVector(t *testing.T) {
	request := []byte(`{}`)
	sealed := []byte(`{"record":{},"envelope":{}}`)
	preimage, err := hex.DecodeString("6b65797661756c742d726f6f742d6772616e74732d636f6d706c6574696f6e2f3200000000027b7d000000001b7b227265636f7264223a7b7d2c22656e76656c6f7065223a7b7d7d")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("4b564732f26112e86e6279b36ba98a6469d3669191911916f072e06fcf77250111c5dd4f")
	if err != nil {
		t.Fatal(err)
	}
	got := rootGrantsCompletionACK(request, sealed)
	if !bytes.Equal(got[:], want) || !bytes.Equal(rootGrantsReferenceACK48(request, sealed), want) {
		t.Fatal("literal ACK mismatch")
	}
	literal := sha256.Sum256(preimage)
	if !bytes.Equal(literal[:], want[4:]) {
		t.Fatal("literal preimage mismatch")
	}
	for i := range preimage {
		mutated := bytes.Clone(preimage)
		mutated[i] ^= 1
		if bytes.Equal(mutated, preimage) {
			t.Fatal("no-op byte mutation")
		}
		h := sha256.Sum256(mutated)
		if bytes.Equal(h[:], want[4:]) {
			t.Fatal("domain/length/status/message byte unbound")
		}
	}
	for i := range request {
		changed := bytes.Clone(request)
		changed[i] ^= 1
		if rootGrantsCompletionACK(changed, sealed) == got {
			t.Fatal("request byte unbound")
		}
	}
	for i := range sealed {
		changed := bytes.Clone(sealed)
		changed[i] ^= 1
		if rootGrantsCompletionACK(request, changed) == got {
			t.Fatal("sealed byte unbound")
		}
	}
	if rootGrantsCompletionACK(append(bytes.Clone(request), ' '), sealed) == got || rootGrantsCompletionACK(request, append(bytes.Clone(sealed), ' ')) == got {
		t.Fatal("exact length unbound")
	}
	for i := range want {
		changed := bytes.Clone(want)
		changed[i] ^= 1
		if bytes.Equal(changed, got[:]) {
			t.Fatal("no-op ACK mutation")
		}
	}
}

type rootGrantsACKWriter48 struct {
	base     *rootGrantsWriter46
	mode     string
	cancel   context.CancelFunc
	acks     int
	mutateAt int
}

func (w *rootGrantsACKWriter48) Write(p []byte) (int, error) {
	if len(p) == 36 && bytes.Equal(p[:4], []byte("KVG2")) {
		w.acks++
		switch w.mode {
		case "ack-byte":
			changed := bytes.Clone(p)
			changed[w.mutateAt] ^= 1
			return w.base.Write(changed)
		case "ack-error":
			return 0, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
		case "ack-short":
			return w.base.Write(p[:35])
		case "ack-lost":
			return len(p), nil // peer sees no ACK; cannot falsely complete
		case "ack-corrupt":
			changed := bytes.Clone(p)
			changed[4] ^= 1
			return w.base.Write(changed)
		case "ack-extra":
			_, err := w.base.Write(append(bytes.Clone(p), 0))
			return len(p), err
		case "ack-cancel":
			w.cancel()
		}
	}
	return w.base.Write(p)
}
func (w *rootGrantsACKWriter48) Close() error {
	err := w.base.Close()
	if w.mode == "close-cancel" {
		w.cancel()
	}
	return err
}

func rootGrantsFixedError48(t *testing.T, err error, code string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Code != "recovery_"+code || strings.Contains(err.Error(), "SENTINEL") {
		t.Fatalf("wrong fixed refusal, wanted %s", code)
	}
}

// Claim: ACK write/short/lost/corrupt/extra and stdin-close faults cannot return
// public completion bytes; refusal has NO ACK and requires EOF AND exit0.
// Limits: injected pipe faults/inert peer, not a real signed helper or OS code.
func TestRootGrantsHelper48CompletionFaults(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	for _, mode := range []string{"ack-error", "ack-short", "ack-lost", "ack-corrupt", "ack-extra", "ack-cancel", "close-cancel"} {
		t.Run(mode, func(t *testing.T) {
			h, base := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := &rootGrantsACKWriter48{base: base, mode: mode, cancel: cancel}
			h.child.input = w
			payload, pid, err := rootGrantsExchange46(t, ctx, request, h)
			if payload != nil || pid != 0 || w.acks != 1 {
				t.Fatal("ACK fault returned completion or retried")
			}
			want := "private_protocol_error"
			if mode == "ack-cancel" || mode == "close-cancel" {
				want = "canceled"
			}
			rootGrantsFixedError48(t, err, want)
			if h.starts != 1 || h.terms != 1 || h.waits != 1 {
				t.Fatal("fault cleanup/retry")
			}
		})
	}
	for _, mode := range []string{"valid", "nonzero-exit", "trailing", "close"} {
		t.Run("refusal/"+mode, func(t *testing.T) {
			frame := rootGrantsFrame46(1, []byte{0, 0, 0, 20})
			if mode == "trailing" {
				frame = append(frame, 0)
			}
			h, w := rootGrantsHostFixture46(frame)
			if mode == "nonzero-exit" {
				h.exitErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
			}
			if mode == "close" {
				w.closeErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
			}
			payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
			if payload != nil || pid != 0 || len(w.bytes()) != 4+len(request) {
				t.Fatal("refusal ACK/output")
			}
			want := "private_protocol_error"
			if mode == "valid" {
				want = "input_canceled"
			}
			rootGrantsFixedError48(t, err, want)
			if h.starts != 1 || h.waits != 1 || !reflect.DeepEqual(h.calls, []int{0, 73}) {
				t.Fatal("refusal retried/rechecked dead peer")
			}
		})
	}
}

// Callbacks are TEST ONLY, at actual I/O/verification boundaries. None can be
// configured through the production factory, public facade or helper request.
type rootGrantsPhaseWriter48 struct {
	io.WriteCloser
	part    int
	onPart  func(int)
	onClose func()
}

func (w *rootGrantsPhaseWriter48) Write(p []byte) (int, error) {
	w.part++
	if w.onPart != nil {
		w.onPart(w.part)
	}
	return w.WriteCloser.Write(p)
}
func (w *rootGrantsPhaseWriter48) Close() error {
	if w.onClose != nil {
		w.onClose()
	}
	return w.WriteCloser.Close()
}

type rootGrantsPhaseReader48 struct {
	io.ReadCloser
	part   int
	onPart func(int)
}

func (r *rootGrantsPhaseReader48) Read(p []byte) (int, error) {
	r.part++
	if r.onPart != nil {
		r.onPart(r.part)
	}
	return r.ReadCloser.Read(p)
}

// Claim: cancellation at EACH phase has fixed canceled14, no completion/plan,
// one actual-child cleanup/no retry, including ACK and waiting for exit. The
// phase is actually reached, not an assertion on wrapper bookkeeping alone.
// Limit: inert I/O/code/process; no real signal/TTY/code-identity conformance.
func TestRootGrantsHelper48CancelEveryPhase(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	for _, phase := range []string{"own", "start", "initial-pid", "request-length", "request-body", "response-header", "response-body", "live-pid", "ack", "stdin-close", "post-ack-read", "exit"} {
		t.Run(phase, func(t *testing.T) {
			h, base := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			entered := make(chan struct{})
			var once sync.Once
			trigger := func() { once.Do(func() { close(entered); cancel() }) }
			h.onVerify = func(_ int, call int) {
				if (phase == "own" && call == 1) || (phase == "initial-pid" && call == 2) || (phase == "live-pid" && call == 3) {
					trigger()
				}
			}
			if phase == "start" {
				h.onStart = trigger
			}
			h.child.input = &rootGrantsPhaseWriter48{WriteCloser: base, onPart: func(part int) {
				if (phase == "request-length" && part == 1) || (phase == "request-body" && part == 2) || (phase == "ack" && part == 3) {
					trigger()
				}
			}, onClose: func() {
				if phase == "stdin-close" {
					trigger()
				}
			}}
			h.child.output = &rootGrantsPhaseReader48{ReadCloser: h.child.output, onPart: func(part int) {
				if (phase == "response-header" && part == 1) || (phase == "response-body" && part == 2) || (phase == "post-ack-read" && part == 3) {
					trigger()
				}
			}}
			wait := h.child.wait
			h.child.wait = func() error {
				if phase == "exit" {
					trigger()
				}
				return wait()
			}
			payload, pid, err := rootGrantsExchange46(t, ctx, request, h)
			rootGrantsFixedError48(t, err, "canceled")
			select {
			case <-entered:
			default:
				t.Fatal("canceled phase never entered")
			}
			if payload != nil || pid != 0 {
				t.Fatal("cancellation returned completion")
			}
			h.mu.Lock()
			starts, terms, kills, waits := h.starts, h.terms, h.kills, h.waits
			h.mu.Unlock()
			if starts > 1 || terms > 1 || waits > 1 || kills != 0 {
				t.Fatal("phase cancellation retried/signaled another child")
			}
			if phase == "own" && (starts != 0 || len(base.bytes()) != 0) {
				t.Fatal("canceled own admission started")
			}
			if phase != "own" && (starts != 1 || waits != 1) {
				t.Fatal("owned child not reaped exactly once")
			}
		})
	}
}

// Claim: the SAME earlier caller deadline expires in ACK/EOF/exit after the
// earlier phases have run; no new phase budget can outlive it. The callback
// waits for the real inherited Done instead of sleeping or asserting a clock
// field. Limit: short caller deadlines; 900s real-time/native NOT measured.
func TestRootGrantsHelper48OriginalDeadlineThroughCompletion(t *testing.T) {
	if rootGrantsAttemptLimit != 900*time.Second || rootGrantsHelperGrace != 2*time.Second {
		t.Fatal("agreed absolute cap/cleanup grace changed")
	}
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	for _, phase := range []string{"ack", "stdin-close", "post-ack-read", "exit"} {
		t.Run(phase, func(t *testing.T) {
			h, base := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
			deadline := time.Now().Add(250 * time.Millisecond)
			ctx, cancel := context.WithDeadline(context.Background(), deadline)
			defer cancel()
			entered := make(chan struct{})
			released := make(chan struct{})
			var once sync.Once
			block := func() { once.Do(func() { close(entered); <-ctx.Done(); close(released) }) }
			h.child.input = &rootGrantsPhaseWriter48{WriteCloser: base, onPart: func(part int) {
				if phase == "ack" && part == 3 {
					block()
				}
			}, onClose: func() {
				if phase == "stdin-close" {
					block()
				}
			}}
			h.child.output = &rootGrantsPhaseReader48{ReadCloser: h.child.output, onPart: func(part int) {
				if phase == "post-ack-read" && part == 3 {
					block()
				}
			}}
			wait := h.child.wait
			h.child.wait = func() error {
				if phase == "exit" {
					block()
				}
				return wait()
			}
			payload, pid, err := rootGrantsExchange46(t, ctx, request, h)
			rootGrantsFixedError48(t, err, "timeout")
			select {
			case <-entered:
			default:
				t.Fatal("deadline phase not entered")
			}
			select {
			case <-released:
			case <-time.After(time.Second):
				t.Fatal("original deadline did not release phase")
			}
			if payload != nil || pid != 0 {
				t.Fatal("deadline returned completion")
			}
			if got, _ := ctx.Deadline(); got != deadline {
				t.Fatal("caller deadline changed")
			}
			h.mu.Lock()
			starts, waits, terms := h.starts, h.waits, h.terms
			h.mu.Unlock()
			if starts != 1 || waits != 1 || terms > 1 {
				t.Fatal("deadline lifecycle renewed/retried")
			}
		})
	}
}

type rootGrantsEOFError48 struct {
	io.ReadCloser
	reads int
}

func (r *rootGrantsEOFError48) Read(p []byte) (int, error) {
	r.reads++
	if r.reads == 3 {
		return 0, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	}
	return r.ReadCloser.Read(p)
}

// Claim: each of the exact36 ACK bytes is compared by the independent modeled
// peer; a distinct changed ACK or failed post-ACK EOF cannot yield completion.
// This is NOT a native ACK verifier/transport qualification or code identity.
func TestRootGrantsHelper48ACKBytesAndLostEOF(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/1")
	for i := 0; i < 36; i++ {
		h, w := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
		fault := &rootGrantsACKWriter48{base: w, mode: "ack-byte", mutateAt: i}
		h.child.input = fault
		payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
		rootGrantsFixedError48(t, err, "private_protocol_error")
		wire := w.bytes()
		want := rootGrantsReferenceACK48(request, sealed)
		if payload != nil || pid != 0 || fault.acks != 1 || len(wire) != 4+len(request)+36 || bytes.Equal(wire[4+len(request):], want) {
			t.Fatal("ACK mutation was absent or admitted")
		}
		for j := range want {
			if (wire[4+len(request)+j] != want[j]) != (i == j) {
				t.Fatal("wrong byte mutated")
			}
		}
		if h.starts != 1 || h.waits != 1 || h.terms != 1 {
			t.Fatal("ACK byte failure retried")
		}
	}
	h, w := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
	h.child.output = &rootGrantsEOFError48{ReadCloser: h.child.output}
	payload, pid, err := rootGrantsExchange46(t, context.Background(), request, h)
	rootGrantsFixedError48(t, err, "private_protocol_error")
	if payload != nil || pid != 0 || !bytes.Equal(w.bytes()[4+len(request):], rootGrantsReferenceACK48(request, sealed)) || w.closeCount() < 1 || h.starts != 1 || h.waits != 1 {
		t.Fatal("lost EOF admitted or bypassed ACK")
	}
}

type rootGrantsBlockedACK48 struct {
	base              *rootGrantsWriter46
	pipe              *io.PipeWriter
	entered, released chan struct{}
}

func (w *rootGrantsBlockedACK48) Write(p []byte) (int, error) {
	if len(p) == 36 && bytes.Equal(p[:4], []byte("KVG2")) {
		close(w.entered)
		n, err := w.pipe.Write(p) // deliberately no peer reader: actual blocked ACK
		close(w.released)
		return n, err
	}
	return w.base.Write(p)
}
func (w *rootGrantsBlockedACK48) Close() error { _ = w.pipe.Close(); return w.base.Close() }

// Claim: actual blocked io.Pipe ACK write is released by cancellation/owned
// pipe closure, one TERM/wait, no result or retry. Limits: inert process only;
// real signed-child signal/code/TTY cleanup remains a separate native lane.
func TestRootGrantsHelper48BlockedACKCancellation(t *testing.T) {
	request, sealed, _, _ := rootGrantsSealedFixture46(t, "keyvault-recovery/2")
	h, base := rootGrantsHostFixture46(rootGrantsFrame46(0, sealed))
	reader, writer := io.Pipe()
	defer reader.Close()
	w := &rootGrantsBlockedACK48{base: base, pipe: writer, entered: make(chan struct{}), released: make(chan struct{})}
	h.child.input = w
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		payload, pid, err := rootGrantsExchange46(t, ctx, request, h)
		rootGrantsFixedError48(t, err, "canceled")
		if payload != nil || pid != 0 {
			t.Error("blocked ACK returned completion")
		}
	}()
	select {
	case <-w.entered:
	case <-time.After(time.Second):
		t.Fatal("ACK write was never reached")
	}
	cancel()
	select {
	case <-w.released:
	case <-time.After(time.Second):
		t.Fatal("owned pipe close did not unblock ACK")
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("ACK cancellation did not return")
	}
	if len(base.bytes()) != 4+len(request) || h.starts != 1 || h.waits != 1 || h.terms != 1 || h.kills != 0 || !reflect.DeepEqual(h.calls, []int{0, 73, 73}) {
		t.Fatal("ACK cancellation renewed/retried/changed PID")
	}
}
