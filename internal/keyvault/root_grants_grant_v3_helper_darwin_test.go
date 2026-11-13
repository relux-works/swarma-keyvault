//go:build darwin && cgo

package keyvault

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type grantV3IPCChild struct {
	request        []byte
	output         io.WriteCloser
	input          io.Reader
	finalBudget    time.Duration
	plaintextOwned *atomic.Bool
	signed         *atomic.Bool
	result         chan error
}

func (p *grantV3IPCChild) run() {
	defer close(p.result)
	defer p.output.Close()
	var prefix [4]byte
	if _, err := io.ReadFull(p.input, prefix[:]); err != nil {
		p.result <- err
		return
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > 262144 {
		p.result <- io.ErrUnexpectedEOF
		return
	}
	request := make([]byte, int(length))
	if _, err := io.ReadFull(p.input, request); err != nil || !bytes.Equal(request, p.request) {
		p.result <- io.ErrUnexpectedEOF
		return
	}
	for stage := byte(1); stage <= 2; stage++ {
		if stage == 2 {
			p.plaintextOwned.Store(true)
		}
		budget := rootGrantsGrantV3AttemptLimit
		if stage == 2 && p.finalBudget > 0 {
			budget = p.finalBudget
		}
		frame, err := rootGrantsGrantV3RecheckFrame(stage, budget)
		if err != nil || writeTestGrantFrame(p.output, frame) != nil {
			p.result <- io.ErrClosedPipe
			return
		}
		status, code, err := readTestGrantControl(p.input)
		if err != nil {
			if err == io.EOF || err == io.ErrClosedPipe {
				p.result <- nil
				return
			}
			p.result <- err
			return
		}
		if status != 0 {
			if writeTestGrantFrame(p.output, grantV3RefusalFrame(code)) != nil {
				p.result <- io.ErrClosedPipe
				return
			}
			p.result <- nil
			return
		}
	}
	plan, err := rootGrantsGrantV3PlanFromHelperRequest(request)
	if err != nil {
		p.result <- err
		return
	}
	var wire rootGrantsGrantV3HelperRequest
	_ = DecodeSingleJSON(request, &wire)
	var review rootGrantsGrantV3HelperReview
	_ = DecodeSingleJSON(wire.Review, &review)
	var message struct {
		MessageSHA256 string `json:"message_sha256"`
	}
	_ = DecodeSingleJSON(wire.Review, &message)
	digest, err := hex.DecodeString(message.MessageSHA256)
	if err != nil || len(digest) != 32 {
		p.result <- io.ErrUnexpectedEOF
		return
	}
	var secret, aux [32]byte
	secret[31] = 3 // Public synthetic key used by the existing operation fixture.
	signature, err := signNostrWithAux(secret[:], digest, aux)
	clear(secret[:])
	if err != nil || plan.VerifySignature(signature) != nil {
		p.result <- io.ErrUnexpectedEOF
		return
	}
	p.signed.Store(true)
	if writeTestGrantFrame(p.output, append([]byte{0, 0, 0, 0, 64}, signature...)) != nil {
		p.result <- io.ErrClosedPipe
		return
	}
	var acknowledgement [36]byte
	ackExpected := rootGrantsCompletionACK(request, signature)
	if _, err := io.ReadFull(p.input, acknowledgement[:]); err != nil || !bytes.Equal(acknowledgement[:], ackExpected[:]) {
		p.result <- io.ErrUnexpectedEOF
		return
	}
	var extra [1]byte
	n, err := p.input.Read(extra[:])
	if n != 0 || err != io.EOF {
		p.result <- io.ErrUnexpectedEOF
		return
	}
	p.result <- nil
}

func writeTestGrantFrame(w io.Writer, frame []byte) error {
	n, err := w.Write(frame)
	if err != nil {
		return err
	}
	if n != len(frame) {
		return io.ErrShortWrite
	}
	return nil
}

func readTestGrantControl(r io.Reader) (byte, uint32, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return 0, 0, err
	}
	n := binary.BigEndian.Uint32(header[1:])
	if header[0] == 0 && n == 0 {
		return 0, 0, nil
	}
	if header[0] != 1 || n != 4 {
		return 0, 0, io.ErrUnexpectedEOF
	}
	var raw [4]byte
	if _, err := io.ReadFull(r, raw[:]); err != nil {
		return 0, 0, err
	}
	return 1, binary.BigEndian.Uint32(raw[:]), nil
}

func grantV3RefusalFrame(code uint32) []byte {
	frame := []byte{1, 0, 0, 0, 4, 0, 0, 0, 0}
	binary.BigEndian.PutUint32(frame[5:], code)
	return frame
}

type grantV3IPCProcessHost struct {
	request        []byte
	plaintextOwned atomic.Bool
	signed         atomic.Bool
	result         chan error
	finalBudget    time.Duration
}

func (h *grantV3IPCProcessHost) verify(pid int, pin []byte) error {
	if pid != 0 && pid != 7319 || pid == 0 && len(pin) != 0 || pid != 0 && len(pin) != 20 {
		return io.ErrUnexpectedEOF
	}
	return nil
}

func (h *grantV3IPCProcessHost) start() (*rootGrantsHelperChild, error) {
	childInput, parentInput := io.Pipe()
	parentOutput, childOutput := io.Pipe()
	h.result = make(chan error, 1)
	peer := &grantV3IPCChild{request: bytes.Clone(h.request), input: childInput, output: childOutput,
		plaintextOwned: &h.plaintextOwned, signed: &h.signed, result: h.result, finalBudget: h.finalBudget}
	go peer.run()
	var waitOnce sync.Once
	var waitErr error
	wait := func() error { waitOnce.Do(func() { waitErr = <-h.result }); return waitErr }
	return &rootGrantsHelperChild{pid: 7319, input: parentInput, output: parentOutput,
		term: func() error { return nil }, kill: func() error { return nil }, wait: wait}, nil
}

type grantV3IPCReadVault struct {
	mu       sync.Mutex
	snapshot RootGrantsSigningSnapshot
	calls    int
	entered  chan struct{}
	blockAt  int
}

func (v *grantV3IPCReadVault) ReadRootGrantsForSigning(ctx context.Context, _ RootGrantsAddress, _ string) (RootGrantsSigningSnapshot, error) {
	v.mu.Lock()
	v.calls++
	call := v.calls
	if call == v.blockAt && v.entered != nil {
		close(v.entered)
		v.mu.Unlock()
		<-ctx.Done()
		return RootGrantsSigningSnapshot{}, ctx.Err()
	}
	snapshot := RootGrantsSigningSnapshot{Metadata: bytes.Clone(v.snapshot.Metadata), Envelope: bytes.Clone(v.snapshot.Envelope),
		PairMetadata: bytes.Clone(v.snapshot.PairMetadata)}
	v.mu.Unlock()
	return snapshot, nil
}

func grantV3ProductionRequest(t *testing.T) (RootGrantsGrantV3SignRequest, []byte, RootGrantsSigningSnapshot, []byte) {
	t.Helper()
	q, authority, snapshot := liveGrantV3OperationFixture(t)
	helper := &grantV3OperationHelper{}
	if _, err := SignRootGrantsGrantV3With(context.Background(), q, authority, &grantV3OperationVault{snapshot: snapshot}, helper); err != nil {
		t.Fatal(err)
	}
	return q, authority, snapshot, helper.request
}

func TestRootGrantsGrantV3HelperExchangeUsesParentVaultRecheckFrames(t *testing.T) {
	_, authority, snapshot, request := grantV3ProductionRequest(t)
	vault := &grantV3IPCReadVault{snapshot: snapshot}
	checks := 0
	check := func(ctx context.Context, raw []byte) error {
		checks++
		if _, ok := ctx.Deadline(); !ok {
			return rootGrantsGrantV3Failed("private_protocol_error", "recheck", false)
		}
		return rootGrantsGrantV3CheckForHelperWithContext(ctx, raw, vault, func(RootGrantsAddress) ([]byte, error) {
			return bytes.Clone(authority), nil
		})
	}
	host := &grantV3IPCProcessHost{request: request}
	pin := bytes.Repeat([]byte{7}, 20)
	signature, pid, err := rootGrantsGrantV3HelperExchange(context.Background(), request, pin, host, check)
	if err != nil || pid != 7319 || checks != 2 || vault.calls != 2 || !host.signed.Load() {
		t.Fatalf("parent did not complete both admitted rechecks before signature: pid=%d checks=%d reads=%d signed=%v err=%v",
			pid, checks, vault.calls, host.signed.Load(), err)
	}
	plan, err := rootGrantsGrantV3PlanFromHelperRequest(request)
	if err != nil || plan.VerifySignature(signature) != nil {
		t.Fatal("parent returned an unverified signature", err)
	}
}

func TestRootGrantsGrantV3CanceledFinalParentReadCannotSignOwnedPlaintext(t *testing.T) {
	_, authority, snapshot, request := grantV3ProductionRequest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	vault := &grantV3IPCReadVault{snapshot: snapshot, entered: make(chan struct{}), blockAt: 2}
	check := func(ctx context.Context, raw []byte) error {
		return rootGrantsGrantV3CheckForHelperWithContext(ctx, raw, vault, func(RootGrantsAddress) ([]byte, error) {
			return bytes.Clone(authority), nil
		})
	}
	host := &grantV3IPCProcessHost{request: request}
	done := make(chan error, 1)
	go func() {
		_, _, err := rootGrantsGrantV3HelperExchange(ctx, request, bytes.Repeat([]byte{7}, 20), host, check)
		done <- err
	}()
	select {
	case <-vault.entered:
	case <-time.After(time.Second):
		t.Fatal("final parent vault read did not start")
	}
	if !host.plaintextOwned.Load() {
		t.Fatal("test did not reach the final read after helper-owned plaintext")
	}
	cancel()
	select {
	case err := <-done:
		var failure *RootGrantsGrantV3Failure
		if !errors.As(err, &failure) || failure.Code != "canceled" || host.signed.Load() {
			t.Fatalf("canceled final read reached signing: signed=%v err=%v", host.signed.Load(), err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("canceled final vault read did not terminate the helper exchange")
	}
}

func TestRootGrantsGrantV3FinalReadDeadlineCannotSignOwnedPlaintext(t *testing.T) {
	_, authority, snapshot, request := grantV3ProductionRequest(t)
	vault := &grantV3IPCReadVault{snapshot: snapshot, entered: make(chan struct{}), blockAt: 2}
	check := func(ctx context.Context, raw []byte) error {
		return rootGrantsGrantV3CheckForHelperWithContext(ctx, raw, vault, func(RootGrantsAddress) ([]byte, error) {
			return bytes.Clone(authority), nil
		})
	}
	host := &grantV3IPCProcessHost{request: request, finalBudget: 500 * time.Millisecond}
	_, _, err := rootGrantsGrantV3HelperExchange(context.Background(), request, bytes.Repeat([]byte{7}, 20), host, check)
	select {
	case <-vault.entered:
	case <-time.After(time.Second):
		t.Fatal("final parent vault read did not start before its deadline")
	}
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure.Code != "timeout" || !host.plaintextOwned.Load() || host.signed.Load() {
		t.Fatalf("expired final parent read reached signing: plaintext=%v signed=%v err=%v",
			host.plaintextOwned.Load(), host.signed.Load(), err)
	}
}

func TestRootGrantsGrantV3RecheckFrameRejectsMutation(t *testing.T) {
	frame, err := rootGrantsGrantV3RecheckFrame(1, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	frame[len(frame)-1] = 'X'
	parsed, _, _ := rootGrantsReadGrantV3ExchangeFrame(bytes.NewReader(frame))
	if parsed.err == nil {
		t.Fatal("mutated parent-check token was accepted")
	}
}
