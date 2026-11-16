//go:build darwin || linux

package namecoinprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
)

func statusTestFrame(kind RunnerEventKind, binding, digest [32]byte) []byte {
	frame := make([]byte, statusFrameBytes)
	copy(frame[:4], "KVNS")
	binary.BigEndian.PutUint16(frame[4:6], statusVersion)
	switch kind {
	case RunnerEffectStarted:
		frame[6] = statusEventEffectStarted
	case RunnerNativeCompleted:
		frame[6] = statusEventNativeDone
	}
	copy(frame[8:40], binding[:])
	copy(frame[40:72], digest[:])
	return frame
}

func joinStatusFrames(frames ...[]byte) []byte {
	return bytes.Join(frames, nil)
}

func TestFramedStatusSourceAcceptsEveryModeSequence(t *testing.T) {
	binding := sha256.Sum256([]byte("attempt"))
	result := sha256.Sum256([]byte("public result"))
	tests := []struct {
		name   string
		mode   RunnerMode
		frames [][]byte
		kinds  []RunnerEventKind
	}{
		{name: "sign", mode: RunnerSign, frames: [][]byte{
			statusTestFrame(RunnerEffectStarted, binding, [32]byte{}),
			statusTestFrame(RunnerNativeCompleted, binding, result),
		}, kinds: []RunnerEventKind{RunnerEffectStarted, RunnerNativeCompleted}},
		{name: "reconcile", mode: RunnerReconcile, frames: [][]byte{
			statusTestFrame(RunnerNativeCompleted, binding, result),
		}, kinds: []RunnerEventKind{RunnerNativeCompleted}},
		{name: "initialize", mode: RunnerInitialize, frames: [][]byte{
			statusTestFrame(RunnerEffectStarted, binding, [32]byte{}),
			statusTestFrame(RunnerNativeCompleted, binding, [32]byte{}),
		}, kinds: []RunnerEventKind{RunnerEffectStarted, RunnerNativeCompleted}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var observed []StatusRecord
			eof, err := (FramedStatusSource{}).ReadStatus(context.Background(), bytes.NewReader(joinStatusFrames(test.frames...)),
				StatusExpectation{Mode: test.mode, AttemptBinding: binding}, func(record StatusRecord) error {
					observed = append(observed, record)
					return nil
				})
			if !eof || err != nil || len(observed) != len(test.kinds) {
				t.Fatalf("eof=%v err=%v records=%+v", eof, err, observed)
			}
			for i, kind := range test.kinds {
				if observed[i].Kind != kind {
					t.Fatalf("record %d kind=%d want=%d", i, observed[i].Kind, kind)
				}
			}
		})
	}
}

func TestFramedStatusSourceRejectsMalformedAndUnboundFrames(t *testing.T) {
	binding := sha256.Sum256([]byte("attempt"))
	other := sha256.Sum256([]byte("other attempt"))
	zero := [32]byte{}
	effect := statusTestFrame(RunnerEffectStarted, binding, zero)
	complete := statusTestFrame(RunnerNativeCompleted, binding, sha256.Sum256([]byte("result")))
	badMagic := bytes.Clone(effect)
	badMagic[0] ^= 1
	badVersion := bytes.Clone(effect)
	binary.BigEndian.PutUint16(badVersion[4:6], 2)
	badEvent := bytes.Clone(effect)
	badEvent[6] = 99
	badReserved := bytes.Clone(effect)
	badReserved[7] = 1
	badBinding := statusTestFrame(RunnerEffectStarted, other, zero)
	badEffectDigest := bytes.Clone(effect)
	badEffectDigest[40] = 1
	badTail := bytes.Clone(effect)
	badTail[79] = 1
	unknownInitDigest := bytes.Clone(statusTestFrame(RunnerNativeCompleted, binding, zero))
	unknownInitDigest[71] = 1
	wrongOrder := joinStatusFrames(complete, effect)
	duplicate := joinStatusFrames(effect, effect)
	extraFrame := joinStatusFrames(effect, complete, complete)
	trailingByte := append(joinStatusFrames(effect, complete), 0x7f)
	truncated := joinStatusFrames(effect, complete)[:statusFrameBytes+statusFrameBytes-1]
	cases := []struct {
		name   string
		mode   RunnerMode
		stream []byte
	}{
		{name: "missing", mode: RunnerSign},
		{name: "truncated", mode: RunnerSign, stream: truncated},
		{name: "bad magic", mode: RunnerSign, stream: joinStatusFrames(badMagic, complete)},
		{name: "unknown version", mode: RunnerSign, stream: joinStatusFrames(badVersion, complete)},
		{name: "unknown event", mode: RunnerSign, stream: joinStatusFrames(badEvent, complete)},
		{name: "reserved byte", mode: RunnerSign, stream: joinStatusFrames(badReserved, complete)},
		{name: "attempt binding", mode: RunnerSign, stream: joinStatusFrames(badBinding, complete)},
		{name: "effect digest", mode: RunnerSign, stream: joinStatusFrames(badEffectDigest, complete)},
		{name: "reserved tail", mode: RunnerSign, stream: joinStatusFrames(badTail, complete)},
		{name: "wrong order", mode: RunnerSign, stream: wrongOrder},
		{name: "duplicate", mode: RunnerSign, stream: duplicate},
		{name: "extra frame", mode: RunnerSign, stream: extraFrame},
		{name: "trailing byte", mode: RunnerSign, stream: trailingByte},
		{name: "init completion digest", mode: RunnerInitialize, stream: joinStatusFrames(effect, unknownInitDigest)},
		{name: "reconcile effect event", mode: RunnerReconcile, stream: joinStatusFrames(effect)},
		{name: "invalid mode", mode: RunnerMode(0), stream: nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			eof, err := (FramedStatusSource{}).ReadStatus(context.Background(), bytes.NewReader(test.stream),
				StatusExpectation{Mode: test.mode, AttemptBinding: binding}, func(StatusRecord) error {
					calls++
					return nil
				})
			if err == nil || (test.mode != RunnerMode(0) && !eof) {
				t.Fatalf("eof=%v err=%v calls=%d", eof, err, calls)
			}
		})
	}
}

func TestFramedStatusSourceReportsEOFSeparatelyAndDrainsAfterConsumerError(t *testing.T) {
	binding := sha256.Sum256([]byte("attempt"))
	stream := joinStatusFrames(
		statusTestFrame(RunnerEffectStarted, binding, [32]byte{}),
		statusTestFrame(RunnerNativeCompleted, binding, sha256.Sum256([]byte("result"))),
	)
	consumerErr := errors.New("consumer stopped accepting records")
	calls := 0
	eof, err := (FramedStatusSource{}).ReadStatus(context.Background(), bytes.NewReader(stream),
		StatusExpectation{Mode: RunnerSign, AttemptBinding: binding}, func(StatusRecord) error {
			calls++
			return consumerErr
		})
	if !eof || !errors.Is(err, consumerErr) || calls != 1 {
		t.Fatalf("eof=%v err=%v calls=%d", eof, err, calls)
	}

	readErr := errors.New("pipe read failed")
	eof, err = (FramedStatusSource{}).ReadStatus(context.Background(), &errorAfterBytes{data: stream, err: readErr},
		StatusExpectation{Mode: RunnerSign, AttemptBinding: binding}, func(StatusRecord) error { return nil })
	if eof || err == nil {
		t.Fatalf("local read error reported EOF: eof=%v err=%v", eof, err)
	}
}

type errorAfterBytes struct {
	data []byte
	err  error
}

func (r *errorAfterBytes) Read(p []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	n := copy(p, r.data)
	r.data = r.data[n:]
	return n, nil
}

func TestStatusAttemptBindingUsesLengthPrefixedPublicFields(t *testing.T) {
	profile := sha256.Sum256([]byte("profile digest"))
	operation := sha256.Sum256([]byte("operation digest"))
	got := statusAttemptBinding(string(SignPSBT), "fixture/recovery@1", "fixture/namecoin@1", profile, operation)
	data := []byte("keyvault-namecoin-process-observation/1\x00")
	for _, field := range [][]byte{[]byte("sign-psbt"), []byte("fixture/recovery@1"), []byte("fixture/namecoin@1"), profile[:], operation[:]} {
		data = binary.BigEndian.AppendUint32(data, uint32(len(field)))
		data = append(data, field...)
	}
	want := sha256.Sum256(data)
	if got != want {
		t.Fatalf("binding=%x want=%x", got, want)
	}
	changed := statusAttemptBinding(string(SignPSBT), "fixture/recovery@1", "fixture/namecoin@1", profile, sha256.Sum256([]byte("different operation")))
	if changed == got {
		t.Fatal("operation digest was not bound")
	}
}

func TestPreparedStatusExpectationBindsFrozenProfileAndOperation(t *testing.T) {
	profile := []byte("exact selected public profile")
	profileHash := sha256.Sum256(profile)
	operationHash := sha256.Sum256([]byte("exact request"))
	prepared := Prepared{
		mode: SignPSBT, profile: bytes.Clone(profile), profileSHA256: profileHash,
		config: namecoinpsbt.NativeSelection{Selection: namecoinpsbt.Selection{
			Group: "fixture/recovery@1", Account: "fixture/namecoin@1",
		}},
		operationSHA256: operationHash, hasOperationSHA256: true,
	}
	expectation, err := prepared.StatusExpectation()
	if err != nil || expectation.Mode != RunnerSign {
		t.Fatalf("expectation=%+v err=%v", expectation, err)
	}
	want := statusAttemptBinding(string(SignPSBT), "fixture/recovery@1", "fixture/namecoin@1", profileHash, operationHash)
	if expectation.AttemptBinding != want {
		t.Fatal("attempt binding did not include the frozen public input hashes")
	}
	prepared.pin = []byte("changed secret account PIN bytes")
	if changed, err := prepared.StatusExpectation(); err != nil || changed != expectation {
		t.Fatal("secret account PIN bytes entered the public attempt binding", err)
	}
	prepared.profile[0] ^= 1
	if _, err := prepared.StatusExpectation(); err == nil {
		t.Fatal("mutated frozen profile retained its binding")
	}
	prepared.profile[0] ^= 1
	prepared.hasOperationSHA256 = false
	if _, err := prepared.StatusExpectation(); err == nil {
		t.Fatal("missing operation digest produced a binding")
	}
}
