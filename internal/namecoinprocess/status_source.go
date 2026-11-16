//go:build darwin || linux

package namecoinprocess

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const (
	statusFrameBytes         = 80
	statusVersion            = 1
	statusEventEffectStarted = 1
	statusEventNativeDone    = 2
)

var ErrInvalidStatusStream = errors.New("invalid native status stream")

// StatusExpectation is independently computed from frozen public inputs. The
// helper's dedicated status pipe is the only allowed source for native phase
// observations; stdout, exit status and caller-generated booleans are not.
type StatusExpectation struct {
	Mode           RunnerMode
	AttemptBinding [32]byte
}

// StatusRecord contains only observations decoded from the dedicated child
// status pipe. The process adapter assigns its retained child handle and
// monotonic timestamp after accepting each record.
type StatusRecord struct {
	Kind   RunnerEventKind
	Digest [32]byte
}

// StatusObservationSource reads concurrently with the child, bounds the
// stream, validates each complete frame and attempt binding, and calls emit as
// each record arrives. It returns nil only after the exact mode-specific event
// sequence and pipe EOF. A local close or read error is not EOF.
type StatusObservationSource interface {
	ReadStatus(context.Context, io.Reader, StatusExpectation, func(StatusRecord) error) (eof bool, err error)
}

// FramedStatusSource implements the agreed process/1 80-byte status protocol.
// After any malformed record or callback failure it discards the bounded
// stream through actual EOF, so the caller can report the fault and EOF as
// separate observations before deciding the attempt. It authenticates no
// writer: the process adapter must independently establish the fixed helper,
// exclusive descriptor inheritance and retained-child identity.
type FramedStatusSource struct{}

var _ StatusObservationSource = FramedStatusSource{}

func (FramedStatusSource) ReadStatus(ctx context.Context, reader io.Reader, expected StatusExpectation, emit func(StatusRecord) error) (bool, error) {
	if ctx == nil || ctx.Err() != nil || reader == nil || emit == nil {
		return false, ErrInvalidStatusStream
	}
	want, err := statusEvents(expected.Mode)
	if err != nil {
		return false, err
	}
	var frame [statusFrameBytes]byte
	var frameBytes int
	var seen int
	var firstErr error
	var input [statusFrameBytes]byte
	zeroReads := 0
	for {
		n, readErr := reader.Read(input[:])
		if n < 0 || n > len(input) {
			if firstErr == nil {
				firstErr = ErrInvalidStatusStream
			}
			n = 0
		}
		if n > 0 {
			zeroReads = 0
			if firstErr == nil {
				remaining := input[:n]
				for len(remaining) > 0 {
					if seen >= len(want) {
						firstErr = ErrInvalidStatusStream
						break
					}
					take := min(len(remaining), statusFrameBytes-frameBytes)
					copy(frame[frameBytes:frameBytes+take], remaining[:take])
					frameBytes += take
					remaining = remaining[take:]
					if frameBytes != statusFrameBytes {
						continue
					}
					record, frameErr := decodeStatusFrame(frame[:], expected, want[seen])
					if frameErr != nil {
						firstErr = frameErr
						break
					}
					if emitErr := emit(record); emitErr != nil {
						firstErr = emitErr
						break
					}
					seen++
					frameBytes = 0
				}
			}
		}
		if readErr == io.EOF {
			if firstErr == nil && (frameBytes != 0 || seen != len(want)) {
				firstErr = ErrInvalidStatusStream
			}
			return true, firstErr
		}
		if readErr != nil {
			if firstErr != nil {
				return false, firstErr
			}
			return false, ErrInvalidStatusStream
		}
		if n == 0 {
			zeroReads++
			if zeroReads >= 100 {
				if firstErr != nil {
					return false, firstErr
				}
				return false, io.ErrNoProgress
			}
		}
	}
}

func decodeStatusFrame(raw []byte, expected StatusExpectation, want byte) (StatusRecord, error) {
	var record StatusRecord
	if len(raw) != statusFrameBytes || !bytes.Equal(raw[:4], []byte("KVNS")) ||
		binary.BigEndian.Uint16(raw[4:6]) != statusVersion || raw[7] != 0 ||
		!bytes.Equal(raw[8:40], expected.AttemptBinding[:]) ||
		!allZero(raw[72:80]) {
		return record, ErrInvalidStatusStream
	}
	if raw[6] != want {
		return record, ErrInvalidStatusStream
	}
	event := RunnerNativeCompleted
	if raw[6] == statusEventEffectStarted {
		event = RunnerEffectStarted
	} else if raw[6] != statusEventNativeDone {
		return record, ErrInvalidStatusStream
	}
	copy(record.Digest[:], raw[40:72])
	if event == RunnerEffectStarted && record.Digest != [32]byte{} ||
		event == RunnerNativeCompleted && expected.Mode == RunnerInitialize && record.Digest != [32]byte{} {
		return StatusRecord{}, ErrInvalidStatusStream
	}
	record.Kind = event
	return record, nil
}

func statusEvents(mode RunnerMode) ([]byte, error) {
	switch mode {
	case RunnerSign, RunnerInitialize:
		return []byte{statusEventEffectStarted, statusEventNativeDone}, nil
	case RunnerReconcile:
		return []byte{statusEventNativeDone}, nil
	default:
		return nil, ErrInvalidStatusStream
	}
}

func allZero(b []byte) bool {
	for _, value := range b {
		if value != 0 {
			return false
		}
	}
	return true
}

// StatusExpectation derives the binding only from validated, frozen public
// inputs. The account PIN bytes are deliberately excluded.
func (p Prepared) StatusExpectation() (StatusExpectation, error) {
	var mode RunnerMode
	switch p.mode {
	case SignPSBT:
		mode = RunnerSign
	case Reconcile:
		mode = RunnerReconcile
	case InitializeJournal:
		mode = RunnerInitialize
	default:
		return StatusExpectation{}, ErrInvalidStatusStream
	}
	selection := p.config.Selection
	if !p.hasOperationSHA256 || selection.Group == "" || selection.Account == "" ||
		len(p.profile) == 0 || sha256.Sum256(p.profile) != p.profileSHA256 {
		return StatusExpectation{}, ErrInvalidStatusStream
	}
	binding := statusAttemptBinding(string(p.mode), selection.Group, selection.Account, p.profileSHA256, p.operationSHA256)
	return StatusExpectation{Mode: mode, AttemptBinding: binding}, nil
}

// StatusExpectation binds reconcile to the exact submitted query before any
// native historical lookup. The parent never needs journal bytes to validate
// the status frame's attempt binding.
func (r ReconcileInput) StatusExpectation() (StatusExpectation, error) {
	profile := r.public.ProfileBytes()
	selection := r.public.NativeSelection().Selection
	if len(profile) == 0 || selection.Group == "" || selection.Account == "" || !r.hasQuerySHA256 {
		return StatusExpectation{}, ErrInvalidStatusStream
	}
	profileSHA256 := sha256.Sum256(profile)
	binding := statusAttemptBinding(string(Reconcile), selection.Group, selection.Account, profileSHA256, r.querySHA256)
	return StatusExpectation{Mode: RunnerReconcile, AttemptBinding: binding}, nil
}

func statusAttemptBinding(mode, group, account string, profile, operation [32]byte) [32]byte {
	data := []byte("keyvault-namecoin-process-observation/1\x00")
	for _, field := range [][]byte{[]byte(mode), []byte(group), []byte(account), profile[:], operation[:]} {
		data = binary.BigEndian.AppendUint32(data, uint32(len(field)))
		data = append(data, field...)
	}
	return sha256.Sum256(data)
}

// RequireStatusSource refuses before child start until the agreed reader is
// installed. It must never turn missing evidence into success or a submission.
func RequireStatusSource(source StatusObservationSource) error {
	if source == nil {
		return namecoinwire.NewFailure(namecoinwire.HelperNotAdmitted, false)
	}
	return nil
}
