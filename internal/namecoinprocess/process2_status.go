package namecoinprocess

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
)

const (
	Process2StatusFrameBytes   = 80
	Process2SuccessStatusBytes = 2 * Process2StatusFrameBytes
)

var errInvalidProcess2Status = errors.New("invalid process2 status")

type Process2StatusEvent uint8

const (
	Process2EffectStarted   Process2StatusEvent = 1
	Process2NativeCompleted Process2StatusEvent = 2
)

// Process2StatusFrame is the fixed status-r3 frame. The result digest is zero
// for effect-started and binds exact fd3 bytes for native-completed.
type Process2StatusFrame struct {
	Event          Process2StatusEvent
	AttemptBinding [32]byte
	ResultSHA256   [32]byte
}

func EncodeProcess2StatusFrame(frame Process2StatusFrame) ([]byte, error) {
	if frame.Event != Process2EffectStarted && frame.Event != Process2NativeCompleted {
		return nil, errInvalidProcess2Status
	}
	if frame.Event == Process2EffectStarted && frame.ResultSHA256 != ([32]byte{}) {
		return nil, errInvalidProcess2Status
	}
	raw := make([]byte, Process2StatusFrameBytes)
	copy(raw[:4], "KVNS")
	binary.BigEndian.PutUint16(raw[4:6], 1)
	raw[6] = byte(frame.Event)
	copy(raw[8:40], frame.AttemptBinding[:])
	copy(raw[40:72], frame.ResultSHA256[:])
	return raw, nil
}

func DecodeProcess2StatusFrame(raw []byte) (Process2StatusFrame, error) {
	var frame Process2StatusFrame
	if len(raw) != Process2StatusFrameBytes || !bytes.Equal(raw[:4], []byte("KVNS")) || binary.BigEndian.Uint16(raw[4:6]) != 1 || raw[7] != 0 || !bytes.Equal(raw[72:80], make([]byte, 8)) {
		return frame, errInvalidProcess2Status
	}
	frame.Event = Process2StatusEvent(raw[6])
	if frame.Event != Process2EffectStarted && frame.Event != Process2NativeCompleted {
		return Process2StatusFrame{}, errInvalidProcess2Status
	}
	copy(frame.AttemptBinding[:], raw[8:40])
	copy(frame.ResultSHA256[:], raw[40:72])
	if frame.Event == Process2EffectStarted && frame.ResultSHA256 != ([32]byte{}) {
		return Process2StatusFrame{}, errInvalidProcess2Status
	}
	return frame, nil
}

// ValidateProcess2SuccessStatus accepts only the exact two-frame success
// transcript. EOF is checked by the bounded fd4 reader in the launch adapter.
func ValidateProcess2SuccessStatus(raw []byte, attempt [32]byte, exactResult []byte) error {
	if len(raw) != Process2SuccessStatusBytes || len(exactResult) == 0 || len(exactResult) > MaxProcessResultBytes {
		return errInvalidProcess2Status
	}
	started, err := DecodeProcess2StatusFrame(raw[:Process2StatusFrameBytes])
	if err != nil {
		return err
	}
	completed, err := DecodeProcess2StatusFrame(raw[Process2StatusFrameBytes:])
	if err != nil {
		return err
	}
	digest := sha256.Sum256(exactResult)
	if started.Event != Process2EffectStarted || completed.Event != Process2NativeCompleted ||
		started.AttemptBinding != attempt || completed.AttemptBinding != attempt || completed.ResultSHA256 != digest {
		return errInvalidProcess2Status
	}
	return nil
}
