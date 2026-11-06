package reviewedsession

import (
	"bytes"
	"encoding/binary"
	"io"
)

// framePayload works on an already bounded control buffer. It does not perform
// blocking reads or infer EOF on a live descriptor. A future live FD runner
// must enforce its monotonic deadline and detect extra input before proceeding.
func framePayload(raw []byte, max int) ([]byte, error) {
	if max < 1 || max > readyMax || len(raw) < 4 {
		return nil, errFrame
	}
	n := binary.BigEndian.Uint32(raw[:4])
	if n == 0 || uint64(n) > uint64(max) || uint64(len(raw)-4) != uint64(n) {
		return nil, errFrame
	}
	return bytes.Clone(raw[4:]), nil
}

// A failed/short write is terminal; never retry a partial READY publication.
func writeFrame(w io.Writer, payload []byte, max int) error {
	if w == nil || max < 1 || max > readyMax || len(payload) == 0 || len(payload) > max {
		return errFrame
	}
	buf := make([]byte, 4+len(payload))
	binary.BigEndian.PutUint32(buf[:4], uint32(len(payload)))
	copy(buf[4:], payload)
	n, err := w.Write(buf)
	if err != nil {
		return err
	}
	if n != len(buf) {
		return io.ErrShortWrite
	}
	return nil
}
