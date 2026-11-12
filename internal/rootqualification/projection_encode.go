package rootqualification

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"unicode/utf8"
)

type projectionWriter struct {
	bytes.Buffer
	invalid bool
}

func (w *projectionWriter) u32(n uint32) {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], n)
	w.Write(b[:])
	if w.Len() > 1048576 {
		w.invalid = true
	}
}
func (w *projectionWriter) count(n int) {
	if n < 0 || n > 64 {
		w.invalid = true
		return
	}
	w.u32(uint32(n))
}
func (w *projectionWriter) field(b []byte, max int) {
	if len(b) > max || w.Len() > 1048576-len(b)-4 {
		w.invalid = true
		return
	}
	w.u32(uint32(len(b)))
	w.Write(b)
}
func (w *projectionWriter) text(s string, max int) {
	if !utf8.ValidString(s) {
		w.invalid = true
		return
	}
	w.field([]byte(s), max)
}
func (w *projectionWriter) state(s string, names ...string) {
	for i, n := range names {
		if s == n {
			w.u32(uint32(i))
			return
		}
	}
	w.invalid = true
}

// EncodeNativeProjection preserves all observed fields/order/multiplicity. It
// normalizes only the Go representation of empty slices, never native forms.
// It cannot decide whether any owner, writer, partition or app is safe.
func EncodeNativeProjection(p Projection) ([]byte, error) {
	var w projectionWriter
	w.WriteString("KVQP1")
	w.u32(p.OwnerUID)
	w.u32(p.OwnerGID)
	w.u32(p.OwnerType)
	w.count(len(p.ACLs))
	if w.invalid {
		return nil, ErrProjection
	}
	for _, a := range p.ACLs {
		w.state(a.AuthorizationNamesState, "readable", "unreadable")
		w.count(len(a.Authorizations))
		if w.invalid {
			return nil, ErrProjection
		}
		for _, s := range a.Authorizations {
			w.text(s, 1024)
		}
		w.count(len(a.AuthorizationNumbers))
		if w.invalid {
			return nil, ErrProjection
		}
		for _, n := range a.AuthorizationNumbers {
			w.u32(n)
		}
		w.state(a.ContentsState, "readable", "unreadable")
		w.state(a.DescriptionState, "null", "present", "unreadable")
		w.text(a.Description, 32768)
		w.u32(a.PromptBits)
		w.state(a.RawPromptState, "readable", "unreadable")
		w.u32(a.RawPromptVersion)
		w.u32(a.RawPromptFlags)
		w.state(a.ApplicationsState, "null", "present", "unreadable")
		w.count(len(a.Applications))
		if w.invalid {
			return nil, ErrProjection
		}
		for _, app := range a.Applications {
			w.state(app.RequirementState, "present", "missing", "unreadable", "unexpected-type")
			w.field(app.Requirement, 65536)
			w.text(app.RequirementText, 65536)
		}
		if w.invalid {
			return nil, ErrProjection
		}
	}
	if _, err := DecodeNativeProjection(w.Bytes()); err != nil {
		return nil, err
	}
	return bytes.Clone(w.Bytes()), nil
}

func ProjectionSHA256(p Projection) (string, error) {
	b, err := EncodeNativeProjection(p)
	if err != nil {
		return "", err
	}
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:]), nil
}
