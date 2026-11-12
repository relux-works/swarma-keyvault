package namecoinpsbt

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// All eight public Core requests retain exact manifest and review commitments
// through a canonical owned descriptor. Historical decode does not reauthorize
// an expired request, and request-ID changes do not partition the attempt fence.
func TestPublicAttemptRoundtripAndIdentity(t *testing.T) {
	for _, mode := range []string{"all-four-before-release", "two-stage"} {
		for _, slot := range []string{"A", "B", "C", "D"} {
			c := candidate(t, mode, slot)
			selected := fixtureSelection(t, c)
			raw, _ := json.Marshal(c.snapshot.Request())
			pin := fixture(t, mode, "account-pin.json")
			now := time.Unix(int64(selected.Policy.CreatedAt)+1, 0)
			a, err := PrepareAttempt(raw, pin, selected, now)
			if err != nil {
				t.Fatal(err)
			}
			encoded := a.Descriptor()
			recovered, err := DecodeAttempt(encoded)
			if err != nil || a.ID() != recovered.ID() || a.Commitment() != recovered.Commitment() || a.ReviewDigest() != recovered.ReviewDigest() || !bytes.Equal(c.snapshot.ManifestBytes(), recovered.candidate.snapshot.ManifestBytes()) {
				t.Fatal("descriptor roundtrip", err)
			}
			if len(a.Outpoints()) != len(c.view.Inputs) {
				t.Fatal("missing fence inputs")
			}
			encoded[0] ^= 1
			frame := a.ReviewFrame()
			frame[0] ^= 1
			if _, err := DecodeAttempt(a.Descriptor()); err != nil || bytes.Equal(frame, a.ReviewFrame()) {
				t.Fatal("borrowed mutable descriptor/frame")
			}
			requireCode(t, recovered.candidate.Admit(selected, time.Unix(int64(c.snapshot.Request().ExpiresAt), 0)), namecoinwire.RequestExpired)
			request := c.snapshot.Request()
			request.RequestID = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
			changed, _ := json.Marshal(request)
			b, err := PrepareAttempt(changed, pin, selected, now)
			if err != nil || a.ID() != b.ID() || a.Commitment() == b.Commitment() || a.ReviewDigest() == b.ReviewDigest() {
				t.Fatal("request correlation changed replay identity", err)
			}
		}
	}
}

// A valid descriptor is the nearby positive control. Truncation, excess bytes,
// oversized lengths, duplicated/unknown selection keys and public pin changes
// refuse without returning a partially prepared candidate or review frame.
func TestPublicAttemptDescriptorRefusals(t *testing.T) {
	c := candidate(t, "all-four-before-release", "C")
	selected := fixtureSelection(t, c)
	raw, _ := json.Marshal(c.snapshot.Request())
	pin := fixture(t, "all-four-before-release", "account-pin.json")
	a, err := PrepareAttempt(raw, pin, selected, time.Unix(int64(selected.Policy.CreatedAt)+1, 0))
	if err != nil {
		t.Fatal(err)
	}
	original := a.Descriptor()
	requestLen := int(binary.BigEndian.Uint32(original[len(attemptDomain):]))
	pinOffset := len(attemptDomain) + 4 + requestLen
	selectionOffset := pinOffset + 4 + int(binary.BigEndian.Uint32(original[pinOffset:]))
	for _, mutate := range []func([]byte) []byte{
		func(b []byte) []byte { return b[:len(b)-1] },
		func(b []byte) []byte { return append(b, 0) },
		func(b []byte) []byte {
			binary.BigEndian.PutUint32(b[len(attemptDomain):], namecoinwire.MaxRequestBytes+1)
			return b
		},
		func(b []byte) []byte { b[pinOffset+4] ^= 1; return b },
		func(b []byte) []byte {
			tail := b[selectionOffset+4:]
			tail = append([]byte(`{"Network":"forged",`), tail[1:]...)
			binary.BigEndian.PutUint32(b[selectionOffset:], uint32(len(tail)))
			return append(b[:selectionOffset+4], tail...)
		},
		func(b []byte) []byte {
			tail := b[selectionOffset+4:]
			tail = append([]byte(`{"unknown":true,`), tail[1:]...)
			binary.BigEndian.PutUint32(b[selectionOffset:], uint32(len(tail)))
			return append(b[:selectionOffset+4], tail...)
		},
	} {
		bad, err := DecodeAttempt(mutate(bytes.Clone(original)))
		if err == nil || len(bad.review) != 0 || len(bad.candidate.digests) != 0 {
			t.Fatal("malformed descriptor admitted or partial state escaped")
		}
	}
	s := a.Selection()
	s.RevealValuesPin[0] ^= 1
	if bytes.Equal(s.RevealValuesPin, a.Selection().RevealValuesPin) {
		t.Fatal("selection borrowed caller memory")
	}
}
