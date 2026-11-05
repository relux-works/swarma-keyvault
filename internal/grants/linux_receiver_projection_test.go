package grants

import (
	"bytes"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/relux-works/swarma-envelope/record"
)

func linuxProjectionMap(e MUEnvelopeEvent) map[string]any {
	return map[string]any{"type": "a2a.event-envelope-input/1", "sender_mxid": e.Sender, "receiver_mxid": e.Receiver,
		"requested_room_id": e.Room, "returned_room_id": e.Room, "requested_event_id": e.EventID, "returned_event_id": e.EventID,
		"envelope_base64": base64.RawURLEncoding.EncodeToString(e.Envelope), "body_text_base64": base64.RawURLEncoding.EncodeToString(e.Text)}
}
func linuxProjectionBytes(t *testing.T, m map[string]any) []byte {
	t.Helper()
	b, err := record.Canonical(m)
	if err != nil {
		t.Fatal(err)
	}
	return append(b, '\n')
}

// Claim: Projection parsing preserves exact bytes and refuses mismatched context, duplicate members and invalid carriage.
func TestLinuxProjectionExactIdentityAndPayload(t *testing.T) {
	g := newLinuxRig(t)
	e := g.event(t, "$projection")
	raw := linuxProjectionBytes(t, linuxProjectionMap(e))
	parsed, err := ParseLinuxProjection(raw, e.Room, e.EventID)
	if err != nil || !bytes.Equal(parsed.Envelope, e.Envelope) || !bytes.Equal(parsed.Text, e.Text) {
		t.Fatal(parsed, err)
	}
	for _, field := range []string{"requested_room_id", "returned_room_id", "requested_event_id", "returned_event_id", "type"} {
		m := linuxProjectionMap(e)
		m[field] = "wrong"
		if _, err := ParseLinuxProjection(linuxProjectionBytes(t, m), e.Room, e.EventID); !errors.Is(err, ErrMUProjection) {
			t.Fatal(field, err)
		}
	}
	for name, alter := range map[string]func(map[string]any){
		"extra":            func(m map[string]any) { m["extra"] = "field" },
		"missing":          func(m map[string]any) { delete(m, "sender_mxid") },
		"not-string":       func(m map[string]any) { m["sender_mxid"] = int64(1) },
		"body-padded":      func(m map[string]any) { m["body_text_base64"] = "YQ==" },
		"envelope-invalid": func(m map[string]any) { m["envelope_base64"] = "ew" },
		"sender-invalid":   func(m map[string]any) { m["sender_mxid"] = "display-name" },
	} {
		m := linuxProjectionMap(e)
		alter(m)
		if _, err := ParseLinuxProjection(linuxProjectionBytes(t, m), e.Room, e.EventID); !errors.Is(err, ErrMUProjection) {
			t.Fatal(name, err)
		}
	}
	for _, bad := range [][]byte{raw[:len(raw)-1], append(bytes.Clone(raw), '\n'), append(bytes.Clone(raw), raw...), bytes.Replace(raw, []byte(`"type":`), []byte(`"type":"duplicate","type":`), 1)} {
		if _, err := ParseLinuxProjection(bad, e.Room, e.EventID); !errors.Is(err, ErrMUProjection) {
			t.Fatal("malformed carriage", err)
		}
	}
	m := linuxProjectionMap(e)
	m["body_text_base64"] = base64.RawURLEncoding.EncodeToString([]byte("a\r"))
	m["envelope_base64"] = "not-json"
	m["returned_room_id"] = "!wrong:invalid"
	if _, err := ParseLinuxProjection(linuxProjectionBytes(t, m), e.Room, e.EventID); !errors.Is(err, ErrLinuxRequestText) {
		t.Fatal("text did not win", err)
	}
}
