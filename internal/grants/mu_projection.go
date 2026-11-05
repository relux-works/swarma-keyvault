package grants

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// ErrMUProjection refuses an a2a envelope projection that is not admitted.
var ErrMUProjection = errors.New("mu-envelope-projection-refused")

// muProjectionFields is the exact a2a #189 record (a2a.event-envelope-input/1).
var muProjectionFields = []string{"type", "sender_mxid", "receiver_mxid", "requested_room_id", "requested_event_id", "returned_room_id", "returned_event_id", "envelope_base64", "body_text_base64"}

// ParseMUProjection admits exactly one JSON object plus a single LF with the
// nine string fields, the right type, room and event ids equal to the
// requested ones (a second, independent layer over a2a's own check), and
// unpadded base64url payloads.
func ParseMUProjection(raw []byte, room, eventID string) (MUEnvelopeEvent, error) {
	frame, ok := a2aRecordFrame(raw)
	if !ok {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	// The duplicate-free platform reader first: encoding/json would keep the
	// last of two equal members.
	if _, err := record.Parse(frame, 196608, 4); err != nil {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	d := json.NewDecoder(bytes.NewReader(frame))
	d.DisallowUnknownFields()
	var m map[string]any
	if err := d.Decode(&m); err != nil || d.More() || len(m) != len(muProjectionFields) {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	s := map[string]string{}
	for _, k := range muProjectionFields {
		v, ok := m[k].(string)
		if !ok || v == "" {
			return MUEnvelopeEvent{}, ErrMUProjection
		}
		s[k] = v
	}
	if s["type"] != "a2a.event-envelope-input/1" || s["requested_room_id"] != room || s["returned_room_id"] != room || s["requested_event_id"] != eventID || s["returned_event_id"] != eventID {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	envelope, err1 := base64.RawURLEncoding.Strict().DecodeString(s["envelope_base64"])
	text, err2 := base64.RawURLEncoding.Strict().DecodeString(s["body_text_base64"])
	if err1 != nil || err2 != nil || len(envelope) == 0 || len(envelope) > 65536 || len(text) == 0 || len(text) > 32768 {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	if _, err := record.Parse(envelope, 65536, 16); err != nil {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	return MUEnvelopeEvent{Sender: s["sender_mxid"], Receiver: s["receiver_mxid"], Room: room, EventID: eventID, Envelope: envelope, Text: text}, nil
}

// MUProjector reads one event through the pinned a2a binary.
type MUProjector struct {
	Path, SHA256, Profile, Identity, ConfigDir, Room string
}

// Read runs the pinned a2a --envelope-input read once and parses its record.
func (p MUProjector) Read(eventID string) (MUEnvelopeEvent, error) {
	if !a2aContextText(eventID, '$') || CheckPinnedExecutable(p.Path, p.SHA256) != nil {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.Path, "--profile", p.Profile, "--as", p.Identity, "read", p.Room, "--event", eventID, "--envelope-input", "--json")
	cmd.Env = append(os.Environ(), "A2A_CONFIG_DIR="+p.ConfigDir)
	out, diag := &boundedLocalOutput{maximum: 196608}, &boundedLocalOutput{maximum: 8192}
	cmd.Stdout, cmd.Stderr = out, diag
	cmd.WaitDelay = subprocessWaitDelay
	if err := cmd.Run(); err != nil || ctx.Err() != nil {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	return ParseMUProjection(bytes.Clone(out.Bytes()), p.Room, eventID)
}

// VerifyRootRevocations checks owner-root-signed revocation/1 snapshots
// against the pinned root and returns their entries (any age: a root
// revocation always wins). Any invalid snapshot refuses the whole set.
func VerifyRootRevocations(root string, snapshots [][]byte) ([]MURevocation, error) {
	var out []MURevocation
	for _, raw := range snapshots {
		e, err := muParseEnvelope(raw)
		if err != nil {
			return nil, err
		}
		b, ok := e["body"].(map[string]any)
		sigs, _ := e["signatures"].([]any)
		if !ok || b["type"] != "revocation/1" || b["issuer"] != root || len(sigs) != 1 {
			return nil, ErrMUState
		}
		sig, _ := sigs[0].(map[string]any)
		text, _ := sig["sig"].(string)
		raw64, err := record.DecodeBase64(text, 64)
		if err != nil || sig["key"] != root || sig["role"] != "author" {
			return nil, ErrMUState
		}
		if id, err := record.ContentID("revocation/1", b); err != nil || id != e["id"] {
			return nil, ErrMUState
		}
		pre, err := record.SigningPreimage("revocation/1", root, "author", b)
		if err != nil || record.VerifySignature(root, raw64, pre) != nil {
			return nil, ErrMUState
		}
		entries, err := muSnapshotEntries(raw)
		if err != nil {
			return nil, err
		}
		out = append(out, entries...)
	}
	return out, nil
}
