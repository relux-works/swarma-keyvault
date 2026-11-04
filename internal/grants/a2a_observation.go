package grants

import (
	"bytes"
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// A2AObservationContext is independently configured, not derived from the
// observation or its human header. Declared labels are contextual only; the
// actual full sender still selects the enrolled key in A2AReceiver.Verify.
type A2AObservationContext struct {
	Audience, RoomID, EventID, Topic, ThreadRoot string
	DeclaredFrom, DeclaredTo                     string
}

// ParseA2AObservation decodes the agreed single-event observation and closed
// request wrapper without network, vault, state or provider access. The caller
// must obtain these bytes from a successful admitted projection invocation;
// parsing JSON alone does not attest origin or qualify a binary. Returned body
// bytes remain untrusted until A2AReceiver.Verify succeeds. This is unencrypted
// m.room.message intake, not Matrix E2EE/device authentication.
func ParseA2AObservation(raw []byte, expected A2AObservationContext) (A2AEvent, error) {
	refuse := func() (A2AEvent, error) { return A2AEvent{}, ErrA2AContext }
	if _, err := parseA2AAccount(expected.Audience); err != nil {
		return refuse()
	}
	if !a2aContextText(expected.RoomID, '!') || !a2aContextText(expected.EventID, '$') || !a2aContextText(expected.ThreadRoot, '$') || !a2aDeclaration(expected.DeclaredFrom) || !a2aDeclaration(expected.DeclaredTo) {
		return refuse()
	}
	if _, err := parseOpaqueID(expected.Topic); err != nil {
		return refuse()
	}
	n, err := strictA2AJSON(raw, 98304)
	if err != nil {
		return refuse()
	}
	p, ok := a2aJSONObject(n, []string{"type", "observation_status", "requested_room_id", "requested_event_id", "returned_event_id", "sender_mxid", "receiver_mxid", "receiver_identity_source", "event_type", "returned_room_id_present", "room_context_source", "content_base64"}, "returned_room_id")
	if !ok || !a2aJSONText(p, "type", "a2a.event-verification-input/1") || !a2aJSONText(p, "observation_status", "observed") || !a2aJSONText(p, "requested_room_id", expected.RoomID) || !a2aJSONText(p, "requested_event_id", expected.EventID) || !a2aJSONText(p, "returned_event_id", expected.EventID) || !a2aJSONText(p, "receiver_mxid", expected.Audience) || !a2aJSONText(p, "receiver_identity_source", "selected-stored-session") || !a2aJSONText(p, "event_type", "m.room.message") {
		return refuse()
	}
	sender, ok := p["sender_mxid"].(string)
	if !ok {
		return refuse()
	}
	if _, err := parseA2AAccount(sender); err != nil {
		return A2AEvent{}, ErrA2ASenderUnavailable
	}
	present, ok := p["returned_room_id_present"].(bool)
	if !ok {
		return refuse()
	}
	if present {
		if !a2aJSONText(p, "returned_room_id", expected.RoomID) || !a2aJSONText(p, "room_context_source", "returned-room-and-original-endpoint") {
			return refuse()
		}
	} else {
		if _, exists := p["returned_room_id"]; exists || !a2aJSONText(p, "room_context_source", "authenticated-room-scoped-endpoint") {
			return refuse()
		}
	}
	encoded, ok := p["content_base64"].(string)
	if !ok {
		return refuse()
	}
	content, err := a2aBase64(encoded, 65536)
	if err != nil {
		return refuse()
	}
	body, err := parseA2AWrapper(content, expected)
	if err != nil {
		return refuse()
	}
	return A2AEvent{SenderMXID: sender, RecipientMXID: expected.Audience, RoomID: expected.RoomID, Topic: expected.Topic, Kind: "request", EventID: expected.EventID, Body: body}, nil
}

func parseA2AWrapper(raw []byte, expected A2AObservationContext) ([]byte, error) {
	n, err := strictA2AJSON(raw, 65536)
	if err != nil {
		return nil, err
	}
	c, ok := a2aJSONObject(n, []string{"msgtype", "body", "ai.relux.a2a", "m.mentions", "m.relates_to"})
	if !ok || !a2aJSONText(c, "msgtype", "m.text") {
		return nil, ErrA2AContext
	}
	h, ok := a2aJSONObject(c["ai.relux.a2a"], []string{"v", "type", "slug", "topic", "from", "to", "at", "kind"}, "re")
	if !ok || h["v"] != json.Number("1") || !a2aJSONText(h, "type", "message") || !a2aJSONText(h, "slug", expected.Topic) || !a2aJSONText(h, "topic", expected.ThreadRoot) || !a2aJSONText(h, "from", expected.DeclaredFrom) || !a2aJSONText(h, "kind", "request") || !a2aOneString(h["to"], expected.DeclaredTo) {
		return nil, ErrA2AContext
	}
	at, ok := h["at"].(string)
	if !ok || !a2aDeclaration(at) {
		return nil, ErrA2AContext
	}
	if _, err := time.Parse(time.RFC3339Nano, at); err != nil {
		return nil, ErrA2AContext
	}
	reply, humanReply := expected.ThreadRoot, "-"
	_, hasReply := h["re"]
	if hasReply {
		reply, ok = h["re"].(string)
		if !ok || !a2aContextText(reply, '$') {
			return nil, ErrA2AContext
		}
		humanReply = reply
	}
	mentions, ok := a2aJSONObject(c["m.mentions"], []string{"user_ids"})
	if !ok || !a2aOneString(mentions["user_ids"], expected.Audience) {
		return nil, ErrA2AContext
	}
	relation, ok := a2aJSONObject(c["m.relates_to"], []string{"rel_type", "event_id", "m.in_reply_to"}, "is_falling_back")
	if !ok || !a2aJSONText(relation, "rel_type", "m.thread") || !a2aJSONText(relation, "event_id", expected.ThreadRoot) {
		return nil, ErrA2AContext
	}
	inReply, ok := a2aJSONObject(relation["m.in_reply_to"], []string{"event_id"})
	if !ok || !a2aJSONText(inReply, "event_id", reply) {
		return nil, ErrA2AContext
	}
	falling, exists := relation["is_falling_back"]
	if hasReply && exists || !hasReply && (!exists || falling != true) {
		return nil, ErrA2AContext
	}
	body, ok := c["body"].(string)
	prefix := "- from: " + expected.DeclaredFrom + "\n- to: " + expected.DeclaredTo + "\n- at: " + at + "\n- re: " + humanReply + "\n- kind: request\n\n"
	if !ok || !strings.HasPrefix(body, prefix) || strings.Index(body, "\n\n") != len(prefix)-2 {
		return nil, ErrA2AContext
	}
	envelope := []byte(body[len(prefix):])
	// Validate only the outer extraction form here. The inert invalid-signature
	// fixture must extract, but cannot pass cryptographic authorization.
	w, err := parseCanonical(envelope, a2aRequestEnvelopeWire)
	if err != nil {
		return nil, ErrA2AContext
	}
	f, err := subobjectTexts(w, "payload", "request", "signature", "type")
	if err != nil || f["type"] != "grants-a2a-envelope-1" {
		return nil, ErrA2AContext
	}
	return bytes.Clone(envelope), nil
}

func a2aDeclaration(value string) bool {
	if value == "" || len(value) > 255 || !utf8.ValidString(value) {
		return false
	}
	for _, c := range value {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

func a2aJSONObject(v any, required []string, optional ...string) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	if !ok {
		return nil, false
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, k := range required {
		allowed[k] = true
		if _, exists := m[k]; !exists {
			return nil, false
		}
	}
	for _, k := range optional {
		allowed[k] = true
	}
	for k := range m {
		if !allowed[k] {
			return nil, false
		}
	}
	return m, true
}
func a2aJSONText(m map[string]any, key, expected string) bool {
	v, ok := m[key].(string)
	return ok && v == expected
}
func a2aOneString(v any, expected string) bool {
	a, ok := v.([]any)
	return ok && len(a) == 1 && a[0] == expected
}

// This decoder is scoped to the observation profile. Unlike encoding/json's
// default string handling it rejects invalid UTF8 and unpaired surrogate
// escapes, as well as decoded duplicate object keys, at every depth.
func strictA2AJSON(raw []byte, maximum int) (any, error) {
	if len(raw) == 0 || len(raw) > maximum || !utf8.Valid(raw) || !a2aScalarStrings(raw) {
		return nil, ErrA2AContext
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	tokens := 0
	var read func(int) (any, error)
	read = func(depth int) (any, error) {
		tokens++
		if depth > 16 || tokens > 16384 {
			return nil, ErrA2AContext
		}
		t, err := d.Token()
		if err != nil {
			return nil, ErrA2AContext
		}
		if delim, ok := t.(json.Delim); ok {
			switch delim {
			case '{':
				m := map[string]any{}
				for d.More() {
					tokens++
					key, err := d.Token()
					name, ok := key.(string)
					if err != nil || !ok || len(name) > 1024 || tokens > 16384 {
						return nil, ErrA2AContext
					}
					if _, exists := m[name]; exists {
						return nil, ErrA2AContext
					}
					v, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					m[name] = v
				}
				end, err := d.Token()
				if err != nil || end != json.Delim('}') {
					return nil, ErrA2AContext
				}
				return m, nil
			case '[':
				a := []any{}
				for d.More() {
					v, err := read(depth + 1)
					if err != nil {
						return nil, err
					}
					a = append(a, v)
				}
				end, err := d.Token()
				if err != nil || end != json.Delim(']') {
					return nil, ErrA2AContext
				}
				return a, nil
			default:
				return nil, ErrA2AContext
			}
		}
		return t, nil
	}
	v, err := read(0)
	if err != nil {
		return nil, err
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrA2AContext
	}
	return v, nil
}

func a2aScalarStrings(raw []byte) bool {
	for i := 0; i < len(raw); i++ {
		if raw[i] != '"' {
			continue
		}
		i++
		closed := false
		for ; i < len(raw); i++ {
			if raw[i] == '"' {
				closed = true
				break
			}
			if raw[i] != '\\' {
				continue
			}
			i++
			if i >= len(raw) {
				return false
			}
			if raw[i] != 'u' {
				continue // The standard decoder validates all other escapes.
			}
			if i+4 >= len(raw) {
				return false
			}
			u, err := strconv.ParseUint(string(raw[i+1:i+5]), 16, 16)
			if err != nil {
				return false
			}
			i += 4
			if u >= 0xdc00 && u <= 0xdfff {
				return false
			}
			if u >= 0xd800 && u <= 0xdbff {
				if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
					return false
				}
				low, err := strconv.ParseUint(string(raw[i+3:i+7]), 16, 16)
				if err != nil || low < 0xdc00 || low > 0xdfff {
					return false
				}
				i += 6
			}
		}
		if !closed {
			return false
		}
	}
	return true
}
