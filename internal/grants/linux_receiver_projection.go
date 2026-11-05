package grants

import (
	"encoding/base64"
	"github.com/relux-works/swarma-envelope/record"
)

// ParseLinuxProjection checks text before envelope contents or identities,
// including when a body hash would correctly bind otherwise refused text.
// Parsing the carriage is necessary to locate text; malformed carriage fails
// closed. record.Parse provides duplicate-member and lexical checks.
func ParseLinuxProjection(raw []byte, room, eventID string) (MUEnvelopeEvent, error) {
	frame, ok := a2aRecordFrame(raw)
	if !ok {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	x, err := record.Parse(frame, 196608, 16)
	if err != nil {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	m, ok := x.(map[string]any)
	if !ok || len(m) != len(muProjectionFields) {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	s := map[string]string{}
	for _, k := range muProjectionFields {
		v, ok := m[k].(string)
		if !ok {
			return MUEnvelopeEvent{}, ErrMUProjection
		}
		s[k] = v
	}
	text, err := base64.RawURLEncoding.Strict().DecodeString(s["body_text_base64"])
	if err != nil {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	if err := ValidateLinuxRequestText(text); err != nil {
		return MUEnvelopeEvent{}, err
	}
	if s["type"] != "a2a.event-envelope-input/1" || !a2aContextText(room, '!') || !a2aContextText(eventID, '$') ||
		s["requested_room_id"] != room || s["returned_room_id"] != room || s["requested_event_id"] != eventID || s["returned_event_id"] != eventID ||
		!linuxMXID(s["sender_mxid"]) || !linuxMXID(s["receiver_mxid"]) {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	envelope, err := base64.RawURLEncoding.Strict().DecodeString(s["envelope_base64"])
	if err != nil || len(envelope) == 0 || len(envelope) > 65536 {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	if _, err := record.Parse(envelope, 65536, 16); err != nil {
		return MUEnvelopeEvent{}, ErrMUProjection
	}
	return MUEnvelopeEvent{Sender: s["sender_mxid"], Receiver: s["receiver_mxid"], Room: room, EventID: eventID, Envelope: envelope, Text: text}, nil
}
