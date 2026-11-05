package grants

import (
	"bytes"
	"context"
	"time"
)

// PublisherCadence and PublisherMaxAge are the fixed D2 schedule and trusted
// clock admission bound. A missed publication gives no freshness grace.
const LinuxPublisherCadence = 30 * time.Second
const LinuxPublisherMaxAge = 60 * time.Second

// LinuxFixedRoomSnapshots is an injected transport adapter. ReadLatest must
// supply the newest authenticated event from exactly RoomID; aliases are only
// used in provisioning. Crypto, complete-snapshot admission and rollback
// safety still belong to the platform adapter and the durable receiver union.
type LinuxFixedRoomSnapshots struct {
	RoomID, PublisherMXID, ReceiverMXID string
	ReadLatest                          func(context.Context, string) (MUEnvelopeEvent, error)
}

func (s LinuxFixedRoomSnapshots) Read(ctx context.Context, now time.Time) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || now.IsZero() || now.Nanosecond() != 0 || !a2aContextText(s.RoomID, '!') || !linuxMXID(s.PublisherMXID) || !linuxMXID(s.ReceiverMXID) || s.ReadLatest == nil {
		return nil, ErrMUState
	}
	e, err := s.ReadLatest(ctx, s.RoomID)
	if err != nil {
		return nil, err
	}
	if e.Room != s.RoomID || e.Sender != s.PublisherMXID || e.Receiver != s.ReceiverMXID || !a2aContextText(e.EventID, '$') {
		return nil, ErrMUProjection
	}
	env, err := muParseEnvelope(e.Envelope)
	if err != nil {
		return nil, err
	}
	b, ok := env["body"].(map[string]any)
	if !ok || b["type"] != "revocation/1" {
		return nil, ErrMUState
	}
	issued, err := time.Parse("2006-01-02T15:04:05Z", strOr(b["issued_at"]))
	if err != nil || issued.After(now) || now.Sub(issued) > LinuxPublisherMaxAge {
		return nil, &ErrMUPlatform{Code: "revocation_unavailable"}
	}
	return bytes.Clone(e.Envelope), nil
}
