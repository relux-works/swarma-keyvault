package grants

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

// Claim: The fixed protected source binds room and poster and provides no freshness grace.
func TestLinuxFixedRoomSnapshotSource(t *testing.T) {
	// Synthetic publisher signatures are not authenticated by this source;
	// the platform verifier must still admit the returned bytes.
	pub := newMUKey(t)
	for _, age := range []time.Duration{0, 30 * time.Second, 60 * time.Second, 61 * time.Second, -time.Second} {
		p, err := mugrant.BuildSnapshot(pub.id, muNow.Add(-age), nil)
		if err != nil {
			t.Fatal(err)
		}
		e := MUEnvelopeEvent{Sender: "@publisher:example.invalid", Receiver: muDockReceiver, Room: "!revocations:example.invalid", EventID: "$snapshot", Envelope: pub.sign(t, p)}
		calls := 0
		s := LinuxFixedRoomSnapshots{RoomID: e.Room, PublisherMXID: e.Sender, ReceiverMXID: e.Receiver, ReadLatest: func(ctx context.Context, room string) (MUEnvelopeEvent, error) {
			calls++
			if room != e.Room {
				t.Fatal("alias or wrong room requested", room)
			}
			return e, nil
		}}
		b, err := s.Read(context.Background(), muNow)
		if age >= 0 && age <= 60*time.Second {
			if err != nil || len(b) == 0 {
				t.Fatal(age, err)
			}
		} else if platformCode(err) != "revocation_unavailable" {
			t.Fatal(age, err)
		}
		if calls != 1 {
			t.Fatal(calls)
		}
	}
	p, _ := mugrant.BuildSnapshot(pub.id, muNow, nil)
	good := MUEnvelopeEvent{Sender: "@publisher:example.invalid", Receiver: muDockReceiver, Room: "!revocations:example.invalid", EventID: "$snapshot", Envelope: pub.sign(t, p)}
	for name, change := range map[string]func(*MUEnvelopeEvent){"room": func(e *MUEnvelopeEvent) { e.Room = "!foreign:invalid" }, "sender": func(e *MUEnvelopeEvent) { e.Sender = "@foreign:invalid" }, "receiver": func(e *MUEnvelopeEvent) { e.Receiver = "@foreign:invalid" }, "event": func(e *MUEnvelopeEvent) { e.EventID = "#alias:invalid" }} {
		e := good
		change(&e)
		s := LinuxFixedRoomSnapshots{RoomID: good.Room, PublisherMXID: good.Sender, ReceiverMXID: good.Receiver, ReadLatest: func(context.Context, string) (MUEnvelopeEvent, error) { return e, nil }}
		if _, err := s.Read(context.Background(), muNow); !errors.Is(err, ErrMUProjection) {
			t.Fatal(name, err)
		}
	}
	called := false
	s := LinuxFixedRoomSnapshots{RoomID: "#swarma-grant-revocation:agents.relux.works", PublisherMXID: good.Sender, ReceiverMXID: good.Receiver, ReadLatest: func(context.Context, string) (MUEnvelopeEvent, error) { called = true; return good, nil }}
	if _, err := s.Read(context.Background(), muNow); !errors.Is(err, ErrMUState) || called {
		t.Fatal("alias accepted", err, called)
	}
}
