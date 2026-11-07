package grants

import (
	"reflect"
	"testing"
	"time"
)

// Clock evidence has a whole-second wire representation. Do not silently
// round a fractional observation into the inclusive freshness window.
func TestLinuxVerifierClockEvidencePrecision(t *testing.T) {
	for _, tc := range []struct {
		name         string
		want         string
		observations int
		edit         func(*linuxVerifierDock)
	}{
		{"observation", "time_unavailable", 0, func(g *linuxVerifierDock) { g.now = g.now.Add(time.Nanosecond) }},
		{"protected-now", "time_unavailable", 0, func(g *linuxVerifierDock) { g.fake.state.Now = g.fake.state.Now.Add(time.Nanosecond) }},
		{"both-now", "time_unavailable", 2, func(g *linuxVerifierDock) {
			g.now = g.now.Add(time.Nanosecond)
			g.fake.state.Now = g.now
		}},
		{"authority-deadline", "time_unavailable", 2, func(g *linuxVerifierDock) {
			g.fake.state.AuthorityUntil = g.fake.state.AuthorityUntil.Add(time.Nanosecond)
		}},
		{"watermark", "watermark_unavailable", 2, func(g *linuxVerifierDock) { g.fake.state.Watermark = g.fake.state.Watermark.Add(time.Nanosecond) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			g := newLinuxVerifierDock(t)
			// A current, signed snapshot exactly at the admitted boundary.
			g.snapshot(g.pub.id, g.now.Add(-60*time.Second), nil)
			g.snapshot(g.revokerID, g.now.Add(-60*time.Second), nil)
			linuxVerifierWant(t, g, "accept")
			tc.edit(g)
			d, err := g.adapter().VerifyProjectedWithSnapshots(g.event, g.now)
			if linuxVerifierCode(err) != tc.want || !reflect.DeepEqual(d.Decision, MUDecision{}) || len(d.SnapshotMarks) != 0 || len(d.VerifiedSnapshots) != tc.observations {
				t.Fatalf("fractional evidence verdict/observation mismatch: code=%s", linuxVerifierCode(err))
			}
		})
	}
}

// Compare instants rather than zone labels, without weakening exactness.
func TestLinuxVerifierClockEquivalentZone(t *testing.T) {
	g := newLinuxVerifierDock(t)
	g.now = g.now.In(time.FixedZone("test-offset", 3600))
	linuxVerifierWant(t, g, "accept")
}

// A fractional protected sample must not dispatch through the real receiver.
// Correcting that sample admits the same request, proving refusal did not
// consume its nonce or leave an invisible effect hold.
func TestLinuxVerifierClockReceiverEffect(t *testing.T) {
	g := newLinuxCombinedRig(t)
	g.dock.fake.state.Now = g.dock.now.Add(time.Nanosecond)
	if err := g.handle(); linuxVerifierCode(err) != "time_unavailable" || g.calls != 0 {
		t.Fatalf("fractional protected clock dispatched: code=%s calls=%d", linuxVerifierCode(err), g.calls)
	}
	g.dock.fake.state.Now = g.dock.now
	if err := g.handle(); err != nil || g.calls != 1 {
		t.Fatalf("corrected exact sample refused: code=%s calls=%d", linuxVerifierCode(err), g.calls)
	}
}
