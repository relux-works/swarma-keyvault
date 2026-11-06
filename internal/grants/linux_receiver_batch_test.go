package grants

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// These are adapter metadata faults, not cryptographic peer failures. Keep a
// legitimate publisher snapshot first so silently retaining a valid subset is
// observably different from rejecting the batch before snapshot appends.
func linuxBadSnapshotBatches() []struct {
	name   string
	change func([]LinuxVerifiedSnapshot) []LinuxVerifiedSnapshot
} {
	type batch = []LinuxVerifiedSnapshot
	cases := []struct {
		name   string
		change func(batch) batch
	}{}
	snapshot := func(name string, change func(*LinuxVerifiedSnapshot)) {
		cases = append(cases, struct {
			name   string
			change func(batch) batch
		}{name, func(b batch) batch { change(&b[1]); return b }})
	}
	snapshot("empty-signer", func(v *LinuxVerifiedSnapshot) { v.Signer = "" })
	snapshot("long-signer", func(v *LinuxVerifiedSnapshot) { v.Signer = strings.Repeat("x", 256) })
	snapshot("space-in-signer", func(v *LinuxVerifiedSnapshot) { v.Signer = "p256:bad signer" })
	snapshot("control-in-signer", func(v *LinuxVerifiedSnapshot) { v.Signer = "p256:bad\x7f" })
	snapshot("non-ascii-signer", func(v *LinuxVerifiedSnapshot) { v.Signer = "p256:é" })
	snapshot("zero-issued-at", func(v *LinuxVerifiedSnapshot) { v.IssuedAt = time.Time{} })
	snapshot("epoch-issued-at", func(v *LinuxVerifiedSnapshot) { v.IssuedAt = time.Unix(0, 0) })
	snapshot("fractional-issued-at", func(v *LinuxVerifiedSnapshot) { v.IssuedAt = muNow.Add(-time.Nanosecond) })
	snapshot("65-entries", func(v *LinuxVerifiedSnapshot) {
		v.Entries = nil
		for i := 0; i < 65; i++ {
			v.Entries = append(v.Entries, MURevocation{"record", fmt.Sprintf("entry-%d", i)})
		}
	})
	snapshot("invalid-entry-kind", func(v *LinuxVerifiedSnapshot) { v.Entries = []MURevocation{{"other", "entry"}} })
	snapshot("empty-entry-id", func(v *LinuxVerifiedSnapshot) { v.Entries = []MURevocation{{"record", ""}} })
	snapshot("long-entry-id", func(v *LinuxVerifiedSnapshot) { v.Entries = []MURevocation{{"key", strings.Repeat("x", 256)}} })
	snapshot("duplicate-entry", func(v *LinuxVerifiedSnapshot) { v.Entries = append(v.Entries, v.Entries[0]) })
	cases = append(cases, struct {
		name   string
		change func(batch) batch
	}{"65-snapshots", func(b batch) batch {
		for i := len(b); i < 65; i++ {
			b = append(b, LinuxVerifiedSnapshot{Signer: fmt.Sprintf("p256:extra-%d", i), IssuedAt: muNow})
		}
		return b
	}})
	return cases
}

func linuxBatchPair(g *linuxRig) []LinuxVerifiedSnapshot {
	return []LinuxVerifiedSnapshot{
		{Signer: g.v.publisher, IssuedAt: muNow, Entries: append([]MURevocation(nil), g.v.revocations...)},
		{Signer: g.r.config.AgentRevocationRoot, IssuedAt: muNow, Entries: []MURevocation{{"record", "agent-unrelated"}}},
	}
}

// Claim: both the successful-verifier path and the independently verified
// evidence-on-refusal path reject malformed batches without keeping their
// valid publisher subset. Correcting the adapter permits the identical request
// to execute once, so these checks cannot pass by rejecting all requests.
func TestLinuxReceiverWholeBatchRefusals(t *testing.T) {
	for _, tc := range linuxBadSnapshotBatches() {
		t.Run(tc.name, func(t *testing.T) {
			for _, refused := range []bool{false, true} {
				t.Run(fmt.Sprintf("verifier-refused-%t", refused), func(t *testing.T) {
					g := newLinuxRig(t)
					g.v.revocations = []MURevocation{{"record", "publisher-unrelated"}}
					bad := tc.change(linuxBatchPair(g))
					g.r.verifier = linuxAdmissionFunc(func(e MUEnvelopeEvent, n time.Time) (LinuxAdmission, error) {
						a, err := g.v.VerifyAdmission(e, n)
						a.Snapshots = bad
						if refused {
							err = &ErrMUPlatform{Code: "revocation_unavailable"}
						}
						return a, err
					})
					e := g.event(t, "$whole-batch")
					before := g.journal(t)
					out, err := g.r.Handle(context.Background(), e)
					if !errors.Is(err, ErrMUState) || out != nil || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
						t.Fatalf("whole-batch refusal: err=%v outcome=%v effects=%d journal_equal=%t", err, out, g.calls.Load(), bytes.Equal(before, g.journal(t)))
					}
					g.reopen() // Restores the legitimate adapter, preserving the same journal.
					out, err = g.r.Handle(context.Background(), e)
					if err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 || bytes.Equal(before, g.journal(t)) {
						t.Fatalf("corrected valid control: err=%v outcome=%v effects=%d", err, out, g.calls.Load())
					}
					s := muOpen(t, g.r.config.State, g.r.config.Binding)
					defer s.close()
					if !s.unions[g.v.publisher][g.v.revocations[0]] || !s.highWater[g.v.publisher].Equal(muNow) {
						t.Fatal("valid control lost publisher evidence")
					}
				})
			}
		})
	}
}

// The receiver's pins can reject an invalid signer or a 65-snapshot batch
// before the snapshot validator sees it. Exercise observe and admit directly
// too: 65 distinct signers isolate the count bound from duplicate detection.
func TestLinuxReceiverSnapshotBatchPreflight(t *testing.T) {
	for _, tc := range linuxBadSnapshotBatches() {
		t.Run(tc.name, func(t *testing.T) {
			for _, admit := range []bool{false, true} {
				t.Run(fmt.Sprintf("admit-%t", admit), func(t *testing.T) {
					g := newLinuxRig(t)
					g.v.revocations = []MURevocation{{"record", "publisher-unrelated"}}
					bad := tc.change(linuxBatchPair(g))
					s := muOpen(t, g.r.config.State, g.r.config.Binding)
					rs, err := openLinuxRevocationState(s)
					if err != nil {
						s.close()
						t.Fatal(err)
					}
					before := g.journal(t)
					if admit {
						err = rs.admit(s, bad, MUDecision{PublisherKey: g.v.publisher, Revocations: g.v.revocations}, muNow)
					} else {
						err = rs.observe(s, bad, muNow)
					}
					equal := bytes.Equal(before, g.journal(t))
					rs.close()
					s.close()
					if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 || !equal {
						t.Fatalf("preflight refusal: err=%v effects=%d journal_equal=%t", err, g.calls.Load(), equal)
					}
					// Genuine receiver admission after refusal also proves no hold was written.
					if out, err := g.r.Handle(context.Background(), g.event(t, "$preflight-control")); err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 {
						t.Fatal("valid control", out, err, g.calls.Load())
					}
				})
			}
		})
	}
}

// Claim: the inclusive limits remain usable; entry identity is the entire
// (kind, ID) pair, and the ID predicate does not impose token/hash syntax.
func TestLinuxReceiverSnapshotBatchLimitsControl(t *testing.T) {
	g := newLinuxRig(t)
	g.v.revocations = []MURevocation{{"key", "same id"}, {"record", "same id"}, {"record", strings.Repeat("x", 255)}}
	for len(g.v.revocations) < 64 {
		g.v.revocations = append(g.v.revocations, MURevocation{"record", fmt.Sprintf("entry-%d", len(g.v.revocations))})
	}
	if out, err := g.r.Handle(context.Background(), g.event(t, "$64-entries")); err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 {
		t.Fatal("64-entry control", out, err, g.calls.Load())
	}
	s := muOpen(t, g.r.config.State, g.r.config.Binding)
	defer s.close()
	rs, err := openLinuxRevocationState(s)
	if err != nil {
		t.Fatal(err)
	}
	defer rs.close()
	var batch []LinuxVerifiedSnapshot
	for i := 0; i < 64; i++ {
		batch = append(batch, LinuxVerifiedSnapshot{Signer: fmt.Sprintf("signer-%d", i), IssuedAt: muNow})
	}
	// Empty snapshots raise marks but do not create signer-union map entries.
	if err := rs.observe(s, batch, muNow); err != nil {
		t.Fatal("64-snapshot control", err)
	}
	for _, v := range batch {
		if !s.highWater[v.Signer].Equal(muNow) {
			t.Fatal("missing control mark", v.Signer)
		}
	}
}

// This helper limit cannot normally be reached by the receiver's two pinned
// snapshot signers. Seed real journal unions directly, not receiver pins. The
// absent signer is FIRST: observe's capacity guard is per iteration, so this
// test does not claim rollback of earlier successful appends in a batch.
func TestLinuxReceiverSnapshotUnionCapacity(t *testing.T) {
	for _, admit := range []bool{false, true} {
		t.Run(fmt.Sprintf("admit-%t", admit), func(t *testing.T) {
			g := newLinuxRig(t)
			s := muOpen(t, g.r.config.State, g.r.config.Binding)
			for i := 0; i < 64; i++ {
				if err := s.absorbSigned(fmt.Sprintf("signer-%d", i), []MURevocation{{"record", fmt.Sprintf("seed-%d", i)}}); err != nil {
					s.close()
					t.Fatal(err)
				}
			}
			s.close()
			s = muOpen(t, g.r.config.State, g.r.config.Binding)
			defer s.close()
			if len(s.unions) != 64 {
				t.Fatal("capacity fixture", len(s.unions))
			}
			rs, err := openLinuxRevocationState(s)
			if err != nil {
				t.Fatal(err)
			}
			defer rs.close()
			entries := []MURevocation{{"record", "new-unrelated"}}
			batch := []LinuxVerifiedSnapshot{{Signer: g.v.publisher, IssuedAt: muNow, Entries: entries}, {Signer: "signer-0", IssuedAt: muNow, Entries: []MURevocation{{"record", "seed-0"}}}}
			before := g.journal(t)
			if admit {
				err = rs.admit(s, batch, MUDecision{PublisherKey: g.v.publisher, Revocations: entries}, muNow)
			} else {
				err = rs.observe(s, batch, muNow)
			}
			if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 || !bytes.Equal(before, g.journal(t)) {
				t.Fatalf("union capacity refusal: err=%v effects=%d journal_equal=%t", err, g.calls.Load(), bytes.Equal(before, g.journal(t)))
			}
			// At capacity, an existing signer's complete superset is still valid.
			control := []LinuxVerifiedSnapshot{{Signer: "signer-0", IssuedAt: muNow, Entries: []MURevocation{{"record", "seed-0"}, {"record", "existing-signer-addition"}}}}
			if admit {
				err = rs.admit(s, control, MUDecision{PublisherKey: "signer-0", Revocations: control[0].Entries}, muNow)
			} else {
				err = rs.observe(s, control, muNow)
			}
			if err != nil || len(s.unions) != 64 || !s.unions["signer-0"][control[0].Entries[1]] || g.calls.Load() != 0 || bytes.Equal(before, g.journal(t)) {
				t.Fatal("existing-union valid control", err, len(s.unions), g.calls.Load())
			}
		})
	}
}
