package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"testing"
	"time"
)

// Build the exact expected journal suffix from the fixed wire bodies, without
// using admit, observe, absorbSigned, or the snapshot body encoders.
func linuxAdmitExpectedJournal(t *testing.T, g *linuxRig, prefix []byte, snapshots []LinuxVerifiedSnapshot) []byte {
	t.Helper()
	link := journalFrameLink{sequence: 1, epoch: g.r.config.State.Epoch}
	reader := bytes.NewReader(prefix)
	for {
		f, err := readJournalFrame(reader, link)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		link.sequence++
		link.previous = f.digest
	}
	out := bytes.Clone(prefix)
	appendFrame := func(kind journalFrameKind, body []byte) {
		raw, err := encodeJournalFrame(kind, link, body)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, raw...)
		link.sequence++
		copy(link.previous[:], raw[len(raw)-sha256.Size:])
	}
	for _, v := range snapshots {
		if len(v.Entries) != 0 {
			body := append([]byte("MUS1"), byte(len(v.Signer)))
			body = append(body, v.Signer...)
			body = append(body, "MUV1"...)
			body = binary.BigEndian.AppendUint16(body, uint16(len(v.Entries)))
			for _, e := range v.Entries {
				kind := byte(1)
				if e.Kind == "key" {
					kind = 2
				}
				body = append(body, kind)
				body = binary.BigEndian.AppendUint16(body, uint16(len(e.ID)))
				body = append(body, e.ID...)
			}
			appendFrame(journalSignerRevocation, body)
		}
		if !v.IssuedAt.After(muNow) {
			body := binary.BigEndian.AppendUint64([]byte("MUH1"), uint64(v.IssuedAt.Unix()))
			body = append(body, v.Signer...)
			appendFrame(journalSnapshotMark, body)
		}
	}
	return out
}

func linuxAdmitRecordingBatch(g *linuxRig) []LinuxVerifiedSnapshot {
	return []LinuxVerifiedSnapshot{
		{Signer: g.v.publisher, IssuedAt: muNow.Add(-5 * time.Second), Entries: []MURevocation{{"record", "sha256:unrelated-publisher-hold"}}},
		{Signer: g.r.config.AgentRevocationRoot, IssuedAt: muNow.Add(-5 * time.Second), Entries: []MURevocation{{"key", "ed25519:unrelated-agent-hold"}}},
	}
}

func linuxAdmitRecordingVerifier(g *linuxRig, snapshots *[]LinuxVerifiedSnapshot) {
	g.r.verifier = linuxAdmissionFunc(func(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
		d, err := g.v.VerifyProjected(e, now)
		d.Revocations = append([]MURevocation(nil), (*snapshots)[0].Entries...)
		return LinuxAdmission{Decision: d, Snapshots: *snapshots}, err
	})
}

// Freshness is a request judgement: both verified signers retain their exact
// evidence before ErrMUState; future entries acquire no high-water mark.
func TestLinuxAdmitEarlyRefusalRecords(t *testing.T) {
	for _, age := range []struct {
		name  string
		delta time.Duration
	}{
		{"stale", -61 * time.Second}, {"future", time.Second},
	} {
		for role := 0; role < 2; role++ {
			t.Run(fmt.Sprintf("%s/signer-%d", age.name, role), func(t *testing.T) {
				g := newLinuxRig(t)
				snapshots := linuxAdmitRecordingBatch(g)
				snapshots[role].IssuedAt = muNow.Add(age.delta)
				linuxAdmitRecordingVerifier(g, &snapshots)
				e := g.event(t, "$early-refusal")
				before := g.journal(t)
				want := linuxAdmitExpectedJournal(t, g, before, snapshots)
				out, err := g.r.Handle(context.Background(), e)
				if !errors.Is(err, ErrMUState) || err.Error() != "mu-required-state-unavailable" || out != nil || g.calls.Load() != 0 {
					t.Fatal("wrong refusal or effect", out, err, g.calls.Load())
				}
				if !bytes.Equal(g.journal(t), want) {
					t.Fatal("verified evidence journal differs from exact expected frames")
				}
				s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
				if err != nil {
					t.Fatal(err)
				}
				marks := map[string]time.Time{}
				unions := map[string]map[MURevocation]bool{}
				revoked := map[MURevocation]bool{}
				for _, v := range snapshots {
					if !v.IssuedAt.After(muNow) {
						marks[v.Signer] = v.IssuedAt
					}
					unions[v.Signer] = map[MURevocation]bool{}
					for _, entry := range v.Entries {
						unions[v.Signer][entry] = true
						revoked[entry] = true
					}
				}
				valid := reflect.DeepEqual(s.highWater, marks) && reflect.DeepEqual(s.unions, unions) && reflect.DeepEqual(s.revoked, revoked) && len(s.reservations) == 0 && len(s.nonces) == 0 && len(s.allowances) == 0
				s.close()
				if !valid {
					t.Fatal("reopened evidence or zero-accounting state differs")
				}
				// A fresh, complete retry is the adjacent positive control: the refused
				// event consumed no nonce and a future observation did not poison its mark.
				g.reopen()
				snapshots[role].IssuedAt = muNow
				linuxAdmitRecordingVerifier(g, &snapshots)
				out, err = g.r.Handle(context.Background(), e)
				if err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 {
					t.Fatal("fresh complete retry failed", out, err, g.calls.Load())
				}
			})
		}
	}
}

// Claim: A stale snapshot below an existing mark grows its durable union without lowering that mark, then refuses without effects.
func TestLinuxAdmitStaleBelowHighwaterRecords(t *testing.T) {
	for role := 0; role < 2; role++ {
		t.Run(fmt.Sprintf("signer-%d", role), func(t *testing.T) {
			g := newLinuxRig(t)
			snapshots := linuxAdmitRecordingBatch(g)
			linuxAdmitRecordingVerifier(g, &snapshots)
			e := g.event(t, "$stale-below-mark")
			higher := snapshots[role].IssuedAt
			g.r.config.Paused[g.v.grant] = true
			if out, err := g.r.Handle(context.Background(), e); !errors.Is(err, ErrMUPaused) || out != nil || g.calls.Load() != 0 {
				t.Fatal("could not seed higher marks without effects", out, err, g.calls.Load())
			}
			g.r.config.Paused[g.v.grant] = false
			before := g.journal(t)
			old := snapshots[role].Entries[0]
			added := MURevocation{"record", "sha256:new-stale-hold"}
			snapshots[role].Entries = append(snapshots[role].Entries, added)
			snapshots[role].IssuedAt = muNow.Add(-61 * time.Second)
			if !snapshots[role].IssuedAt.Before(higher) {
				t.Fatal("fixture must be stale and below the existing mark")
			}
			out, err := g.r.Handle(context.Background(), e)
			if !errors.Is(err, ErrMUState) || err.Error() != "mu-required-state-unavailable" || out != nil || g.calls.Load() != 0 {
				t.Fatal("stale below-mark request did not refuse without effects", out, err, g.calls.Load())
			}
			after := g.journal(t)
			if len(after) <= len(before) || !bytes.HasPrefix(after, before) {
				t.Fatal("stale below-mark evidence did not grow the append-only journal")
			}
			s, err := openMUState(context.Background(), g.r.config.State, g.r.config.Binding)
			if err != nil {
				t.Fatal("stale below-mark journal could not reopen", err)
			}
			marks := map[string]time.Time{}
			unions := map[string]map[MURevocation]bool{}
			revoked := map[MURevocation]bool{}
			for _, v := range snapshots {
				marks[v.Signer] = higher
				unions[v.Signer] = map[MURevocation]bool{}
				for _, entry := range v.Entries {
					unions[v.Signer][entry] = true
					revoked[entry] = true
				}
			}
			unionGrew := len(s.unions[snapshots[role].Signer]) == 2 && s.unions[snapshots[role].Signer][old] && s.unions[snapshots[role].Signer][added]
			markPreserved := reflect.DeepEqual(s.highWater, marks)
			evidenceExact := reflect.DeepEqual(s.unions, unions) && reflect.DeepEqual(s.revoked, revoked)
			noAccounting := len(s.reservations) == 0 && len(s.nonces) == 0 && len(s.allowances) == 0
			s.close()
			if !unionGrew || !markPreserved || !evidenceExact || !noAccounting {
				t.Fatal("stale below-mark union growth or higher-mark preservation failed", unionGrew, markPreserved, evidenceExact, noAccounting)
			}
			// A complete fresh retry of the same event proves the refusal consumed no nonce.
			g.reopen()
			for i := range snapshots {
				snapshots[i].IssuedAt = muNow
			}
			linuxAdmitRecordingVerifier(g, &snapshots)
			out, err = g.r.Handle(context.Background(), e)
			if err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 {
				t.Fatal("fresh complete below-mark neighbor failed", out, err, g.calls.Load())
			}
		})
	}
}

// At the inclusive freshness boundary the exact evidence precedes the local
// pause refusal, and removing the pause admits the identical unreserved event.
func TestLinuxAdmitFreshNeighbors(t *testing.T) {
	for _, age := range []time.Duration{0, 60 * time.Second} {
		t.Run(age.String(), func(t *testing.T) {
			g := newLinuxRig(t)
			snapshots := linuxAdmitRecordingBatch(g)
			for i := range snapshots {
				snapshots[i].IssuedAt = muNow.Add(-age)
			}
			linuxAdmitRecordingVerifier(g, &snapshots)
			e := g.event(t, "$fresh-neighbor")
			want := linuxAdmitExpectedJournal(t, g, g.journal(t), snapshots)
			g.r.config.Paused[g.v.grant] = true
			out, err := g.r.Handle(context.Background(), e)
			if !errors.Is(err, ErrMUPaused) || out != nil || g.calls.Load() != 0 || !bytes.Equal(g.journal(t), want) {
				t.Fatal("fresh snapshot neighbor did not record before pause", out, err, g.calls.Load())
			}
			g.r.config.Paused[g.v.grant] = false
			out, err = g.r.Handle(context.Background(), e)
			if err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 {
				t.Fatal(out, err, g.calls.Load())
			}
		})
	}
}

// Adapter trust failures invalidate the whole invocation, including any valid
// peer and any stale/future snapshot encountered before the broken metadata.
func TestLinuxAdmitTrustFailuresDoNotRecord(t *testing.T) {
	changes := []struct {
		name   string
		change func(*LinuxAdmission)
	}{
		{"missing", func(a *LinuxAdmission) { a.Snapshots = nil }},
		{"too-many", func(a *LinuxAdmission) {
			for len(a.Snapshots) < 65 {
				a.Snapshots = append(a.Snapshots, a.Snapshots[1])
			}
		}},
		{"duplicate-signer", func(a *LinuxAdmission) { a.Snapshots = append(a.Snapshots, a.Snapshots[0]) }},
		{"unpinned", func(a *LinuxAdmission) { a.Snapshots[1].Signer = "ed25519:unpinned" }},
		{"fractional-time", func(a *LinuxAdmission) { a.Snapshots[1].IssuedAt = muNow.Add(-time.Nanosecond) }},
		{"duplicate-entry", func(a *LinuxAdmission) {
			a.Snapshots[1].Entries = append(a.Snapshots[1].Entries, a.Snapshots[1].Entries[0])
		}},
		{"invalid-entry", func(a *LinuxAdmission) { a.Snapshots[1].Entries[0].Kind = "invalid" }},
		{"missing-publisher", func(a *LinuxAdmission) { a.Snapshots = a.Snapshots[1:] }},
		{"decision-count-mismatch", func(a *LinuxAdmission) { a.Decision.Revocations = nil }},
		{"decision-entry-mismatch", func(a *LinuxAdmission) { a.Decision.Revocations = []MURevocation{{"record", "sha256:other"}} }},
	}
	for _, delta := range []time.Duration{-61 * time.Second, time.Second} {
		for _, tc := range changes {
			t.Run(fmt.Sprintf("%s/%s", delta, tc.name), func(t *testing.T) {
				g := newLinuxRig(t)
				snapshots := linuxAdmitRecordingBatch(g)
				snapshots[0].IssuedAt = muNow.Add(delta)
				g.r.verifier = linuxAdmissionFunc(func(e MUEnvelopeEvent, now time.Time) (LinuxAdmission, error) {
					d, err := g.v.VerifyProjected(e, now)
					d.Revocations = append([]MURevocation(nil), snapshots[0].Entries...)
					a := LinuxAdmission{Decision: d, Snapshots: snapshots}
					tc.change(&a)
					return a, err
				})
				before := g.journal(t)
				out, err := g.r.Handle(context.Background(), g.event(t, "$trust-failure"))
				if !errors.Is(err, ErrMUState) || out != nil || g.calls.Load() != 0 || !bytes.Equal(g.journal(t), before) {
					t.Fatal("adapter trust failure recorded or dispatched", out, err, g.calls.Load())
				}
				// Repair the adapter, preserving the same complete evidence and grant.
				snapshots = linuxAdmitRecordingBatch(g)
				linuxAdmitRecordingVerifier(g, &snapshots)
				out, err = g.r.Handle(context.Background(), g.event(t, "$repaired-adapter"))
				if err != nil || out == nil || out.State != "succeeded" || g.calls.Load() != 1 {
					t.Fatal("corrected adapter refused", out, err, g.calls.Load())
				}
			})
		}
	}
}

// Claim: when the first journal write, recording a stale snapshot before its
// freshness refusal, fails in storage, the request refuses with ErrMUState
// (storage faults are normalized to it), the journal is byte-identical and no
// effect runs, although later writes would succeed.
// Control: the same request with healthy storage also refuses with
// ErrMUState but records the snapshot, so the fault case is not vacuous.
func TestLinuxAdmitFreshnessRecordingStorageFault(t *testing.T) {
	for _, fault := range []bool{false, true} {
		t.Run(fmt.Sprintf("fault=%t", fault), func(t *testing.T) {
			g := newLinuxRig(t)
			issued := muNow.Add(-61 * time.Second)
			g.v.revocations = []MURevocation{{"record", "sha256:stale-storage-fault"}}
			linuxSnapshotRig(g, &issued, nil)
			writes := 0
			if fault {
				g.r.open = func(ctx context.Context, c MUStateConfig, b MUBinding) (*muState, error) {
					s, err := openMUState(ctx, c, b)
					if err != nil {
						return nil, err
					}
					write := s.write
					s.write = func(f *os.File, raw []byte) (int, error) {
						writes++
						if writes == 1 {
							return 0, errors.New("injected journal write failure")
						}
						return write(f, raw)
					}
					return s, nil
				}
			}
			before := g.journal(t)
			_, err := g.r.Handle(context.Background(), g.event(t, "$stale-fault"))
			if !errors.Is(err, ErrMUState) || g.calls.Load() != 0 {
				t.Fatalf("got %v with %d effects, want %v and none", err, g.calls.Load(), ErrMUState)
			}
			after := g.journal(t)
			if fault {
				if writes == 0 {
					t.Fatal("setup: the injected write was never reached")
				}
				if !bytes.Equal(before, after) {
					t.Fatal("journal changed although the recording write failed")
				}
				return
			}
			if len(after) <= len(before) {
				t.Fatal("control: healthy storage did not record the stale snapshot")
			}
		})
	}
}
