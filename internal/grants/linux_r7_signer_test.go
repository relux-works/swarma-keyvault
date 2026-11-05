package grants

import (
	"context"
	"encoding/base64"
	"errors"
	"github.com/relux-works/swarma-envelope/record"
	"strings"
	"testing"
	"time"
)

// Override only transport availability; signature/shape verification and journal
// persistence still run through the real verifier and receiver.
type linuxR7SnapshotSource struct {
	*linuxVerifierFake
	failed string
	reads  []string
}

func (s *linuxR7SnapshotSource) Snapshot(root string) (LinuxSnapshot, error) {
	s.reads = append(s.reads, root)
	if root == s.failed {
		return LinuxSnapshot{}, errors.New("snapshot transport offline")
	}
	return s.linuxVerifierFake.Snapshot(root)
}

// A defective signer must not suppress another signer's verified union or mark.
// Reopen the journal before trying equal/older snapshots that drop the entry.
// The author case checks durable revocation; the unrelated record case checks
// continuity/mark enforcement independently of an already-revoked author.
// Claim: Either healthy signer survives peer evidence failure; equal/older omissions refuse after reopen beside a valid-peer positive.
func TestLinuxR7IndependentSignerDurability(t *testing.T) {
	for _, badRole := range []string{"publisher", "registry"} {
		for _, defect := range []string{"incomplete", "extra", "entry-shape", "oversize", "unavailable", "fetch-error", "signature"} {
			for _, dropped := range []string{"equal", "older"} {
				for _, target := range []string{"author", "unrelated-record"} {
					t.Run(badRole+"/"+defect+"/"+dropped+"/"+target, func(t *testing.T) {
						positive := newLinuxCombinedRig(t)
						ps := positive.dock.pub.id
						if badRole == "publisher" {
							ps = positive.dock.revokerID
						}
						positive.dock.snapshot(ps, positive.dock.now.Add(-5*time.Second), []any{map[string]any{"kind": "record", "id": "sha256:" + strings.Repeat("1", 64), "from": positive.dock.now.Add(-time.Hour).Format(time.RFC3339)}})
						if err := positive.handle(); err != nil || positive.calls != 1 {
							t.Fatal("valid independent signer positive refused", err, positive.calls)
						}
						t.Log("nearby positive effects", positive.calls)
						g := newLinuxCombinedRig(t)
						d := g.dock
						bad, healthy := d.pub.id, d.revokerID
						if badRole == "registry" {
							bad, healthy = healthy, bad
						}
						at := d.now.Add(-5 * time.Second)
						revoked := MURevocation{Kind: "key", ID: d.agentID}
						if target == "unrelated-record" {
							revoked = MURevocation{Kind: "record", ID: "sha256:" + strings.Repeat("1", 64)}
						}
						d.snapshot(healthy, at, []any{map[string]any{"kind": revoked.Kind, "id": revoked.ID, "from": d.now.Add(-time.Hour).Format(time.RFC3339)}})
						badEntry := map[string]any{"kind": "key", "id": d.serviceID, "from": d.now.Add(-time.Hour).Format(time.RFC3339)}
						body := map[string]any{"type": "revocation/1", "issuer": bad, "issued_at": at.Format(time.RFC3339), "complete": true, "entries": []any{badEntry}}
						source := &linuxR7SnapshotSource{linuxVerifierFake: d.fake}
						switch defect {
						case "incomplete":
							body["complete"] = false
						case "extra":
							body["extra"] = true
						case "entry-shape":
							badEntry["extra"] = true
						case "oversize":
							badEntry["kind"], badEntry["id"] = "record", "sha256:"+strings.Repeat("0", 64)
							entries := []any{}
							for range 64 {
								entries = append(entries, badEntry)
							}
							body["entries"] = entries
						case "fetch-error":
							source.failed = bad
						}
						var wire []byte
						if badRole == "publisher" {
							wire = signedSnapshotBody(t, d.pub, body)
						} else {
							wire = linuxVerifierSign(t, bad, d.revoker, body)
						}
						if defect == "signature" {
							env, err := muParseEnvelope(wire)
							if err != nil {
								t.Fatal(err)
							}
							env["signatures"].([]any)[0].(map[string]any)["sig"] = base64.RawURLEncoding.EncodeToString(make([]byte, 64))
							wire, err = record.Canonical(env)
							if err != nil {
								t.Fatal(err)
							}
						}
						if defect == "oversize" && len(wire) <= muMaxSnapshotBytes {
							t.Fatal("oversize premise", len(wire))
						}
						d.fake.snapshots[bad] = LinuxSnapshot{Wire: wire, Available: defect != "unavailable", RollbackSafe: true}
						p, err := NewLinuxVerifier(d.config, source, d.fake, func(string, string) (MUEnvelopeEvent, error) { return d.event, nil })
						if err != nil {
							t.Fatal(err)
						}
						r := g.receiver()
						r.verifier = p
						if _, err := r.Handle(context.Background(), d.event); err == nil || g.calls != 0 {
							t.Fatal("defective co-present snapshot executed", err, g.calls)
						} else if (defect == "unavailable" || defect == "fetch-error") && linuxVerifierCode(err) != "revocation_unavailable" {
							t.Fatal("transport refusal changed", err)
						} else {
							t.Log("initial refusal", linuxVerifierCode(err), "effects", g.calls)
						}
						if len(source.reads) != 2 || source.reads[0] != d.pub.id || source.reads[1] != d.revokerID {
							t.Fatal("each root must be fetched once despite a defective peer", source.reads)
						}
						s, err := openMUState(context.Background(), g.config.State, g.config.Binding)
						if err != nil {
							t.Fatal(err)
						}
						sn, err := openLinuxRevocationState(s)
						if err != nil {
							s.close()
							t.Fatal(err)
						}
						if !sn.journal.highWater[healthy].Equal(at) || len(sn.journal.unions[healthy]) != 1 || !sn.journal.unions[healthy][revoked] || !s.revoked[revoked] {
							t.Errorf("healthy observation lost after reopen: mark=%v union=%v global=%v", sn.journal.highWater[healthy], sn.journal.unions[healthy], s.revoked[revoked])
						}
						_, marked := sn.journal.highWater[bad]
						if marked || len(sn.journal.unions[bad]) != 0 || s.revoked[MURevocation{Kind: badEntry["kind"].(string), ID: badEntry["id"].(string)}] {
							t.Error("defective signer contributed durable state")
						}
						sn.close()
						s.close()
						// g.handle constructs a new receiver using the restored source.
						d.snapshot(bad, at.Add(-time.Second), nil)
						if dropped == "older" {
							at = at.Add(-time.Second)
						}
						d.snapshot(healthy, at, nil)
						want := ErrMURevoked
						if target == "unrelated-record" {
							want = ErrMURollback
						}
						if err := g.handle(); !errors.Is(err, want) || g.calls != 0 {
							t.Fatal("dropped verified union executed or changed refusal", err, want, g.calls)
						} else {
							t.Log("drop refusal", linuxVerifierCode(err), "effects", g.calls)
						}
					})
				}
			}
		}
	}
}
