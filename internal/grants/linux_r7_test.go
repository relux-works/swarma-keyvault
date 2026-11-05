package grants

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// A copied registry identity is independent of generation evidence. An already
// constructed verifier must refresh the latter and never adopt it as a new pin.
// Claim: Every request compares refreshed generation evidence with copied protected sender identity pins.
func TestLinuxProtectedIdentityPerRequest(t *testing.T) {
	for _, field := range []string{"key", "uid", "registration", "unavailable"} {
		t.Run(field, func(t *testing.T) {
			g := newLinuxVerifierDock(t)
			p := g.adapter()
			g.config.LinuxAgents[g.event.Sender] = MULinuxAgent{Key: g.serviceID, UID: 3, RegistrationNumber: 4}
			if _, err := p.VerifyProjected(g.event, g.now); err != nil {
				t.Fatal("configuration alias", err)
			}
			switch field {
			case "key":
				g.fake.agent.Key = g.serviceID
			case "uid":
				g.fake.agent.UID++
			case "registration":
				g.fake.agent.RegistrationNumber++
			case "unavailable":
				g.fake.agentErr = errors.New("offline")
			}
			if _, err := p.VerifyProjected(g.event, g.now); linuxVerifierCode(err) != "key_binding_unavailable" {
				t.Fatal("fresh evidence compared with protected pin", err)
			}
			if g.fake.calls != 2 {
				t.Fatal("evidence not refreshed", g.fake.calls)
			}
		})
	}
}

// Claim: A request cannot choose its author family or cause fallback from its protected sender identity.
func TestLinuxFamilyUsesProtectedSender(t *testing.T) {
	g := newLinuxVerifierDock(t)
	p := g.adapter()
	// A registered Linux identity cannot choose the Mac family by naming P-256.
	// This call deliberately uses a valid content reference to isolate routing.
	c, err := p.context(g.now, [32]byte{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.authorContext(&c, g.root.id, g.attID, g.event.Sender); linuxVerifierCode(err) != "key_binding_invalid" {
		t.Fatal(err)
	}
	if g.fake.calls != 0 {
		t.Fatal("request key caused registry fallback")
	}
	delete(g.config.LinuxAgents, g.event.Sender)
	if _, err := g.adapter().VerifyProjected(g.event, g.now); !errors.Is(err, ErrMUSender) {
		t.Fatal("unknown sender", err)
	}
	g.config.LinuxAgents = map[string]MULinuxAgent{g.event.Sender: {}}
	if _, err := g.adapter().VerifyProjected(g.event, g.now); linuxVerifierCode(err) != "key_binding_unavailable" {
		t.Fatal("missing pin", err)
	}
}

// Each malformed or oversized signed observation refuses without retaining its
// signer's entries or mark. A fresh older snapshot then succeeds after reopen.
// Claim: Malformed or oversized signed evidence contributes no union or mark, and an older valid replacement admits.
func TestLinuxR7InvalidSnapshotNeverDurable(t *testing.T) {
	for _, role := range []string{"publisher", "registry"} {
		for _, defect := range []string{"incomplete", "extra", "entry-shape", "oversize"} {
			t.Run(role+"/"+defect, func(t *testing.T) {
				g := newLinuxCombinedRig(t)
				d := g.dock
				signer := d.pub.id
				if role == "registry" {
					signer = d.revokerID
				}
				entry := map[string]any{"kind": "key", "id": d.serviceID, "from": d.now.Add(-time.Hour).Format(time.RFC3339)}
				body := map[string]any{"type": "revocation/1", "issuer": signer, "issued_at": d.now.Add(-time.Second).Format(time.RFC3339), "complete": true, "entries": []any{entry}}
				switch defect {
				case "incomplete":
					body["complete"] = false
				case "extra":
					body["extra"] = true
				case "entry-shape":
					entry["extra"] = true
				case "oversize":
					entries := []any{}
					entry["kind"] = "record"
					entry["id"] = "sha256:" + strings.Repeat("0", 64)
					for range 64 {
						entries = append(entries, entry)
					}
					body["entries"] = entries
				}
				var wire []byte
				if role == "publisher" {
					wire = signedSnapshotBody(t, d.pub, body)
				} else {
					wire = linuxVerifierSign(t, signer, d.revoker, body)
				}
				if defect == "oversize" && len(wire) <= muMaxSnapshotBytes {
					t.Fatal("oversize premise", len(wire))
				}
				d.fake.snapshots[signer] = LinuxSnapshot{Wire: wire, Available: true, RollbackSafe: true}
				if err := g.handle(); err == nil || g.calls != 0 {
					t.Fatal("invalid snapshot executed", err, g.calls)
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
				_, marked := sn.journal.highWater[signer]
				retained := len(sn.journal.unions[signer])
				globallyRevoked := s.revoked[MURevocation{entry["kind"].(string), entry["id"].(string)}]
				sn.close()
				s.close()
				if marked || retained != 0 || globallyRevoked {
					t.Fatal("invalid observation durable", marked, retained, globallyRevoked)
				}
				d.snapshot(signer, d.now.Add(-15*time.Second), nil)
				if err := g.handle(); err != nil || g.calls != 1 {
					t.Fatal("older valid snapshot after invalid", err, g.calls)
				}
			})
		}
	}
}

// r7 records statically valid observations even when publisher obligations
// (ordering, duplicates, from<=issued_at) are violated.
// Claim: Statically valid signed observations remain durable despite publisher sorting, duplicate or from-time violations.
func TestLinuxR7StaticSnapshotObservations(t *testing.T) {
	for _, role := range []string{"publisher", "registry"} {
		t.Run(role, func(t *testing.T) {
			g := newLinuxCombinedRig(t)
			d := g.dock
			at := d.now.Add(-5 * time.Second)
			signer := d.pub.id
			if role == "registry" {
				signer = d.revokerID
			}
			entry := map[string]any{"kind": "key", "id": d.serviceID, "from": d.now.Add(time.Second).Format(time.RFC3339)}
			// record before key is unsorted; the key entry is also repeated.
			entries := []any{map[string]any{"kind": "record", "id": "sha256:" + strings.Repeat("0", 64), "from": d.now.Add(time.Second).Format(time.RFC3339)}, entry, entry}
			body := map[string]any{"type": "revocation/1", "issuer": signer, "issued_at": at.Format(time.RFC3339), "complete": true, "entries": entries}
			var wire []byte
			if role == "publisher" {
				wire = signedSnapshotBody(t, d.pub, body)
			} else {
				wire = linuxVerifierSign(t, signer, d.revoker, body)
			}
			if len(wire) > muMaxSnapshotBytes {
				t.Fatal("valid bound premise", len(wire))
			}
			if _, err := record.Parse(wire, muMaxSnapshotBytes, 16); err != nil {
				t.Fatal(err)
			}
			d.fake.snapshots[signer] = LinuxSnapshot{Wire: wire, Available: true, RollbackSafe: true}
			admission, err := d.adapter().VerifyAdmission(d.event, d.now)
			if err != nil {
				t.Fatal("static-shape observation refused", err)
			}
			g.config.Paused = map[string]bool{admission.Decision.GrantID: true}
			if err := g.handle(); !errors.Is(err, ErrMUPaused) {
				t.Fatal(err)
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
			if !sn.journal.highWater[signer].Equal(at) || len(sn.journal.unions[signer]) != 2 {
				t.Errorf("lost observation: mark=%v entries=%d want=2", sn.journal.highWater[signer], len(sn.journal.unions[signer]))
			}
			sn.close()
			s.close()
		})
	}
}
