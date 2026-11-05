package grants

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-envelope/record"
	"github.com/relux-works/swarma-keyvault/internal/mugrant"
)

func muProjectionRecord(t *testing.T, mutate func(map[string]any)) []byte {
	t.Helper()
	env := []byte(`{"body":{"type":"message/1"},"id":"sha256:00","signatures":[],"version":"swarm-envelope/2"}`)
	m := map[string]any{"type": "a2a.event-envelope-input/1", "sender_mxid": muDockMeta, "receiver_mxid": muDockReceiver,
		"requested_room_id": muDockRoom, "requested_event_id": "$e", "returned_room_id": muDockRoom, "returned_event_id": "$e",
		"envelope_base64": base64.RawURLEncoding.EncodeToString(env), "body_text_base64": base64.RawURLEncoding.EncodeToString([]byte("text"))}
	if mutate != nil {
		mutate(m)
	}
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return append(raw, '\n')
}

// Claim: the projection parser admits exactly the a2a #189 record (nine string
// fields, ids equal to the requested ones, unpadded base64url, one object plus
// one LF) and refuses each deviation, beside the valid record.
func TestMUProjectionParse(t *testing.T) {
	e, err := ParseMUProjection(muProjectionRecord(t, nil), muDockRoom, "$e")
	if err != nil || e.Sender != muDockMeta || e.Receiver != muDockReceiver || string(e.Text) != "text" {
		t.Fatal("valid record refused", err)
	}
	cases := map[string]func(map[string]any){
		"missing-field":  func(m map[string]any) { delete(m, "returned_room_id") },
		"extra-field":    func(m map[string]any) { m["expected_sender"] = "x" },
		"wrong-type":     func(m map[string]any) { m["type"] = "a2a.event-verification-input/1" },
		"room-mismatch":  func(m map[string]any) { m["returned_room_id"] = "!other:gr.relux.works" },
		"event-mismatch": func(m map[string]any) { m["returned_event_id"] = "$other" },
		"padded-base64":  func(m map[string]any) { m["body_text_base64"] = "dGV4dA==" },
		// "dGV4dB" decodes to "text" only if non-zero trailing bits are ignored.
		"noncanonical-base64": func(m map[string]any) { m["body_text_base64"] = "dGV4dB" },
		"empty-text":          func(m map[string]any) { m["body_text_base64"] = "" },
		"not-an-envelope": func(m map[string]any) {
			m["envelope_base64"] = base64.RawURLEncoding.EncodeToString([]byte("{not json"))
		},
		"number-field": func(m map[string]any) { m["sender_mxid"] = 7 },
	}
	for name, mutate := range cases {
		if _, err := ParseMUProjection(muProjectionRecord(t, mutate), muDockRoom, "$e"); !errors.Is(err, ErrMUProjection) {
			t.Error("deviation admitted", name)
		}
	}
	good := muProjectionRecord(t, nil)
	for name, raw := range map[string][]byte{"no-lf": good[:len(good)-1], "two-lf": append(bytes.Clone(good), '\n'), "leading-space": append([]byte(" "), good...)} {
		if _, err := ParseMUProjection(raw, muDockRoom, "$e"); !errors.Is(err, ErrMUProjection) {
			t.Error("framing admitted", name)
		}
	}
	// A duplicated member (here the sender) refuses, whichever value is last.
	dup := bytes.Replace(good, []byte(`{"body_text_base64"`), []byte(`{"sender_mxid":"@other:gr.relux.works","body_text_base64"`), 1)
	if bytes.Equal(dup, good) {
		t.Fatal("fixture")
	}
	if _, err := ParseMUProjection(dup, muDockRoom, "$e"); !errors.Is(err, ErrMUProjection) {
		t.Error("duplicate member admitted")
	}
	if _, err := ParseMUProjection(good, muDockRoom, "$other"); !errors.Is(err, ErrMUProjection) {
		t.Error("record for another requested event admitted")
	}
}

// Claim: owner-root revocation snapshots are admitted only when signed by the
// pinned root over the exact body; a snapshot by another key or a tampered
// entry refuses the whole set.
func TestMUVerifyRootRevocations(t *testing.T) {
	root, other := newMUKey(t), newMUKey(t)
	at := time.Date(2026, 11, 5, 18, 0, 0, 0, time.UTC)
	entry := []mugrant.SnapshotEntry{{Kind: "record", ID: "sha256:abcd", From: "2026-11-05T17:00:00Z"}}
	snap := func(k muKey) []byte {
		p, err := mugrant.BuildSnapshot(k.id, at, entry)
		if err != nil {
			t.Fatal(err)
		}
		return k.sign(t, p)
	}
	got, err := VerifyRootRevocations(root.id, [][]byte{snap(root)})
	if err != nil || len(got) != 1 || got[0] != (MURevocation{"record", "sha256:abcd"}) {
		t.Fatal("root snapshot refused", err, got)
	}
	if _, err := VerifyRootRevocations(root.id, [][]byte{snap(root), snap(other)}); err == nil {
		t.Error("snapshot by another key admitted")
	}
	tampered := bytes.Replace(snap(root), []byte("sha256:abcd"), []byte("sha256:abce"), 1)
	if _, err := VerifyRootRevocations(root.id, [][]byte{tampered}); err == nil {
		t.Error("tampered snapshot admitted")
	}
	// Tamper the entry AND recompute the content id: only the signature
	// check can refuse this one.
	e, err := muParseEnvelope(snap(root))
	if err != nil {
		t.Fatal(err)
	}
	body := e["body"].(map[string]any)
	body["entries"].([]any)[0].(map[string]any)["id"] = "sha256:ffff"
	id, err := record.ContentID("revocation/1", body)
	if err != nil {
		t.Fatal(err)
	}
	e["id"] = id
	reid, err := record.Canonical(e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRootRevocations(root.id, [][]byte{reid}); err == nil {
		t.Error("re-identified tampered snapshot admitted")
	}
}
