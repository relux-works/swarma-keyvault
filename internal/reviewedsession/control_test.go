package reviewedsession

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
)

func hexHash(d [32]byte) string { return hex.EncodeToString(d[:]) }

// These are PUBLIC SYNTHETIC fixtures. They supply no deployment admission,
// actual room/sender, attestation, successful send, authenticated read or permit.
func comparisonFixture(t *testing.T) (*ownedComparison, publicationExpectation, map[string]any) {
	t.Helper()
	preimage := []byte("synthetic-domain\n{\"synthetic\":true}")
	snapshot := []byte("synthetic snapshot bytes, NOT kv-reviewed-plan/1")
	nonce := testDigest()
	d, s := sha256.Sum256(preimage), sha256.Sum256(snapshot)
	body := []byte("СИНТЕТИЧЕСКИЙ ТЕСТ; НЕ ДОПУСК\n" + digestLabel + shortDigest(d) + "]\n" +
		"plan_snapshot_sha256=" + hexHash(s) + "\nsession_nonce=" + hexHash(nonce) + "\nshort_signing_digest=" + shortDigest(d) + "\nsigning_digest_sha256=" + hexHash(d) + "\n")
	p, err := newOwnedComparison(preimage, snapshot, body, nonce)
	if err != nil {
		t.Fatal(err)
	}
	receiver := "@receiver:example.invalid"
	e := publicationExpectation{sender: "@sender:example.invalid", receiver: &receiver, room: "!synthetic:example.invalid", currentEvent: "$synthetic-current-send", eventType: "m.room.message", subtype: "m.text", kind: "owner-needed", currentTransaction: "synthetic-transaction", currentSendSequence: 11, scriptHash: sha256.Sum256([]byte("synthetic script")), transportHash: sha256.Sum256([]byte("synthetic transport"))}
	r := map[string]any{
		"schema": "kv-publication-receipt/1", "session_nonce": hexHash(nonce), "sender_mxid": e.sender, "receiver_mxid": receiver,
		"requested_room_id": e.room, "returned_room_id": e.room, "requested_event_id": e.currentEvent, "returned_event_id": e.currentEvent,
		"event_type": e.eventType, "message_subtype": e.subtype, "kind": e.kind, "body_base64": base64.RawURLEncoding.EncodeToString(body), "body_bytes": len(body),
		"event_state": "original_unedited_unredacted_plain", "send_transaction_id": e.currentTransaction, "send_sequence": 11, "read_sequence": 12,
		"script_artifact_sha256": hexHash(e.scriptHash), "transport_artifact_sha256": hexHash(e.transportHash),
	}
	m := map[string]any{"type": "kv-review-commit/1", "session_nonce": hexHash(nonce), "plan_snapshot_sha256": hexHash(s), "review_body_sha256": hexHash(sha256.Sum256(body)), "signing_digest_sha256": hexHash(d), "publication_receipt": r}
	return p, e, m
}

func framed(t *testing.T, m map[string]any) []byte {
	t.Helper()
	raw, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := writeFrame(&b, raw, commitMax); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func TestNormalizedReceiptIsOnlyComparisonData(t *testing.T) {
	p, e, m := comparisonFixture(t)
	c, err := parseControlFrame(framed(t, m))
	if err != nil {
		t.Fatal(err)
	}
	if err := p.compare(c, e); err != nil {
		t.Fatal(err)
	}
	if workflowAvailability() == nil {
		t.Fatal("synthetic matching receipt enabled workflow")
	}
	// Expected identity, room and successful-send coordinates are supplied
	// separately. Copying forged response fields into the response alone fails.
	mutations := map[string]func(map[string]any){
		"outer-nonce":         func(m map[string]any) { m["session_nonce"] = strings.Repeat("1", 64) },
		"context-only-change": func(m map[string]any) { m["plan_snapshot_sha256"] = strings.Repeat("1", 64) },
		"review-hash":         func(m map[string]any) { m["review_body_sha256"] = strings.Repeat("1", 64) },
		"same-short-different-full-digest": func(m map[string]any) {
			s := m["signing_digest_sha256"].(string)
			m["signing_digest_sha256"] = s[:62] + "ff"
		},
		"receipt-nonce": func(m map[string]any) { receiptMap(m)["session_nonce"] = strings.Repeat("1", 64) },
		"sender":        func(m map[string]any) { receiptMap(m)["sender_mxid"] = "@attacker:example.invalid" },
		"receiver":      func(m map[string]any) { receiptMap(m)["receiver_mxid"] = "@attacker:example.invalid" },
		"null-receiver": func(m map[string]any) { receiptMap(m)["receiver_mxid"] = nil },
		"room-alias":    func(m map[string]any) { receiptMap(m)["requested_room_id"] = "#alias:example.invalid" },
		"returned-room": func(m map[string]any) { receiptMap(m)["returned_room_id"] = "!wrong:example.invalid" },
		"current-send-id": func(m map[string]any) {
			receiptMap(m)["requested_event_id"] = "$previous"
			receiptMap(m)["returned_event_id"] = "$previous"
		},
		"returned-id":             func(m map[string]any) { receiptMap(m)["returned_event_id"] = "$wrong" },
		"event-type":              func(m map[string]any) { receiptMap(m)["event_type"] = "m.room.encrypted" },
		"subtype":                 func(m map[string]any) { receiptMap(m)["message_subtype"] = "m.notice" },
		"kind":                    func(m map[string]any) { receiptMap(m)["kind"] = "other" },
		"script":                  func(m map[string]any) { receiptMap(m)["script_artifact_sha256"] = strings.Repeat("0", 64) },
		"transport":               func(m map[string]any) { receiptMap(m)["transport_artifact_sha256"] = strings.Repeat("0", 64) },
		"transaction":             func(m map[string]any) { receiptMap(m)["send_transaction_id"] = "previous" },
		"different-send-sequence": func(m map[string]any) { receiptMap(m)["send_sequence"] = 10 },
		"read-before-send":        func(m map[string]any) { receiptMap(m)["read_sequence"] = 10 },
		"equal-sequences":         func(m map[string]any) { receiptMap(m)["read_sequence"] = 11 },
		"zero-sequence":           func(m map[string]any) { receiptMap(m)["send_sequence"] = 0 },
		"float-sequence":          func(m map[string]any) { receiptMap(m)["send_sequence"] = json.Number("11.0") },
		"sequence-overflow":       func(m map[string]any) { receiptMap(m)["read_sequence"] = json.Number("18446744073709551616") },
		"edited":                  func(m map[string]any) { receiptMap(m)["event_state"] = "edited" },
		"redacted":                func(m map[string]any) { receiptMap(m)["event_state"] = "redacted" },
		"formatted-alternate":     func(m map[string]any) { receiptMap(m)["formatted_body"] = "<p>other</p>" },
		"approval-forgery":        func(m map[string]any) { receiptMap(m)["owner_approved"] = true },
		"authenticated-flag":      func(m map[string]any) { receiptMap(m)["authenticated"] = true },
		"missing-required-field":  func(m map[string]any) { delete(receiptMap(m), "event_state") },
		"bad-byte-count":          func(m map[string]any) { receiptMap(m)["body_bytes"] = 1 },
		"padded-base64":           func(m map[string]any) { receiptMap(m)["body_base64"] = receiptMap(m)["body_base64"].(string) + "=" },
		"snapshot-replacement":    func(m map[string]any) { m["plan_snapshot_base64"] = "eA" },
	}
	good, _ := json.Marshal(m)
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			var changed map[string]any
			if err := json.Unmarshal(good, &changed); err != nil {
				t.Fatal(err)
			}
			mutate(changed)
			got, err := parseControlFrame(framed(t, changed))
			if err == nil {
				err = p.compare(got, e)
			}
			if err == nil {
				t.Fatal("accepted mutated comparison data")
			}
			neighbor, err := parseControlFrame(framed(t, m))
			if err != nil || p.compare(neighbor, e) != nil {
				t.Fatal("broken valid neighbor", err)
			}
		})
	}
}

func receiptMap(m map[string]any) map[string]any { return m["publication_receipt"].(map[string]any) }

func TestWholeBodyExactnessAndTrailer(t *testing.T) {
	p, e, m := comparisonFixture(t)
	good := bytes.Clone(p.review)
	for name, body := range map[string][]byte{
		"prefix": append([]byte("extra\n"), good...), "suffix": append(bytes.Clone(good), []byte("extra\n")...),
		"missing-final-lf": good[:len(good)-1], "crlf": bytes.ReplaceAll(good, []byte("\n"), []byte("\r\n")),
		"different-human-body": bytes.Replace(good, []byte("ТЕСТ"), []byte("ТЕКСТ"), 1),
		"duplicate-full-field": append(bytes.Clone(good), []byte("signing_digest_sha256="+hexHash(p.signingDigest)+"\n")...),
	} {
		t.Run(name, func(t *testing.T) {
			r := receiptMap(m)
			r["body_base64"] = base64.RawURLEncoding.EncodeToString(body)
			r["body_bytes"] = len(body)
			c, err := parseControlFrame(framed(t, m))
			if err == nil {
				err = p.compare(c, e)
			}
			if err == nil {
				t.Fatal("accepted changed whole body")
			}
		})
	}
	// Also reject a malicious expected body with duplicate authoritative fields;
	// equality to such a body is insufficient on its own.
	duplicated := append([]byte("signing_digest_sha256="+hexHash(p.signingDigest)+"\n"), good...)
	if _, err := newOwnedComparison(p.preimage, p.snapshot, duplicated, p.nonce); err == nil {
		t.Fatal("expected-body duplicate accepted")
	}
}

func TestOwnedBytesAndContextAreNotReopenedOrReplaced(t *testing.T) {
	p, e, m := comparisonFixture(t)
	preimage, snapshot, review := bytes.Clone(p.preimage), bytes.Clone(p.snapshot), bytes.Clone(p.review)
	owned, err := newOwnedComparison(preimage, snapshot, review, p.nonce)
	if err != nil {
		t.Fatal(err)
	}
	preimage[0] ^= 1
	snapshot[0] ^= 1
	review[0] ^= 1
	c, err := parseControlFrame(framed(t, m))
	if err != nil || owned.compare(c, e) != nil {
		t.Fatal("ingress aliases retained", err)
	}
	for _, which := range []string{"preimage", "snapshot", "review"} {
		p, e, m := comparisonFixture(t)
		c, err := parseControlFrame(framed(t, m))
		if err != nil {
			t.Fatal(err)
		}
		switch which {
		case "preimage":
			p.preimage[0] ^= 1
		case "snapshot":
			p.snapshot[0] ^= 1
		case "review":
			p.review[0] ^= 1
		}
		if p.compare(c, e) == nil {
			t.Fatal("corrupt owned bytes accepted", which)
		}
	}
}

func TestCancelCannotCompareAsCommit(t *testing.T) {
	p, e, _ := comparisonFixture(t)
	m := map[string]any{"type": "kv-review-cancel/1", "session_nonce": hexHash(p.nonce)}
	c, err := parseControlFrame(framed(t, m))
	if err != nil || !c.cancel {
		t.Fatal(c, err)
	}
	if p.compare(c, e) == nil {
		t.Fatal("cancel accepted as commit")
	}
	m["signing_digest_sha256"] = hexHash(p.signingDigest)
	if _, err := parseControlFrame(framed(t, m)); err == nil {
		t.Fatal("extended cancel accepted")
	}
}
