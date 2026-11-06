package reviewedsession

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode/utf8"
)

// These are normalized comparison data. Neither this type nor its parser
// authenticates a transport, a sender, event state, freshness, or owner consent.
type publicationReceipt struct {
	nonce                                                      [32]byte
	sender                                                     string
	receiver                                                   *string
	requestedRoom, returnedRoom, requestedEvent, returnedEvent string
	eventType, subtype, kind, state, transaction               string
	body                                                       []byte
	sendSequence, readSequence                                 uint64
	scriptHash, transportHash                                  [32]byte
}

type control struct {
	cancel                                         bool
	nonce, snapshotHash, reviewHash, signingDigest [32]byte
	receipt                                        publicationReceipt
}

func parseControlFrame(raw []byte) (control, error) {
	var c control
	payload, err := framePayload(raw, commitMax)
	if err != nil {
		return c, err
	}
	m, err := strictObject(payload, commitMax)
	if err != nil {
		return c, err
	}
	switch m["type"] {
	case "kv-review-cancel/1":
		if len(payload) > cancelMax {
			return c, errSchema
		}
		if err := closed(m, "type", "session_nonce"); err != nil {
			return c, err
		}
		c.cancel = true
	case "kv-review-commit/1":
		if err := closed(m, "type", "session_nonce", "plan_snapshot_sha256", "review_body_sha256", "signing_digest_sha256", "publication_receipt"); err != nil {
			return c, err
		}
		for name, dest := range map[string]*[32]byte{
			"plan_snapshot_sha256": &c.snapshotHash, "review_body_sha256": &c.reviewHash, "signing_digest_sha256": &c.signingDigest,
		} {
			*dest, err = hashField(m, name)
			if err != nil {
				return control{}, err
			}
		}
		r, ok := m["publication_receipt"].(map[string]any)
		if !ok {
			return control{}, errSchema
		}
		c.receipt, err = parseReceipt(r)
		if err != nil {
			return control{}, err
		}
	default:
		return c, errSchema
	}
	c.nonce, err = hashField(m, "session_nonce")
	if err != nil {
		return control{}, err
	}
	return c, nil
}

func hashField(m map[string]any, name string) ([32]byte, error) {
	s, err := text(m, name)
	if err != nil {
		return [32]byte{}, err
	}
	return digestHex(s)
}

func parseReceipt(m map[string]any) (publicationReceipt, error) {
	var r publicationReceipt
	if err := closed(m, "schema", "session_nonce", "sender_mxid", "receiver_mxid", "requested_room_id", "returned_room_id", "requested_event_id", "returned_event_id", "event_type", "message_subtype", "kind", "body_base64", "body_bytes", "event_state", "send_transaction_id", "send_sequence", "read_sequence", "script_artifact_sha256", "transport_artifact_sha256"); err != nil {
		return r, err
	}
	if m["schema"] != "kv-publication-receipt/1" {
		return r, errSchema
	}
	var err error
	for name, dest := range map[string]*string{
		"sender_mxid": &r.sender, "requested_room_id": &r.requestedRoom, "returned_room_id": &r.returnedRoom,
		"requested_event_id": &r.requestedEvent, "returned_event_id": &r.returnedEvent,
		"event_type": &r.eventType, "message_subtype": &r.subtype, "kind": &r.kind,
		"event_state": &r.state, "send_transaction_id": &r.transaction,
	} {
		*dest, err = text(m, name)
		if err != nil {
			return publicationReceipt{}, err
		}
	}
	if m["receiver_mxid"] != nil {
		s, err := text(m, "receiver_mxid")
		if err != nil {
			return publicationReceipt{}, err
		}
		r.receiver = &s
	}
	for name, dest := range map[string]*[32]byte{
		"session_nonce": &r.nonce, "script_artifact_sha256": &r.scriptHash, "transport_artifact_sha256": &r.transportHash,
	} {
		*dest, err = hashField(m, name)
		if err != nil {
			return publicationReceipt{}, err
		}
	}
	s, err := text(m, "body_base64")
	if err != nil {
		return publicationReceipt{}, err
	}
	r.body, err = byteString(s, reviewMax)
	if err != nil || !utf8.Valid(r.body) {
		return publicationReceipt{}, errSchema
	}
	n, err := positive(m, "body_bytes")
	if err != nil || n != uint64(len(r.body)) {
		return publicationReceipt{}, errSchema
	}
	r.sendSequence, err = positive(m, "send_sequence")
	if err != nil {
		return publicationReceipt{}, err
	}
	r.readSequence, err = positive(m, "read_sequence")
	if err != nil || r.readSequence <= r.sendSequence {
		return publicationReceipt{}, errSchema
	}
	if r.state != "original_unedited_unredacted_plain" {
		return publicationReceipt{}, errSchema
	}
	return r, nil
}

// publicationExpectation must eventually originate in protected admission AND
// the live script's current successful send result. A normalized response must
// never populate its own expectation. No such adapter/admission exists here.
type publicationExpectation struct {
	sender                                                           string
	receiver                                                         *string
	room, currentEvent, eventType, subtype, kind, currentTransaction string
	currentSendSequence                                              uint64
	scriptHash, transportHash                                        [32]byte
}

func (p publicationExpectation) compare(r publicationReceipt) error {
	if p.sender == "" || p.room == "" || !strings.HasPrefix(p.room, "!") || p.currentEvent == "" || !strings.HasPrefix(p.currentEvent, "$") || p.currentTransaction == "" || p.eventType == "" || p.subtype == "" || p.kind == "" || p.currentSendSequence == 0 {
		return errBinding
	}
	if r.sender != p.sender || r.requestedRoom != p.room || r.returnedRoom != p.room || r.requestedEvent != p.currentEvent || r.returnedEvent != p.currentEvent || r.eventType != p.eventType || r.subtype != p.subtype || r.kind != p.kind || r.transaction != p.currentTransaction || r.sendSequence != p.currentSendSequence || r.readSequence <= r.sendSequence || r.state != "original_unedited_unredacted_plain" || r.scriptHash != p.scriptHash || r.transportHash != p.transportHash {
		return errBinding
	}
	if (r.receiver == nil) != (p.receiver == nil) {
		return errBinding
	}
	if r.receiver != nil && *r.receiver != *p.receiver {
		return errBinding
	}
	return nil
}

// ownedComparison is ONLY an immutable byte-comparison fixture/component. It
// validates no grant, snapshot schema, release, admission or evidence. It issues
// no permit and cannot sign. A future typed plan must compose these comparisons
// after independently admitted profile validation, not promote this to a plan.
type ownedComparison struct {
	preimage, snapshot, review                     []byte
	nonce, signingDigest, snapshotHash, reviewHash [32]byte
}

func newOwnedComparison(preimage, snapshot, review []byte, nonce [32]byte) (*ownedComparison, error) {
	if len(preimage) == 0 || len(preimage) > snapshotMax || len(snapshot) == 0 || len(snapshot) > snapshotMax || len(review) == 0 || len(review) > reviewMax {
		return nil, errBinding
	}
	p := &ownedComparison{preimage: bytes.Clone(preimage), snapshot: bytes.Clone(snapshot), review: bytes.Clone(review), nonce: nonce,
		signingDigest: sha256.Sum256(preimage), snapshotHash: sha256.Sum256(snapshot), reviewHash: sha256.Sum256(review)}
	if err := p.checkTrailer(p.review); err != nil {
		return nil, err
	}
	return p, nil
}

func (p *ownedComparison) checkTrailer(body []byte) error {
	if p == nil || !bytes.Equal(body, p.review) || !utf8.Valid(body) {
		return errBinding
	}
	s := string(body)
	trailer := "plan_snapshot_sha256=" + hex.EncodeToString(p.snapshotHash[:]) + "\nsession_nonce=" + hex.EncodeToString(p.nonce[:]) + "\nshort_signing_digest=" + shortDigest(p.signingDigest) + "\nsigning_digest_sha256=" + hex.EncodeToString(p.signingDigest[:]) + "\n"
	if !strings.HasSuffix(s, "\n"+trailer) {
		return errBinding
	}
	for _, label := range []string{"plan_snapshot_sha256=", "session_nonce=", "short_signing_digest=", "signing_digest_sha256="} {
		if strings.Count(s, label) != 1 {
			return errBinding
		}
	}
	segment := digestLabel + shortDigest(p.signingDigest) + "]"
	if strings.Count(s, segment) != 1 || strings.Count(s, digestLabel) != 1 {
		return errBinding
	}
	return nil
}

// Comparing a commit is not accepting authenticated publication. There is no
// state transition or capability here; workflowAvailability still refuses.
func (p *ownedComparison) compare(c control, expected publicationExpectation) error {
	if p == nil || c.cancel || c.nonce != p.nonce || c.receipt.nonce != p.nonce || c.snapshotHash != p.snapshotHash || c.reviewHash != p.reviewHash || c.signingDigest != p.signingDigest {
		return errBinding
	}
	if sha256.Sum256(p.preimage) != p.signingDigest || sha256.Sum256(p.snapshot) != p.snapshotHash || sha256.Sum256(p.review) != p.reviewHash {
		return errBinding
	}
	if err := p.checkTrailer(c.receipt.body); err != nil {
		return err
	}
	return expected.compare(c.receipt)
}
