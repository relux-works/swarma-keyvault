package grants

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"sort"
	"time"

	"github.com/relux-works/swarma-envelope/record"
)

// Candidate-only extension of an existing MU reservation body. It introduces
// no separate file, authority source or wire profile. Old readers refuse MUP1;
// a journal containing it must never be downgraded. No production caller is
// enabled until authoritative update exclusion and storage bounds are qualified.
type muVerificationCommit struct {
	now, authorityUntil, watermark  time.Time
	deadline                        time.Time // transient original monotonic fence; not a replayed clock
	ids                             map[string][]byte
	complete                        bool
	publisherKey, authorAttestation string // transient verified decision bindings
}

func (v *linuxProviderView) commitCandidate(a LinuxAdmission) (muVerificationCommit, error) {
	var c muVerificationCommit
	if !v.usable() || a.Decision.RequestHash != sha256.Sum256(v.input.Event.Envelope) ||
		!v.input.State.WatermarkAvailable || !v.input.State.IDJournalAvailable || v.input.State.IDJournal == nil ||
		len(a.plan.originals) == 0 || a.plan.watermark.IsZero() {
		return c, ErrMUState
	}
	// Check the complete union before allocating a detached candidate. A full
	// 4096-binding baseline is not silently evicted to make room for this use.
	count, remaining := len(v.input.State.IDJournal), linuxVerificationMaxViewBytes-16
	charge := func(id string, wire []byte) bool {
		if len(wire) > 65536 || len(id) > remaining {
			return false
		}
		remaining -= len(id)
		if remaining < 16 || len(wire) > remaining-16 {
			return false
		}
		remaining -= 16 + len(wire)
		return true
	}
	for id, wire := range v.input.State.IDJournal {
		if !charge(id, wire) {
			return c, ErrMUState
		}
	}
	for id, wire := range a.plan.originals {
		if prior, ok := v.input.State.IDJournal[id]; ok {
			if !bytes.Equal(prior, wire) {
				return c, ErrMUState
			}
		} else {
			count++
			if count > linuxVerificationMaxIDBindings || !charge(id, wire) {
				return c, ErrMUState
			}
		}
	}
	c = muVerificationCommit{now: v.input.State.Now, authorityUntil: v.input.State.AuthorityUntil, watermark: a.plan.watermark, deadline: v.deadline, ids: map[string][]byte{}, complete: true}
	c.publisherKey, c.authorAttestation = a.Decision.PublisherKey, a.Decision.AuthorAttestation
	for id, wire := range v.input.State.IDJournal {
		c.ids[id] = bytes.Clone(wire)
	}
	for id, wire := range a.plan.originals {
		if prior, ok := c.ids[id]; ok && !bytes.Equal(prior, wire) {
			return muVerificationCommit{}, ErrMUState
		}
		c.ids[id] = bytes.Clone(wire)
	}
	if !linuxVerificationJournalFits(c.ids) {
		return muVerificationCommit{}, ErrMUState
	}
	return c, nil
}

func (s *muState) validVerificationCommit(c muVerificationCommit) bool {
	if !c.complete || c.ids == nil || !linuxVerificationJournalFits(c.ids) || c.now.Unix() <= 0 || c.now.Nanosecond() != 0 ||
		c.authorityUntil.Nanosecond() != 0 || c.watermark.Nanosecond() != 0 || !c.authorityUntil.After(c.now) ||
		c.watermark.Before(c.now) || !c.authorityUntil.After(c.watermark) || c.now.Before(s.verificationNow) || c.watermark.Before(s.verificationWatermark) {
		return false
	}
	for id, wire := range s.verificationIDs {
		if current, ok := c.ids[id]; !ok || !bytes.Equal(current, wire) {
			return false
		}
	}
	return true
}

func encodeMUVerification(r *muReservation, c muVerificationCommit) ([]byte, error) {
	// Keep the existing reservation frame limit. A complete larger history is
	// unavailable, never truncated, chunked into an unsafe partial transaction,
	// evicted or given a widened limit.
	size := 159
	if len(c.ids) > linuxVerificationMaxIDBindings {
		return nil, ErrMUState
	}
	for id, wire := range c.ids {
		if !record.IsContentID(id) || len(wire) == 0 || len(wire) > 65536 || len(id) > 65535 {
			return nil, ErrMUState
		}
		if size > journalBodyLimit(journalReservation)-6-len(id)-len(wire) {
			return nil, ErrMUState
		}
		size += 6 + len(id) + len(wire)
	}
	body := make([]byte, 0, size)
	base := encodeMUReservation(r)
	body = append(body, []byte("MUP1")...)
	body = append(body, base[4:]...)
	for _, at := range []time.Time{c.now, c.authorityUntil, c.watermark} {
		body = binary.BigEndian.AppendUint64(body, uint64(at.Unix()))
	}
	body = binary.BigEndian.AppendUint16(body, uint16(len(c.ids)))
	keys := make([]string, 0, len(c.ids))
	for id := range c.ids {
		keys = append(keys, id)
	}
	sort.Strings(keys)
	for _, id := range keys {
		wire := c.ids[id]
		body = binary.BigEndian.AppendUint16(body, uint16(len(id)))
		body = append(body, id...)
		body = binary.BigEndian.AppendUint32(body, uint32(len(wire)))
		body = append(body, wire...)
	}
	return body, nil
}

func decodeMUVerification(body []byte) (muVerificationCommit, bool) {
	var c muVerificationCommit
	if len(body) < 159 || len(body) > journalBodyLimit(journalReservation) || string(body[:4]) != "MUP1" {
		return c, false
	}
	times := []*time.Time{&c.now, &c.authorityUntil, &c.watermark}
	for i, p := range times {
		n := binary.BigEndian.Uint64(body[133+i*8:])
		if n == 0 || n > 253402300799 {
			return c, false
		}
		*p = time.Unix(int64(n), 0).UTC()
	}
	n := int(binary.BigEndian.Uint16(body[157:159]))
	if n == 0 || n > linuxVerificationMaxIDBindings {
		return c, false
	}
	// Count/byte checks precede each allocation. The physical frame is bounded
	// by the existing parser before this typed decoder is entered.
	c.ids = make(map[string][]byte, n)
	off := 159
	previous := ""
	for i := 0; i < n; i++ {
		if len(body)-off < 2 {
			return muVerificationCommit{}, false
		}
		length := int(binary.BigEndian.Uint16(body[off:]))
		off += 2
		if length > len(body)-off {
			return muVerificationCommit{}, false
		}
		id := string(body[off : off+length])
		off += length
		if !record.IsContentID(id) || id <= previous || len(body)-off < 4 {
			return muVerificationCommit{}, false
		}
		previous = id
		length = int(binary.BigEndian.Uint32(body[off:]))
		off += 4
		if length == 0 || length > 65536 || length > len(body)-off {
			return muVerificationCommit{}, false
		}
		c.ids[id] = bytes.Clone(body[off : off+length])
		off += length
	}
	if off != len(body) || !linuxVerificationJournalFits(c.ids) {
		return muVerificationCommit{}, false
	}
	c.complete = true
	return c, true
}

func (s *muState) replayVerifiedReservation(f *journalFrame) error {
	c, ok := decodeMUVerification(f.body)
	if !ok || !s.validVerificationCommit(c) {
		return ErrMUState
	}
	// Reuse the exact existing nonce/allowance lifecycle validator before
	// applying time/history. Both changes come from this single sealed frame.
	base := bytes.Clone(f.body[:133])
	copy(base[:4], "MUR1")
	if err := s.replay(&journalFrame{kind: journalReservation, link: f.link, body: base}); err != nil {
		return err
	}
	s.verificationNow, s.verificationWatermark, s.verificationIDs = c.now, c.watermark, c.ids
	return nil
}

func (s *muState) reserveVerified(u MUUse, c muVerificationCommit) (uint64, error) {
	finalDeadline := time.Now().Add(linuxProviderFinalLimit)
	if c.deadline.IsZero() || !time.Now().Before(c.deadline) {
		return 0, ErrMUState
	}
	if c.deadline.Before(finalDeadline) {
		finalDeadline = c.deadline
	}
	if s.failed || !s.validVerificationCommit(c) || u.GrantID == "" || u.Nonce == "" || u.Requester == "" || u.Audience != s.binding.Audience || u.GrantRoot != s.binding.GrantRoot || u.RequestHash == [32]byte{} {
		return 0, ErrMUState
	}
	if c.publisherKey == "" || c.authorAttestation == "" {
		return 0, ErrMUState
	}
	for _, rev := range []MURevocation{{Kind: "record", ID: u.GrantID}, {Kind: "key", ID: u.Requester}, {Kind: "record", ID: c.authorAttestation}, {Kind: "key", ID: c.publisherKey}} {
		if s.revoked[rev] {
			return 0, ErrMURevoked
		}
	}
	grant, ok := c.ids[u.GrantID]
	if !ok {
		return 0, ErrMUState
	}
	if id, err := muRecordID(grant, "grant/1"); err != nil || id != u.GrantID {
		return 0, ErrMUState
	}
	grantBody, err := muParseEnvelope(grant)
	if err != nil {
		return 0, ErrMUState
	}
	gb, _ := grantBody["body"].(map[string]any)
	caveats, _ := gb["caveats"].(map[string]any)
	use := strOr(caveats["use"])
	if gb["issuer"] != u.GrantRoot || (use != "once" && use != "until_expiry") || u.Once != (use == "once") || muOnceScope(grant, use) != nil {
		return 0, ErrMUState
	}
	// A held once right wins even for a fresh-nonce refill attempt. Nothing
	// below can release it, including a different exact request or an UNKNOWN.
	if u.Once && s.allowances[muAllowanceKey(u)] != nil {
		return 0, ErrMUUseHeld
	}
	matched := false
	for id, wire := range c.ids {
		if sha256.Sum256(wire) == u.RequestHash {
			actual, err := muRecordID(wire, "message/1")
			b, bodyErr := muMessageBody(wire)
			target, _ := b["target"].(map[string]any)
			if err == nil && bodyErr == nil && actual == id && b["author"] == u.Requester && b["author_attestation"] == c.authorAttestation && b["nonce"] == u.Nonce && b["aud"] == u.Audience &&
				b["action"] == u.Action && target["kind"] == u.TargetKind && target["id"] == u.TargetID {
				matched = true
			}
		}
	}
	if !matched {
		return 0, ErrMUState
	}
	r := &muReservation{nonce: muNonceKey(u), grantID: sha256.Sum256([]byte(u.GrantID)), requestHash: u.RequestHash, once: u.Once, sequence: s.link.sequence}
	if u.Once {
		r.allowance = muAllowanceKey(u)
		if s.allowances[r.allowance] != nil {
			return 0, ErrMUUseHeld
		}
	}
	if s.nonces[r.nonce] != nil {
		return 0, ErrMUNonceHeld
	}
	if len(s.reservations) >= muMaxReservations {
		return 0, ErrMUState
	}
	body, err := encodeMUVerification(r, c)
	if err != nil {
		return 0, err
	}
	if !time.Now().Before(finalDeadline) {
		return 0, ErrMUState
	}
	link := s.link
	if err := s.append(journalReservation, body); err != nil {
		return 0, err
	}
	if err := s.replayVerifiedReservation(&journalFrame{kind: journalReservation, link: link, body: body}); err != nil {
		s.failed = true
		return 0, err
	}
	// Synchronous file writes/fsync cannot be forcibly cancelled by this API.
	// A late completed append remains held and refuses before any effect. This
	// fences dispatch; it is not a qualified 100 ms storage-return guarantee.
	if !time.Now().Before(finalDeadline) {
		return 0, ErrMUState
	}
	return r.sequence, nil
}
