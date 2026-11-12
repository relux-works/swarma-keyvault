package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const maxAttemptBytes = 12 << 20

var attemptDomain = []byte("KVND1\x00")

// PublicAttempt owns the immutable public inputs needed to reconstruct one
// journal attempt. It is not consent, protected history or permission to sign.
// The descriptor hash becomes authoritative only when bound into authenticated
// DISPATCHED history by the private engine.
type PublicAttempt struct {
	candidate          Candidate
	selected           Selection
	descriptor, review []byte
	id                 namecoinjournal.AttemptID
}

// PrepareAttempt applies the actual clock and independently selected authority.
// Recovery uses DecodeAttempt instead: an expired request must remain readable
// without silently granting permission for another signature.
func PrepareAttempt(request, pin []byte, selected Selection, now time.Time) (PublicAttempt, error) {
	a, err := makeAttempt(request, pin, selected)
	if err != nil {
		return PublicAttempt{}, err
	}
	if err = a.candidate.Admit(a.selected, now); err != nil {
		return PublicAttempt{}, err
	}
	return a, nil
}

func makeAttempt(request, pin []byte, selected Selection) (PublicAttempt, error) {
	var a PublicAttempt
	if len(pin) == 0 || len(pin) > 32768 {
		return a, failure(namecoinwire.AccountMismatch)
	}
	snapshot, err := namecoinwire.Decode(request)
	if err != nil {
		return a, err
	}
	c, err := Inspect(snapshot, pin)
	if err != nil {
		return a, err
	}
	plan := snapshot.Plan()
	if selected.Network != plan.Network || selected.Genesis != plan.Genesis || selected.Group != plan.Group || selected.Account != plan.Account || selected.AccountPinSHA256 != plan.AccountPinSHA256 || selected.Policy != plan.Policy {
		return a, failure(namecoinwire.PolicyRefused)
	}
	selected.RevealValuesPin = bytes.Clone(selected.RevealValuesPin)
	context, err := c.ReviewContext(selected)
	if err != nil {
		return a, err
	}
	review, err := snapshot.ReviewFrame(context)
	if err != nil {
		return a, err
	}
	// Canonicalize only the outer request. The once-decoded manifest and its
	// committed exact UTF-8 bytes remain unchanged inside the request string.
	canonical, err := json.Marshal(snapshot.Request())
	if err != nil || len(canonical) > namecoinwire.MaxRequestBytes {
		return a, failure(namecoinwire.InvalidRequest)
	}
	selection, err := json.Marshal(selected)
	if err != nil || len(selection) > 2<<20 {
		return a, failure(namecoinwire.InvalidRequest)
	}
	raw := bytes.Clone(attemptDomain)
	for _, field := range [][]byte{canonical, pin, selection} {
		raw = binary.BigEndian.AppendUint32(raw, uint32(len(field)))
		raw = append(raw, field...)
	}
	if len(raw) > maxAttemptBytes {
		return a, failure(namecoinwire.InvalidRequest)
	}
	r := snapshot.Request()
	id := attemptIdentity(r.PlanSHA256, r.Slot)
	return PublicAttempt{candidate: c, selected: selected, descriptor: raw, review: review, id: id}, nil
}

// DecodeAttempt requires the exact canonical descriptor representation and
// rechecks the public transaction/account/frame bindings. A syntactically valid
// descriptor alone proves neither its source nor completed journal membership.
func DecodeAttempt(raw []byte) (PublicAttempt, error) {
	var empty PublicAttempt
	if len(raw) > maxAttemptBytes || !bytes.HasPrefix(raw, attemptDomain) {
		return empty, failure(namecoinwire.InvalidRequest)
	}
	rest := raw[len(attemptDomain):]
	var fields [3][]byte
	limits := [3]uint32{namecoinwire.MaxRequestBytes, 32768, 2 << 20}
	for i := range fields {
		if len(rest) < 4 {
			return empty, failure(namecoinwire.InvalidRequest)
		}
		size := binary.BigEndian.Uint32(rest[:4])
		rest = rest[4:]
		if size == 0 || size > limits[i] || uint64(size) > uint64(len(rest)) {
			return empty, failure(namecoinwire.InvalidRequest)
		}
		fields[i], rest = rest[:size], rest[size:]
	}
	if len(rest) != 0 {
		return empty, failure(namecoinwire.InvalidRequest)
	}
	var selected Selection
	decoder := json.NewDecoder(bytes.NewReader(fields[2]))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&selected) != nil {
		return empty, failure(namecoinwire.InvalidRequest)
	}
	a, err := makeAttempt(fields[0], fields[1], selected)
	if err != nil {
		return empty, err
	}
	// Also rejects unknown/duplicate selection keys, alternative base64, trailing
	// JSON and noncanonical encodings without accepting two interpretations.
	if !bytes.Equal(a.descriptor, raw) {
		return empty, failure(namecoinwire.InvalidRequest)
	}
	return a, nil
}

func (a PublicAttempt) Descriptor() []byte            { return bytes.Clone(a.descriptor) }
func (a PublicAttempt) Commitment() [32]byte          { return sha256.Sum256(a.descriptor) }
func (a PublicAttempt) ID() namecoinjournal.AttemptID { return a.id }
func (a PublicAttempt) ReviewFrame() []byte           { return bytes.Clone(a.review) }
func (a PublicAttempt) ReviewDigest() [32]byte        { return sha256.Sum256(a.review) }
func (a PublicAttempt) Candidate() Candidate          { return a.candidate }
func (a PublicAttempt) Selection() Selection {
	s := a.selected
	s.RevealValuesPin = bytes.Clone(s.RevealValuesPin)
	return s
}
func (a PublicAttempt) Outpoints() []namecoinjournal.Outpoint {
	points := make([]namecoinjournal.Outpoint, len(a.candidate.packet.tx.inputs))
	for i, in := range a.candidate.packet.tx.inputs {
		points[i] = namecoinjournal.Outpoint{Transaction: in.hash, Index: in.index}
	}
	return points
}

func attemptIdentity(planHash, slot string) namecoinjournal.AttemptID {
	raw, _ := hex.DecodeString(planHash)
	identity := append([]byte("keyvault/namecoin-attempt/1\x00"), raw...)
	identity = append(identity, slot[0])
	return namecoinjournal.AttemptID(sha256.Sum256(identity))
}
