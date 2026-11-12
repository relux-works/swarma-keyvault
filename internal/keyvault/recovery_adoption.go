package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"path/filepath"
	"unicode"
	"unicode/utf8"
)

// Adoption is an internal finite owner-sitting primitive, not a public route.
// No plan, path, hash or software test supplies owner consent or native admission.
const recoveryAdoptionService = "works.relux.mac-keyvault.nostr.v1"
const recoveryAdoptionMaxFrame = 1024 * 1024

var errRecoveryAdoptionInvalid = errors.New("recovery adoption selection refused")
var errRecoveryAdoptionNative = errors.New("recovery adoption native operation refused")
var errRecoveryAdoptionUnknown = errors.New("recovery adoption outcome UNKNOWN; do not retry")

type recoveryAdoptionCode struct {
	path string
	hash []byte
}

func recoveryAdoptionIdentity(path string, hash []byte) (recoveryAdoptionCode, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path || len(path) > 4095 || path == "/" || !utf8.ValidString(path) || (len(hash) != 20 && len(hash) != 32) {
		return recoveryAdoptionCode{}, errRecoveryAdoptionInvalid
	}
	for _, r := range path {
		if unicode.IsControl(r) {
			return recoveryAdoptionCode{}, errRecoveryAdoptionInvalid
		}
	}
	return recoveryAdoptionCode{path: path, hash: bytes.Clone(hash)}, nil
}

// All byte slices are privately owned. They contain only the sealed pair,
// metadata and public selection; no account/key/plaintext is accepted here.
type recoveryAdoptionSelection struct {
	account                      string
	metadata, sealed, persistent []byte
	old, next                    recoveryAdoptionCode
}

func (*recoveryAdoptionSelection) String() string   { return "<recovery adoption selection>" }
func (*recoveryAdoptionSelection) GoString() string { return "<recovery adoption selection>" }

func newRecoveryAdoptionSelection(account string, metadata, sealed, persistent []byte, oldPath string, oldHash []byte, newPath string, newHash []byte) (*recoveryAdoptionSelection, error) {
	r, err := parseRecoveryRecord(metadata)
	if err != nil || r.Account() != account || len(persistent) == 0 || len(persistent) > 4096 {
		return nil, errRecoveryAdoptionInvalid
	}
	if _, err := parseRecoveryCiphertext(sealed, r); err != nil {
		return nil, errRecoveryAdoptionInvalid
	}
	old, err := recoveryAdoptionIdentity(oldPath, oldHash)
	if err != nil {
		return nil, err
	}
	next, err := recoveryAdoptionIdentity(newPath, newHash)
	if err != nil || old.path == next.path || bytes.Equal(old.hash, next.hash) {
		return nil, errRecoveryAdoptionInvalid
	}
	return &recoveryAdoptionSelection{account: account, metadata: bytes.Clone(metadata), sealed: bytes.Clone(sealed), persistent: bytes.Clone(persistent), old: old, next: next}, nil
}

func (s *recoveryAdoptionSelection) clear() {
	if s == nil {
		return
	}
	clear(s.metadata)
	clear(s.sealed)
	clear(s.persistent)
	clear(s.old.hash)
	clear(s.next.hash)
	s.metadata = nil
	s.sealed = nil
	s.persistent = nil
}

// The frame is public evidence from the finite native inspector. It is NOT an
// authenticated assertion when supplied by a caller or a software fixture.
type recoveryAdoptionNativeFrame struct {
	oldApp, newApp, attributes, beforeACL, afterACL []byte
}

type recoveryAdoptionReader struct{ rest []byte }

func (r *recoveryAdoptionReader) u32() (uint32, bool) {
	if len(r.rest) < 4 {
		return 0, false
	}
	v := binary.BigEndian.Uint32(r.rest[:4])
	r.rest = r.rest[4:]
	return v, true
}
func (r *recoveryAdoptionReader) field() ([]byte, bool) {
	n, ok := r.u32()
	if !ok || uint64(n) > uint64(len(r.rest)) {
		return nil, false
	}
	v := r.rest[:int(n)]
	r.rest = r.rest[int(n):]
	return v, true
}
func recoveryAdoptionField(out []byte, v []byte) []byte {
	out = binary.BigEndian.AppendUint32(out, uint32(len(v)))
	return append(out, v...)
}

func parseRecoveryAdoptionNativeFrame(raw []byte) (recoveryAdoptionNativeFrame, error) {
	var v recoveryAdoptionNativeFrame
	if len(raw) < 5 || len(raw) > recoveryAdoptionMaxFrame || !bytes.Equal(raw[:5], []byte("KVAD1")) {
		return v, errRecoveryAdoptionInvalid
	}
	r := recoveryAdoptionReader{raw[5:]}
	for _, target := range []*[]byte{&v.oldApp, &v.newApp, &v.attributes, &v.beforeACL, &v.afterACL} {
		b, ok := r.field()
		if !ok || len(b) == 0 {
			return recoveryAdoptionNativeFrame{}, errRecoveryAdoptionInvalid
		}
		*target = bytes.Clone(b)
	}
	if len(r.rest) != 0 || bytes.Equal(v.oldApp, v.newApp) || bytes.Equal(v.beforeACL, v.afterACL) {
		return recoveryAdoptionNativeFrame{}, errRecoveryAdoptionInvalid
	}
	if !recoveryAdoptionAttributes(v.attributes) || !recoveryAdoptionACLTransition(v.beforeACL, v.afterACL, v.oldApp, v.newApp) {
		return recoveryAdoptionNativeFrame{}, errRecoveryAdoptionInvalid
	}
	return v, nil
}

func recoveryAdoptionAttributes(raw []byte) bool {
	if len(raw) < 9 || !bytes.Equal(raw[:5], []byte("KVAT1")) {
		return false
	}
	r := recoveryAdoptionReader{raw[5:]}
	n, ok := r.u32()
	if !ok || n == 0 || n > 128 {
		return false
	}
	var last uint32
	for i := uint32(0); i < n; i++ {
		tag, a := r.u32()
		_, b := r.u32()
		_, c := r.field()
		if !a || !b || !c || (i != 0 && tag <= last) {
			return false
		}
		last = tag
	}
	return len(r.rest) == 0
}

func recoveryAdoptionAttributesMatch(raw []byte, s *recoveryAdoptionSelection) bool {
	if !recoveryAdoptionAttributes(raw) {
		return false
	}
	r := recoveryAdoptionReader{raw[5:]}
	count, _ := r.u32()
	want := map[uint32][]byte{
		0x73766365: []byte(recoveryAdoptionService), // svce
		0x61636374: []byte(s.account),               // acct
		0x6c61626c: []byte(s.account),               // labl
		0x69636d74: s.metadata,                      // icmt
	}
	for i := uint32(0); i < count; i++ {
		tag, _ := r.u32()
		_, _ = r.u32()
		value, _ := r.field()
		if expected, ok := want[tag]; ok {
			if !bytes.Equal(value, expected) {
				return false
			}
			delete(want, tag)
		}
	}
	return len(want) == 0
}

type recoveryAdoptionACLEntry struct {
	decrypt                 bool
	preserved, applications []byte
}

func recoveryAdoptionACL(raw []byte) ([]byte, []recoveryAdoptionACLEntry, bool) {
	if len(raw) < 21 || !bytes.Equal(raw[:5], []byte("KVAC1")) {
		return nil, nil, false
	}
	owner := raw[5:17]
	r := recoveryAdoptionReader{raw[17:]}
	n, ok := r.u32()
	if !ok || n == 0 || n > 64 {
		return nil, nil, false
	}
	entries := make([]recoveryAdoptionACLEntry, 0, n)
	for i := uint32(0); i < n; i++ {
		kind, a := r.u32()
		state, b := r.field()
		apps, c := r.field()
		if !a || !b || !c || kind > 1 || len(state) == 0 {
			return nil, nil, false
		}
		// Native preserved state includes complete authorization strings,
		// nullable description and full CSSM prompt version/flags.
		p := recoveryAdoptionReader{state}
		auths, d := p.u32()
		if !d || auths == 0 || auths > 32 {
			return nil, nil, false
		}
		for j := uint32(0); j < auths; j++ {
			s, good := p.field()
			if !good || len(s) == 0 || !utf8.Valid(s) {
				return nil, nil, false
			}
		}
		nullable, d := p.u32()
		desc, e := p.field()
		version, f := p.u32()
		flags, g := p.u32()
		if !d || !e || !f || !g || nullable > 1 || (nullable == 0 && len(desc) != 0) || !utf8.Valid(desc) || version > 65535 || flags > 65535 || len(p.rest) != 0 {
			return nil, nil, false
		}
		appsReader := recoveryAdoptionReader{apps}
		present, d := appsReader.u32()
		count, e := appsReader.u32()
		if !d || !e || present > 1 || count > 64 || (present == 0 && count != 0) {
			return nil, nil, false
		}
		for j := uint32(0); j < count; j++ {
			data, good := appsReader.field()
			if !good || len(data) == 0 {
				return nil, nil, false
			}
		}
		if len(appsReader.rest) != 0 || (kind == 1 && (auths != 1 || present != 1 || count != 1)) {
			return nil, nil, false
		}
		entries = append(entries, recoveryAdoptionACLEntry{kind == 1, state, apps})
	}
	rawState, ok := r.field()
	if !ok || len(rawState) < 5 || !bytes.Equal(rawState[:5], []byte("KVAR1")) || len(r.rest) != 0 {
		return nil, nil, false
	}
	// This native-only invariant includes raw owner, delegation, validity,
	// handles/tags and unrelated subject trees, not process pointers.
	preservedOwner := append(bytes.Clone(owner), rawState...)
	return preservedOwner, entries, true
}

func recoveryAdoptionSoleApplication(app []byte) []byte {
	v := binary.BigEndian.AppendUint32(nil, 1)
	v = binary.BigEndian.AppendUint32(v, 1)
	return recoveryAdoptionField(v, app)
}
func recoveryAdoptionACLTransition(before, after, old, next []byte) bool {
	ownerA, a, okA := recoveryAdoptionACL(before)
	ownerB, b, okB := recoveryAdoptionACL(after)
	if !okA || !okB || !bytes.Equal(ownerA, ownerB) || len(a) != len(b) {
		return false
	}
	count := 0
	for i := range a {
		if a[i].decrypt != b[i].decrypt || !bytes.Equal(a[i].preserved, b[i].preserved) {
			return false
		}
		if a[i].decrypt {
			count++
			if !bytes.Equal(a[i].applications, recoveryAdoptionSoleApplication(old)) || !bytes.Equal(b[i].applications, recoveryAdoptionSoleApplication(next)) {
				return false
			}
		} else if !bytes.Equal(a[i].applications, b[i].applications) {
			return false
		}
	}
	return count != 0
}

// This immutable public document is a review INPUT, never a consent boolean.
// Its native frame includes every preserved attribute/ACL field and the sole
// app substitutions. An owning typed UI must render it completely before apply.
type recoveryAdoptionPlan struct {
	selection *recoveryAdoptionSelection
	native    []byte
	review    []byte
	digest    [32]byte
}

func (*recoveryAdoptionPlan) String() string   { return "<recovery adoption plan>" }
func (*recoveryAdoptionPlan) GoString() string { return "<recovery adoption plan>" }

func newRecoveryAdoptionPlan(s *recoveryAdoptionSelection, native []byte) (*recoveryAdoptionPlan, error) {
	if s == nil {
		return nil, errRecoveryAdoptionInvalid
	}
	copySelection, err := newRecoveryAdoptionSelection(s.account, s.metadata, s.sealed, s.persistent, s.old.path, s.old.hash, s.next.path, s.next.hash)
	if err != nil {
		return nil, err
	}
	parsed, err := parseRecoveryAdoptionNativeFrame(native)
	if err != nil || !recoveryAdoptionAttributesMatch(parsed.attributes, s) {
		copySelection.clear()
		return nil, errRecoveryAdoptionInvalid
	}
	v := []byte("works.relux.mac-keyvault.recovery-adoption-review/1\x00")
	for _, part := range [][]byte{[]byte(recoveryAdoptionService), []byte(s.account), s.metadata, s.persistent, []byte(s.old.path), s.old.hash, []byte(s.next.path), s.next.hash} {
		v = recoveryAdoptionField(v, part)
	}
	sealedHash := sha256.Sum256(s.sealed)
	v = recoveryAdoptionField(v, sealedHash[:])
	v = binary.BigEndian.AppendUint32(v, uint32(len(s.sealed)))
	// Both retained purpose envelopes are individually bound for complete review.
	r, _ := parseRecoveryRecord(s.metadata)
	envelopes, _ := parseRecoveryCiphertext(s.sealed, r)
	for _, purpose := range []struct {
		account  string
		envelope recoveryEnvelope
	}{
		{r.PurposeAccount(r.Nostr), envelopes.Nostr}, {r.PurposeAccount(r.Namecoin), envelopes.Namecoin},
	} {
		v = recoveryAdoptionField(v, []byte(purpose.account))
		hash := sha256.Sum256(purpose.envelope.Ciphertext)
		v = recoveryAdoptionField(v, hash[:])
		v = binary.BigEndian.AppendUint32(v, uint32(len(purpose.envelope.Ciphertext)))
		hash = sha256.Sum256(purpose.envelope.EnclaveBlob)
		v = recoveryAdoptionField(v, hash[:])
		v = binary.BigEndian.AppendUint32(v, uint32(len(purpose.envelope.EnclaveBlob)))
	}
	v = recoveryAdoptionField(v, native)
	return &recoveryAdoptionPlan{selection: copySelection, native: bytes.Clone(native), review: v, digest: sha256.Sum256(v)}, nil
}
func (p *recoveryAdoptionPlan) reviewDocument() ([]byte, string) {
	return bytes.Clone(p.review), hex.EncodeToString(p.digest[:])
}
func (p *recoveryAdoptionPlan) clear() {
	if p == nil {
		return
	}
	p.selection.clear()
	clear(p.native)
	clear(p.review)
	p.native = nil
	p.review = nil
	p.digest = [32]byte{}
}

func recoveryAdoptionResult(status int, attempted bool) error {
	if status == 0 && attempted {
		return nil
	}
	if attempted || status == 2 {
		return errRecoveryAdoptionUnknown
	}
	return errRecoveryAdoptionNative
}
