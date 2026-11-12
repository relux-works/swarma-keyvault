package namecoinjournal

import (
	"crypto/sha256"
	"strings"
)

// Sidecar links public selected-item facts without rewriting either existing
// purpose, its opaque paired ciphertext, or its metadata. It stores hashes only;
// no grant purpose/derivation/presence policy is defined here.
type Sidecar struct {
	Binding         Binding
	NostrAccount    string
	GroupID         [16]byte
	NostrPublicPin  [32]byte
	MetadataHash    [32]byte
	PairedValueHash [32]byte
}

func (s Sidecar) valid() bool {
	return s.Binding.valid() && identity(s.NostrAccount, "nostr") &&
		strings.SplitN(s.Binding.Group, "/", 2)[0] == strings.SplitN(s.NostrAccount, "/", 2)[0]
}
func EncodeSidecar(s Sidecar) ([]byte, error) {
	if !s.valid() {
		return nil, ErrInvalid
	}
	raw := append([]byte("KVNS1\x00"), bindingBytes(s.Binding)...)
	raw = lp(raw, []byte(s.NostrAccount))
	raw = append(raw, s.GroupID[:]...)
	raw = append(raw, s.NostrPublicPin[:]...)
	raw = append(raw, s.MetadataHash[:]...)
	raw = append(raw, s.PairedValueHash[:]...)
	return raw, nil
}
func DecodeSidecar(raw []byte, expected Sidecar) (Sidecar, error) {
	if len(raw) == 0 {
		return Sidecar{}, ErrMissing
	}
	if len(raw) > 640 || !expected.valid() {
		return Sidecar{}, ErrUnknown
	}
	d := decoder{raw: raw}
	d.magic("KVNS1\x00")
	s := Sidecar{Binding: d.binding(), NostrAccount: string(d.blob(80))}
	copy(s.GroupID[:], d.take(16))
	copy(s.NostrPublicPin[:], d.take(32))
	copy(s.MetadataHash[:], d.take(32))
	copy(s.PairedValueHash[:], d.take(32))
	if !d.end() || !s.valid() || s != expected {
		return Sidecar{}, ErrUnknown
	}
	return s, nil
}

// VerifyPairedBytes compares exact bytes, never decodes/re-encodes the pair.
// Hash equality alone is not selected-item identity or authority; the native
// adoption must additionally verify the exact item reference and ACL structure.
func (s Sidecar) VerifyPairedBytes(metadata, pairedValue []byte) error {
	if !s.valid() || sha256.Sum256(metadata) != s.MetadataHash || sha256.Sum256(pairedValue) != s.PairedValueHash {
		return ErrUnknown
	}
	return nil
}
