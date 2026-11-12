package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
	"testing"
)

// Exact paired bytes and BOTH purpose identities are preserved. Neutral opaque
// fixture bytes exercise linkage, not real Keychain metadata/ACL adoption.
func TestLinkedSidecarPreservesPairBytes(t *testing.T) {
	metadata := []byte("opaque paired metadata fixture\x00\xff")
	paired := []byte("opaque existing Nostr and Namecoin ciphertext fixture\x00\xfe")
	beforeMetadata, beforePaired := bytes.Clone(metadata), bytes.Clone(paired)
	s := Sidecar{Binding: fixtureBinding(), NostrAccount: "fixture/nostr@2", GroupID: [16]byte{1}, NostrPublicPin: [32]byte{8}, MetadataHash: sha256.Sum256(metadata), PairedValueHash: sha256.Sum256(paired)}
	raw, e := EncodeSidecar(s)
	if e != nil {
		t.Fatal(e)
	}
	decoded, e := DecodeSidecar(raw, s)
	if e != nil {
		t.Fatal(e)
	}
	if e = decoded.VerifyPairedBytes(metadata, paired); e != nil {
		t.Fatal(e)
	}
	if !bytes.Equal(metadata, beforeMetadata) || !bytes.Equal(paired, beforePaired) {
		t.Fatal("existing pair mutated")
	}
	for i := range raw {
		altered := bytes.Clone(raw)
		altered[i] ^= 1
		if _, e = DecodeSidecar(altered, s); e == nil {
			t.Fatalf("sidecar mismatch accepted %d", i)
		}
	}
	for i := 0; i < len(raw); i++ {
		if _, e = DecodeSidecar(raw[:i], s); e == nil {
			t.Fatal("truncated sidecar")
		}
	}
	if _, e = DecodeSidecar(append(bytes.Clone(raw), 0), s); e == nil {
		t.Fatal("trailing sidecar")
	}
	paired[0] ^= 1
	if e = s.VerifyPairedBytes(metadata, paired); e == nil {
		t.Fatal("changed ciphertext")
	}
	paired[0] ^= 1
	metadata[0] ^= 1
	if e = s.VerifyPairedBytes(metadata, paired); e == nil {
		t.Fatal("changed metadata")
	}
	for _, change := range []func(*Sidecar){func(p *Sidecar) { p.NostrAccount = "other/nostr@2" }, func(p *Sidecar) { p.Binding.Account = "other/namecoin@1" }, func(p *Sidecar) { p.Binding.PublicPin[0] ^= 1 }, func(p *Sidecar) { p.NostrPublicPin[0] ^= 1 }, func(p *Sidecar) { p.GroupID[0] ^= 1 }} {
		wrong := s
		change(&wrong)
		if _, e = DecodeSidecar(raw, wrong); e == nil {
			t.Fatal("changed purpose/group pin")
		}
	}
}
