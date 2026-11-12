package namecoinpsbt

import (
	"bytes"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/ecdsa"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

// Adding an admitted partial-signature entry must not invalidate an original
// PSBT at its4MiB input limit. The extra bound covers128 maximum-size entries.
const MaxSignedPSBTBytes = namecoinwire.MaxSignedPSBTBytes

// VerifySignatures checks public strict-DER/low-S/ALL signatures independently
// against this immutable candidate. It performs no private signing operation.
func (c Candidate) VerifySignatures(signatures [][]byte) error {
	if len(c.digests) == 0 || len(signatures) != len(c.digests) {
		return failure(namecoinwire.SighashRefused)
	}
	for i, raw := range signatures {
		if len(raw) < 9 || len(raw) > 72 || raw[len(raw)-1] != 1 {
			return failure(namecoinwire.SighashRefused)
		}
		der := raw[:len(raw)-1]
		sig, err := ecdsa.ParseDERSignature(der)
		if err != nil || !bytes.Equal(sig.Serialize(), der) {
			return failure(namecoinwire.SighashRefused)
		}
		pub, err := btcec.ParsePubKey(c.packet.inputs[i].origin.key[:])
		if err != nil || !sig.Verify(c.digests[i][:], pub) {
			return failure(namecoinwire.SighashRefused)
		}
	}
	return nil
}
func appendSection(dst []byte, entries section) []byte {
	for _, e := range entries {
		dst = vector(dst, e.key)
		dst = vector(dst, e.value)
	}
	return append(dst, 0)
}

// Assemble accepts only already independently verified public signatures. It
// preserves the unsigned transaction/maps, adds one partial signature per input,
// and returns a public finalized witness transaction for exact size checking.
func (c Candidate) Assemble(signatures [][]byte) ([]byte, []byte, error) {
	if err := c.VerifySignatures(signatures); err != nil {
		return nil, nil, err
	}
	raw := appendSection([]byte{'p', 's', 'b', 't', 255}, c.packet.globals)
	tx := c.packet.tx
	tx.inputs = append([]input(nil), tx.inputs...)
	tx.segwit = true
	for i, v := range c.packet.inputs {
		entries := append(section(nil), v.entries...)
		key := append([]byte{2}, v.origin.key[:]...)
		entries = append(entries, entry{key, signatures[i]})
		raw = appendSection(raw, entries)
		tx.inputs[i].witness = [][]byte{bytes.Clone(signatures[i]), bytes.Clone(v.origin.key[:])}
	}
	for _, entries := range c.packet.outputMaps {
		raw = appendSection(raw, entries)
	}
	return raw, tx.serialize(true), nil
}
func sameSection(a, b section) bool {
	if len(a) != len(b) {
		return false
	}
	lookup := make(map[string][]byte, len(a))
	for _, e := range a {
		lookup[string(e.key)] = e.value
	}
	for _, e := range b {
		v, ok := lookup[string(e.key)]
		if !ok || !bytes.Equal(v, e.value) {
			return false
		}
	}
	return true
}

// VerifySignedPSBT permits map reordering but requires every original map entry
// and exactly one correct partial signature per owned input. Final scripts,
// extra signatures, unknown keys and changes to original fields refuse.
func (c Candidate) VerifySignedPSBT(raw []byte) ([][]byte, error) {
	if len(c.digests) == 0 || len(raw) > MaxSignedPSBTBytes || !bytes.HasPrefix(raw, []byte{'p', 's', 'b', 't', 255}) {
		return nil, failure(namecoinwire.UnsupportedPSBT)
	}
	cur := cursor{raw: raw, offset: 5}
	globals, err := readSection(&cur)
	if err != nil || !sameSection(globals, c.packet.globals) {
		return nil, failure(namecoinwire.UnsupportedPSBT)
	}
	signatures := make([][]byte, len(c.packet.inputs))
	for i, v := range c.packet.inputs {
		entries, err := readSection(&cur)
		if err != nil {
			return nil, err
		}
		var original section
		for _, e := range entries {
			if len(e.key) > 0 && e.key[0] == 2 {
				if signatures[i] != nil || len(e.key) != 34 || !bytes.Equal(e.key[1:], v.origin.key[:]) {
					return nil, failure(namecoinwire.SighashRefused)
				}
				signatures[i] = bytes.Clone(e.value)
			} else {
				original = append(original, e)
			}
		}
		if !sameSection(original, v.entries) {
			return nil, failure(namecoinwire.UnsupportedPSBT)
		}
	}
	for _, expected := range c.packet.outputMaps {
		actual, err := readSection(&cur)
		if err != nil || !sameSection(actual, expected) {
			return nil, failure(namecoinwire.UnsupportedPSBT)
		}
	}
	if cur.bad || cur.offset != len(raw) {
		return nil, failure(namecoinwire.UnsupportedPSBT)
	}
	if err := c.VerifySignatures(signatures); err != nil {
		return nil, err
	}
	return signatures, nil
}
