package keyvault

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	_ "embed"
	"encoding/binary"
	"encoding/hex"
	"strings"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil/base58"
	"golang.org/x/crypto/pbkdf2"
	"golang.org/x/crypto/ripemd160"
)

// The English BIP-39 list is public, fixed source data, not runtime seed data.
//
//go:embed recoverydata/english.txt
var recoveryEnglish string

var recoveryWords = strings.Fields(recoveryEnglish)

func recoveryRefuse(code string) error {
	return &Refusal{Code: "recovery_" + code, Message: "Recovery operation refused: " + code, Hint: "preserve the offline backup and existing items; no weaker custody fallback is available"}
}

// mnemonicIndices supports official BIP-39 vector lengths. The CLI separately
// admits exactly 24 words. All secret representations here are owned buffers.
func mnemonicIndices(entropy []byte) ([]uint16, error) {
	if len(entropy) < 16 || len(entropy) > 32 || len(entropy)%4 != 0 || len(recoveryWords) != 2048 {
		return nil, recoveryRefuse("invalid_mnemonic")
	}
	sum := sha256.Sum256(entropy)
	defer clear(sum[:])
	bits := len(entropy)*8 + len(entropy)/4
	indices := make([]uint16, bits/11)
	for bit := 0; bit < bits; bit++ {
		var v byte
		if bit < len(entropy)*8 {
			v = (entropy[bit/8] >> (7 - bit%8)) & 1
		} else {
			v = (sum[0] >> (7 - (bit - len(entropy)*8))) & 1
		}
		indices[bit/11] = indices[bit/11]<<1 | uint16(v)
	}
	return indices, nil
}

func mnemonicPhrase(indices []uint16) ([]byte, error) {
	phrase := make([]byte, 0, len(indices)*9)
	for i, index := range indices {
		if int(index) >= len(recoveryWords) {
			clear(phrase)
			return nil, recoveryRefuse("invalid_mnemonic")
		}
		if i != 0 {
			phrase = append(phrase, ' ')
		}
		phrase = append(phrase, recoveryWords[index]...)
	}
	return phrase, nil
}

func parseMnemonic(phrase []byte) ([]uint16, error) {
	if len(phrase) == 0 || len(phrase) > 512 {
		return nil, recoveryRefuse("invalid_mnemonic")
	}
	// ASCII English with canonical single spaces is already NFKD. No hidden
	// passphrase or Unicode normalization ambiguity enters this closed interface.
	count := bytes.Count(phrase, []byte{' '}) + 1
	if count < 12 || count > 24 || count%3 != 0 {
		return nil, recoveryRefuse("invalid_mnemonic")
	}
	indices := make([]uint16, count)
	ok := false
	defer func() {
		if !ok {
			clear(indices)
		}
	}()
	start, pos := 0, 0
	for end := 0; end <= len(phrase); end++ {
		if end != len(phrase) && phrase[end] != ' ' {
			continue
		}
		found := false
		for index, word := range recoveryWords {
			if bytes.Equal(phrase[start:end], []byte(word)) {
				indices[pos] = uint16(index)
				found = true
				break
			}
		}
		if !found {
			return nil, recoveryRefuse("invalid_mnemonic")
		}
		pos++
		start = end + 1
	}
	bits := count * 11
	entropyBits := bits * 32 / 33
	entropy := make([]byte, entropyBits/8)
	defer clear(entropy)
	for bit := 0; bit < entropyBits; bit++ {
		v := byte((indices[bit/11] >> (10 - bit%11)) & 1)
		entropy[bit/8] |= v << (7 - bit%8)
	}
	expected, err := mnemonicIndices(entropy)
	defer clear(expected)
	if err != nil {
		return nil, err
	}
	for i := range indices {
		if indices[i] != expected[i] {
			return nil, recoveryRefuse("invalid_checksum")
		}
	}
	ok = true
	return indices, nil
}

type recoveryNode struct {
	key, chain [32]byte
	depth      byte
	parent     [4]byte
	child      uint32
}

func (n *recoveryNode) clear() { clear(n.key[:]); clear(n.chain[:]) }

func (n *recoveryNode) public() ([]byte, error) {
	key, err := nostrPrivate(n.key[:])
	if err != nil {
		return nil, recoveryRefuse("invalid_derivation")
	}
	defer key.Zero()
	return key.PubKey().SerializeCompressed(), nil
}

func masterRecoveryNode(seed []byte) (recoveryNode, error) {
	if len(seed) < 16 || len(seed) > 64 {
		return recoveryNode{}, recoveryRefuse("invalid_derivation")
	}
	h := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, _ = h.Write(seed)
	material := h.Sum(nil)
	defer clear(material)
	var n recoveryNode
	defer n.clear()
	copy(n.key[:], material[:32])
	copy(n.chain[:], material[32:])
	key, err := nostrPrivate(n.key[:])
	if err != nil {
		n.clear()
		return recoveryNode{}, recoveryRefuse("invalid_derivation")
	}
	key.Zero()
	return n, nil
}

func (n *recoveryNode) derive(index uint32) (recoveryNode, error) {
	var out recoveryNode
	defer out.clear()
	if n.depth == 255 {
		return out, recoveryRefuse("invalid_derivation")
	}
	pub, err := n.public()
	if err != nil {
		return out, err
	}
	var input [37]byte
	defer clear(input[:])
	if index&0x80000000 != 0 {
		copy(input[1:33], n.key[:])
	} else {
		copy(input[:33], pub)
	}
	binary.BigEndian.PutUint32(input[33:], index)
	h := hmac.New(sha512.New, n.chain[:])
	_, _ = h.Write(input[:])
	material := h.Sum(nil)
	defer clear(material)
	out.key, err = recoveryChildKey(n.key[:], material[:32])
	if err != nil {
		return recoveryNode{}, err
	}
	copy(out.chain[:], material[32:])
	out.depth = n.depth + 1
	out.child = index

	fp := recoveryHash160(pub)
	copy(out.parent[:], fp[:4])
	return out, nil
}

func (n *recoveryNode) path(path []uint32) (recoveryNode, error) {
	current := *n
	defer current.clear()
	for _, index := range path {
		next, err := current.derive(index)
		current.clear()
		if err != nil {
			return recoveryNode{}, err
		}
		current = next
		next.clear()
	}
	return current, nil
}

func (n *recoveryNode) xpub() (string, error) {
	pub, err := n.public()
	if err != nil {
		return "", err
	}
	var raw [82]byte
	copy(raw[:4], []byte{4, 0x88, 0xb2, 0x1e})
	raw[4] = n.depth
	copy(raw[5:9], n.parent[:])
	binary.BigEndian.PutUint32(raw[9:13], n.child)
	copy(raw[13:45], n.chain[:])
	copy(raw[45:78], pub)
	first := sha256.Sum256(raw[:78])
	second := sha256.Sum256(first[:])
	copy(raw[78:], second[:4])
	return base58.Encode(raw[:]), nil
}

type recoveryMaterial struct {
	nostr                         [32]byte
	namecoin                      recoveryNode
	publicKey, npub, xpub, origin string
}

func (m *recoveryMaterial) clear() { clear(m.nostr[:]); m.namecoin.clear() }

func deriveRecovery(phrase []byte) (recoveryMaterial, error) {
	var out recoveryMaterial
	defer out.clear()
	indices, err := parseMnemonic(phrase)
	if err != nil {
		return out, err
	}
	defer clear(indices)
	// English words, ASCII spaces and the empty passphrase are already NFKD.
	seed := pbkdf2.Key(phrase, []byte("mnemonic"), 2048, 64, sha512.New)
	defer clear(seed)
	root, err := masterRecoveryNode(seed)
	if err != nil {
		return out, err
	}
	defer root.clear()
	pub, err := root.public()
	if err != nil {
		return out, err
	}
	fp := recoveryHash160(pub)
	out.origin = "[" + hex.EncodeToString(fp[:4]) + "/84h/7h/0h]"
	leaf, err := root.path([]uint32{0x8000002c, 0x800004d5, 0x80000000, 0, 0})
	if err != nil {
		return out, err
	}
	defer leaf.clear()
	copy(out.nostr[:], leaf.key[:])
	key, err := nostrPrivate(leaf.key[:])
	if err != nil {
		out.clear()
		return recoveryMaterial{}, err
	}
	public := schnorr.SerializePubKey(key.PubKey())
	key.Zero()
	out.publicKey = hex.EncodeToString(public)
	out.npub, _ = NostrNPub(public)
	out.namecoin, err = root.path([]uint32{0x80000054, 0x80000007, 0x80000000})
	if err != nil {
		out.clear()
		return recoveryMaterial{}, err
	}
	out.xpub, err = out.namecoin.xpub()
	if err != nil {
		out.clear()
		return recoveryMaterial{}, err
	}
	return out, nil
}

func recoveryHash160(public []byte) []byte {
	sum := sha256.Sum256(public)
	h := ripemd160.New()
	_, _ = h.Write(sum[:])
	return h.Sum(nil)
}

func recoveryChildKey(parent, tweakBytes []byte) ([32]byte, error) {
	var output [32]byte
	defer clear(output[:])
	var tweak, key btcec.ModNScalar
	defer tweak.Zero()
	defer key.Zero()
	if len(parent) != 32 || len(tweakBytes) != 32 || tweak.SetByteSlice(tweakBytes) || key.SetByteSlice(parent) || key.IsZero() {
		return output, recoveryRefuse("invalid_derivation")
	}
	key.Add(&tweak)
	if key.IsZero() {
		return output, recoveryRefuse("invalid_derivation")
	}
	key.PutBytes(&output)
	return output, nil
}
