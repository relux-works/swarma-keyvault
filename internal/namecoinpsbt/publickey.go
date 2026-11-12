package namecoinpsbt

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
	"golang.org/x/crypto/ripemd160"
)

type accountPublic struct {
	serialized  [78]byte
	point       [33]byte
	chain       [32]byte
	fingerprint [4]byte
}

func parseAccount(pin namecoinwire.AccountPin) (accountPublic, error) {
	var result accountPublic
	raw := base58.Decode(pin.AccountXPub)
	if len(raw) != 82 || base58.Encode(raw) != pin.AccountXPub {
		return result, failure(namecoinwire.AccountMismatch)
	}
	h := doubleHash(raw[:78])
	if !bytes.Equal(h[:4], raw[78:]) || !bytes.Equal(raw[:4], []byte{4, 136, 178, 30}) || raw[4] != 3 || binary.BigEndian.Uint32(raw[9:13]) != 0x80000000 || pin.AccountPath != "m/84h/7h/0h" {
		return result, failure(namecoinwire.AccountMismatch)
	}
	if raw[45] != 2 && raw[45] != 3 {
		return result, failure(namecoinwire.AccountMismatch)
	}
	if _, err := btcec.ParsePubKey(raw[45:78]); err != nil {
		return result, failure(namecoinwire.AccountMismatch)
	}
	copy(result.serialized[:], raw[:78])
	copy(result.chain[:], raw[13:45])
	copy(result.point[:], raw[45:78])
	copy(result.fingerprint[:], decodeHex(pin.MasterFingerprint))
	return result, nil
}

// Public-only CKDpub rejects invalid children rather than silently moving to
// another path. No private account or child scalar enters this function.
func derivePublic(account accountPublic, branch, index uint32) ([33]byte, error) {
	if branch > 1 || index >= 0x80000000 {
		return [33]byte{}, failure(namecoinwire.PathRefused)
	}
	point, chain := account.point, account.chain
	for _, child := range []uint32{branch, index} {
		mac := hmac.New(sha512.New, chain[:])
		_, _ = mac.Write(point[:])
		var childBytes [4]byte
		binary.BigEndian.PutUint32(childBytes[:], child)
		_, _ = mac.Write(childBytes[:])
		sum := mac.Sum(nil)
		var err error
		point, err = addPublicTweak(point, sum[:32])
		if err != nil {
			return [33]byte{}, err
		}
		copy(chain[:], sum[32:])
	}
	return point, nil
}

func addPublicTweak(point [33]byte, raw []byte) ([33]byte, error) {
	var delta btcec.ModNScalar
	if len(raw) != 32 || delta.SetByteSlice(raw) {
		return [33]byte{}, failure(namecoinwire.PathRefused)
	}
	// BIP32 permits I_L=0 for a child; only >=n and infinity refuse.
	pub, err := btcec.ParsePubKey(point[:])
	if err != nil {
		return [33]byte{}, failure(namecoinwire.AccountMismatch)
	}
	var parent, tweak, combined btcec.JacobianPoint
	pub.AsJacobian(&parent)
	btcec.ScalarBaseMultNonConst(&delta, &tweak)
	btcec.AddNonConst(&parent, &tweak, &combined)
	if combined.Z.IsZero() {
		return [33]byte{}, failure(namecoinwire.PathRefused)
	}
	combined.ToAffine()
	var out [33]byte
	copy(out[:], btcec.NewPublicKey(&combined.X, &combined.Y).SerializeCompressed())
	return out, nil
}
func hash160(raw []byte) [20]byte {
	h := sha256.Sum256(raw)
	r := ripemd160.New()
	_, _ = r.Write(h[:])
	var out [20]byte
	copy(out[:], r.Sum(nil))
	return out
}
func (a accountPublic) checkOrigin(o origin) error {
	if a.fingerprint != o.fingerprint {
		return failure(namecoinwire.AccountMismatch)
	}
	expected, err := derivePublic(a, o.branch, o.index)
	if err != nil {
		return err
	}
	if expected != o.key {
		return failure(namecoinwire.AccountMismatch)
	}
	return nil
}
func (a accountPublic) checkGlobal(p packet) error {
	if p.globalXpub == nil {
		return nil
	}
	expected := append([]byte(nil), a.fingerprint[:]...)
	for _, child := range []uint32{0x80000054, 0x80000007, 0x80000000} {
		expected = binary.LittleEndian.AppendUint32(expected, child)
	}
	if !bytes.Equal(p.globalXpub, a.serialized[:]) || !bytes.Equal(p.globalOrigin, expected) {
		return failure(namecoinwire.AccountMismatch)
	}
	return nil
}
