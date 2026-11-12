// Package namecoinpsbt validates the public, restricted Namecoin PSBT profile.
// Parsing is not authorization, custody, journal authentication or consent.
package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const maxMoney uint64 = 21_000_000 * 100_000_000

type input struct {
	hash     [32]byte // wire order
	index    uint32
	script   []byte
	sequence uint32
	witness  [][]byte
}
type output struct {
	amount uint64
	script []byte
}
type transaction struct {
	version  uint32
	inputs   []input
	outputs  []output
	locktime uint32
	segwit   bool
}
type cursor struct {
	raw    []byte
	offset int
	bad    bool
}

func (c *cursor) take(n int) []byte {
	if n < 0 || n > len(c.raw)-c.offset {
		c.bad = true
		return nil
	}
	r := c.raw[c.offset : c.offset+n]
	c.offset += n
	return r
}
func (c *cursor) u32() uint32 {
	r := c.take(4)
	if c.bad {
		return 0
	}
	return binary.LittleEndian.Uint32(r)
}
func (c *cursor) u64() uint64 {
	r := c.take(8)
	if c.bad {
		return 0
	}
	return binary.LittleEndian.Uint64(r)
}
func (c *cursor) compact() uint64 {
	r := c.take(1)
	if c.bad {
		return 0
	}
	v := uint64(r[0])
	switch r[0] {
	case 253:
		r = c.take(2)
		if c.bad {
			return 0
		}
		v = uint64(binary.LittleEndian.Uint16(r))
		if v < 253 {
			c.bad = true
		}
	case 254:
		v = uint64(c.u32())
		if v <= 65535 {
			c.bad = true
		}
	case 255:
		v = c.u64()
		if v <= 0xffffffff {
			c.bad = true
		}
	}
	return v
}
func (c *cursor) vector(limit int) []byte {
	n := c.compact()
	if c.bad || n > uint64(limit) {
		c.bad = true
		return nil
	}
	return c.take(int(n))
}
func compact(dst []byte, n uint64) []byte {
	switch {
	case n < 253:
		return append(dst, byte(n))
	case n <= 65535:
		dst = append(dst, 253)
		return binary.LittleEndian.AppendUint16(dst, uint16(n))
	case n <= 0xffffffff:
		dst = append(dst, 254)
		return binary.LittleEndian.AppendUint32(dst, uint32(n))
	default:
		dst = append(dst, 255)
		return binary.LittleEndian.AppendUint64(dst, n)
	}
}
func vector(dst, raw []byte) []byte { return append(compact(dst, uint64(len(raw))), raw...) }
func parseTransaction(raw []byte, allowWitness bool) (transaction, error) {
	var tx transaction
	refuse := func() (transaction, error) { return transaction{}, failure(namecoinwire.UnsupportedPSBT) }
	if len(raw) == 0 || len(raw) > namecoinwire.MaxTransactionBytes {
		return refuse()
	}
	c := cursor{raw: raw}
	tx.version = c.u32()
	count := c.compact()
	if !c.bad && count == 0 {
		flags := c.take(1)
		if !allowWitness || c.bad || flags[0] != 1 {
			return refuse()
		}
		tx.segwit = true
		count = c.compact()
	}
	if c.bad || count == 0 || count > namecoinwire.MaxInputs {
		return refuse()
	}
	tx.inputs = make([]input, int(count))
	for i := range tx.inputs {
		v := &tx.inputs[i]
		copy(v.hash[:], c.take(32))
		v.index = c.u32()
		v.script = bytes.Clone(c.vector(10000))
		v.sequence = c.u32()
		if c.bad {
			return refuse()
		}
	}
	count = c.compact()
	if c.bad || count == 0 || count > namecoinwire.MaxOutputs {
		return refuse()
	}
	tx.outputs = make([]output, int(count))
	var total uint64
	for i := range tx.outputs {
		v := &tx.outputs[i]
		v.amount = c.u64()
		v.script = bytes.Clone(c.vector(10000))
		if c.bad || v.amount > maxMoney || total > maxMoney-v.amount {
			return refuse()
		}
		total += v.amount
	}
	if tx.segwit {
		anyWitness := false
		for i := range tx.inputs {
			count = c.compact()
			if c.bad || count > 1000 {
				return refuse()
			}
			tx.inputs[i].witness = make([][]byte, int(count))
			anyWitness = anyWitness || count != 0
			for j := range tx.inputs[i].witness {
				tx.inputs[i].witness[j] = bytes.Clone(c.vector(namecoinwire.MaxTransactionBytes))
				if c.bad {
					return refuse()
				}
			}
		}
		if !anyWitness {
			return refuse()
		}
	}
	tx.locktime = c.u32()
	if c.bad || c.offset != len(raw) {
		return refuse()
	}
	return tx, nil
}
func serializeOutput(dst []byte, o output) []byte {
	return vector(binary.LittleEndian.AppendUint64(dst, o.amount), o.script)
}
func (tx transaction) serialize(witness bool) []byte {
	dst := binary.LittleEndian.AppendUint32(nil, tx.version)
	if witness && tx.segwit {
		dst = append(dst, 0, 1)
	}
	dst = compact(dst, uint64(len(tx.inputs)))
	for _, v := range tx.inputs {
		dst = append(dst, v.hash[:]...)
		dst = binary.LittleEndian.AppendUint32(dst, v.index)
		dst = vector(dst, v.script)
		dst = binary.LittleEndian.AppendUint32(dst, v.sequence)
	}
	dst = compact(dst, uint64(len(tx.outputs)))
	for _, v := range tx.outputs {
		dst = serializeOutput(dst, v)
	}
	if witness && tx.segwit {
		for _, v := range tx.inputs {
			dst = compact(dst, uint64(len(v.witness)))
			for _, w := range v.witness {
				dst = vector(dst, w)
			}
		}
	}
	return binary.LittleEndian.AppendUint32(dst, tx.locktime)
}
func doubleHash(raw []byte) [32]byte  { h := sha256.Sum256(raw); return sha256.Sum256(h[:]) }
func (tx transaction) hash() [32]byte { return doubleHash(tx.serialize(false)) }
func rpcHash(h [32]byte) string {
	for i := 0; i < 16; i++ {
		h[i], h[31-i] = h[31-i], h[i]
	}
	return hex.EncodeToString(h[:])
}
func failure(code namecoinwire.Code) error { return namecoinwire.NewFailure(code, false) }

// signatureHash implements only BIP143 SIGHASH_ALL for a native P2WPKH
// prevout. Name prefixes are checked separately; only its witness program is
// used in scriptCode, while hashOutputs commits to every complete name script.
func (tx transaction) signatureHash(index int, prev output, program []byte) ([32]byte, error) {
	if index < 0 || index >= len(tx.inputs) || len(program) != 20 {
		return [32]byte{}, failure(namecoinwire.UnsupportedScript)
	}
	var outpoints, sequences, outputs []byte
	for _, v := range tx.inputs {
		outpoints = append(outpoints, v.hash[:]...)
		outpoints = binary.LittleEndian.AppendUint32(outpoints, v.index)
		sequences = binary.LittleEndian.AppendUint32(sequences, v.sequence)
	}
	for _, v := range tx.outputs {
		outputs = serializeOutput(outputs, v)
	}
	hp, hs, ho := doubleHash(outpoints), doubleHash(sequences), doubleHash(outputs)
	pre := binary.LittleEndian.AppendUint32(nil, tx.version)
	pre = append(pre, hp[:]...)
	pre = append(pre, hs[:]...)
	v := tx.inputs[index]
	pre = append(pre, v.hash[:]...)
	pre = binary.LittleEndian.AppendUint32(pre, v.index)
	script := append([]byte{0x76, 0xa9, 0x14}, program...)
	script = append(script, 0x88, 0xac)
	pre = vector(pre, script)
	pre = binary.LittleEndian.AppendUint64(pre, prev.amount)
	pre = binary.LittleEndian.AppendUint32(pre, v.sequence)
	pre = append(pre, ho[:]...)
	pre = binary.LittleEndian.AppendUint32(pre, tx.locktime)
	pre = binary.LittleEndian.AppendUint32(pre, 1)
	return doubleHash(pre), nil
}
