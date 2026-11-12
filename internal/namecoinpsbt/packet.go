package namecoinpsbt

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"strconv"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type entry struct{ key, value []byte }
type section []entry
type origin struct {
	key           [33]byte
	fingerprint   [4]byte
	branch, index uint32
}

func (o origin) path() string {
	return "m/84h/7h/0h/" + strconv.FormatUint(uint64(o.branch), 10) + "/" + strconv.FormatUint(uint64(o.index), 10)
}

type packetInput struct {
	previous transaction
	prevout  output
	origin   origin
	entries  section
}
type packet struct {
	tx                       transaction
	globals                  section
	inputs                   []packetInput
	outputs                  []origin
	outputMaps               []section
	globalXpub, globalOrigin []byte
}

func readSection(c *cursor) (section, error) {
	var result section
	seen := make(map[string]bool)
	for {
		key := c.vector(1024)
		if c.bad {
			return nil, failure(namecoinwire.UnsupportedPSBT)
		}
		if len(key) == 0 {
			return result, nil
		}
		value := c.vector(namecoinwire.MaxPSBTBytes)
		if c.bad || seen[string(key)] || len(result) >= 512 {
			return nil, failure(namecoinwire.UnsupportedPSBT)
		}
		seen[string(key)] = true
		result = append(result, entry{bytes.Clone(key), bytes.Clone(value)})
	}
}
func parseOrigin(e entry, kind byte) (origin, error) {
	var o origin
	if len(e.key) != 34 || e.key[0] != kind || (e.key[1] != 2 && e.key[1] != 3) || len(e.value) != 24 {
		return o, failure(namecoinwire.PathRefused)
	}
	if _, err := btcec.ParsePubKey(e.key[1:]); err != nil {
		return o, failure(namecoinwire.PathRefused)
	}
	copy(o.key[:], e.key[1:])
	copy(o.fingerprint[:], e.value[:4])
	if binary.LittleEndian.Uint32(e.value[4:8]) != 0x80000054 || binary.LittleEndian.Uint32(e.value[8:12]) != 0x80000007 || binary.LittleEndian.Uint32(e.value[12:16]) != 0x80000000 {
		return origin{}, failure(namecoinwire.PathRefused)
	}
	o.branch = binary.LittleEndian.Uint32(e.value[16:20])
	o.index = binary.LittleEndian.Uint32(e.value[20:24])
	if o.branch > 1 || o.index >= 0x80000000 {
		return origin{}, failure(namecoinwire.PathRefused)
	}
	return o, nil
}
func parsePacket(raw []byte) (packet, error) {
	var p packet
	if len(raw) > namecoinwire.MaxPSBTBytes || !bytes.HasPrefix(raw, []byte{'p', 's', 'b', 't', 255}) {
		return p, failure(namecoinwire.UnsupportedPSBT)
	}
	c := cursor{raw: raw, offset: 5}
	globals, err := readSection(&c)
	if err != nil {
		return p, err
	}
	p.globals = globals
	var unsigned []byte
	for _, e := range globals {
		switch {
		case bytes.Equal(e.key, []byte{0}):
			unsigned = e.value
		case bytes.Equal(e.key, []byte{251}):
			if len(e.value) != 4 || binary.LittleEndian.Uint32(e.value) != 0 {
				return packet{}, failure(namecoinwire.UnsupportedPSBT)
			}
		case e.key[0] == 1 && len(e.key) == 79:
			if p.globalXpub != nil || len(e.value) != 16 {
				return packet{}, failure(namecoinwire.UnsupportedPSBT)
			}
			p.globalXpub = e.key[1:]
			p.globalOrigin = e.value
		default:
			return packet{}, failure(namecoinwire.UnsupportedPSBT)
		}
	}
	p.tx, err = parseTransaction(unsigned, false)
	if err != nil {
		return packet{}, err
	}
	if p.tx.version != 0x7100 {
		return packet{}, failure(namecoinwire.UnsupportedPSBT)
	}
	for _, v := range p.tx.inputs {
		if len(v.script) != 0 {
			return packet{}, failure(namecoinwire.UnsupportedPSBT)
		}
	}
	p.inputs = make([]packetInput, len(p.tx.inputs))
	seen := make(map[[36]byte]bool)
	for i, txin := range p.tx.inputs {
		var point [36]byte
		copy(point[:32], txin.hash[:])
		binary.LittleEndian.PutUint32(point[32:], txin.index)
		if seen[point] {
			return packet{}, failure(namecoinwire.PrevoutMismatch)
		}
		seen[point] = true
		entries, e := readSection(&c)
		if e != nil {
			return packet{}, e
		}
		v := &p.inputs[i]
		v.entries = entries
		var previous, witness []byte
		haveOrigin := false
		for _, e := range entries {
			switch {
			case bytes.Equal(e.key, []byte{0}):
				previous = e.value
			case bytes.Equal(e.key, []byte{1}):
				witness = e.value
			case bytes.Equal(e.key, []byte{3}):
				if len(e.value) != 4 || binary.LittleEndian.Uint32(e.value) != 1 {
					return packet{}, failure(namecoinwire.SighashRefused)
				}
			case e.key[0] == 6:
				if haveOrigin {
					return packet{}, failure(namecoinwire.PathRefused)
				}
				haveOrigin = true
				v.origin, err = parseOrigin(e, 6)
				if err != nil {
					return packet{}, err
				}
			default:
				return packet{}, failure(namecoinwire.UnsupportedPSBT)
			}
		}
		if previous == nil {
			return packet{}, failure(namecoinwire.UnsupportedPSBT)
		}
		if !haveOrigin {
			return packet{}, failure(namecoinwire.PathRefused)
		}
		v.previous, err = parseTransaction(previous, true)
		if err != nil {
			return packet{}, err
		}
		if v.previous.hash() != txin.hash || uint64(txin.index) >= uint64(len(v.previous.outputs)) {
			return packet{}, failure(namecoinwire.PrevoutMismatch)
		}
		v.prevout = v.previous.outputs[txin.index]
		if witness != nil {
			wc := cursor{raw: witness}
			amount := wc.u64()
			script := wc.vector(10000)
			if wc.bad || wc.offset != len(witness) || amount != v.prevout.amount || !bytes.Equal(script, v.prevout.script) {
				return packet{}, failure(namecoinwire.PrevoutMismatch)
			}
		}
	}
	p.outputs = make([]origin, len(p.tx.outputs))
	p.outputMaps = make([]section, len(p.tx.outputs))
	for i := range p.outputs {
		entries, e := readSection(&c)
		if e != nil {
			return packet{}, e
		}
		p.outputMaps[i] = entries
		if len(entries) != 1 || entries[0].key[0] != 2 {
			return packet{}, failure(namecoinwire.UnsupportedPSBT)
		}
		p.outputs[i], err = parseOrigin(entries[0], 2)
		if err != nil {
			return packet{}, err
		}
	}
	if c.bad || c.offset != len(raw) {
		return packet{}, failure(namecoinwire.UnsupportedPSBT)
	}
	return p, nil
}
func decodeHex(s string) []byte { r, _ := hex.DecodeString(s); return r }
