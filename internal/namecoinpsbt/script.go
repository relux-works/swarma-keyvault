package namecoinpsbt

import (
	"bytes"
	"encoding/binary"

	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type scriptFacts struct {
	operation                        string
	name, opening, value, commitment []byte
	program                          [20]byte
}

// push reproduces Core's byte-vector CScript insertion, including OP_0 for
// an empty vector; alternate PUSHDATA encodings are not canonical prefixes.
func push(dst, data []byte) []byte {
	switch {
	case len(data) < 76:
		dst = append(dst, byte(len(data)))
	case len(data) <= 255:
		dst = append(dst, 76, byte(len(data)))
	case len(data) <= 65535:
		dst = append(dst, 77)
		dst = binary.LittleEndian.AppendUint16(dst, uint16(len(data)))
	default:
		dst = append(dst, 78)
		dst = binary.LittleEndian.AppendUint32(dst, uint32(len(data)))
	}
	return append(dst, data...)
}
func scriptPush(c *cursor, limit int) []byte {
	b := c.take(1)
	if c.bad {
		return nil
	}
	var n uint64
	switch {
	case b[0] < 76:
		n = uint64(b[0])
	case b[0] == 76:
		r := c.take(1)
		if c.bad {
			return nil
		}
		n = uint64(r[0])
		if n < 76 {
			c.bad = true
		}
	case b[0] == 77:
		r := c.take(2)
		if c.bad {
			return nil
		}
		n = uint64(binary.LittleEndian.Uint16(r))
		if n <= 255 {
			c.bad = true
		}
	default:
		c.bad = true
	}
	if n > uint64(limit) {
		c.bad = true
	}
	if c.bad {
		return nil
	}
	return c.take(int(n))
}
func splitScript(raw []byte) (scriptFacts, error) {
	var f scriptFacts
	c := cursor{raw: raw}
	refuse := func() (scriptFacts, error) { return scriptFacts{}, failure(namecoinwire.UnsupportedScript) }
	if len(raw) == 0 {
		return refuse()
	}
	switch raw[0] {
	case 0: // native witness program, no name prefix
	case 0x51:
		c.offset = 1
		f.operation = "name_new"
		f.commitment = scriptPush(&c, 20)
		if c.bad || len(f.commitment) != 20 || !bytes.Equal(c.take(1), []byte{0x6d}) {
			return refuse()
		}
	case 0x52:
		c.offset = 1
		f.operation = "name_firstupdate"
		f.name = scriptPush(&c, 255)
		f.opening = scriptPush(&c, 20)
		f.value = scriptPush(&c, 520)
		if c.bad || len(f.name) == 0 || len(f.opening) != 20 || !bytes.Equal(c.take(2), []byte{0x6d, 0x6d}) {
			return refuse()
		}
	default:
		return refuse()
	}
	remaining := c.take(len(raw) - c.offset)
	if c.bad || len(remaining) != 22 || remaining[0] != 0 || remaining[1] != 20 {
		return refuse()
	}
	copy(f.program[:], remaining[2:])
	return f, nil
}
func nameScript(r namecoinwire.Registration, reveal bool, program [20]byte) []byte {
	var raw []byte
	if reveal {
		raw = []byte{0x52}
		raw = push(raw, decodeHex(r.NameHex))
		raw = push(raw, decodeHex(r.RandHex))
		raw = push(raw, decodeHex(r.ValueHex))
		raw = append(raw, 0x6d, 0x6d)
	} else {
		commit := hash160(append(decodeHex(r.RandHex), decodeHex(r.NameHex)...))
		raw = push([]byte{0x51}, commit[:])
		raw = append(raw, 0x6d)
	}
	raw = append(raw, 0, 20)
	return append(raw, program[:]...)
}
