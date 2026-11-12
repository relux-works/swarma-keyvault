// Package namecoinjournal implements bounded internal journal representations
// and gated public-file persistence. It performs no Keychain, biometric or
// signing operation. File checks do not authenticate history: independently
// qualified protected storage, account correspondence and ordering are required.
package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

var (
	ErrInvalid = errors.New("journal_invalid")
	ErrUnknown = errors.New("journal_unknown")
	ErrReplay  = errors.New("journal_input_fenced")
	ErrMissing = errors.New("journal_missing")
)

// Binding uses existing public purpose identities; no caller-selected path is
// derived from a request ID. Policy is an exact trusted local revision string.
type Binding struct {
	Group     string
	Account   string
	PublicPin [32]byte
	Policy    string
}

func identity(s, purpose string) bool {
	parts := strings.Split(s, "/")
	if len(parts) != 2 || len(parts[0]) < 1 || len(parts[0]) > 40 {
		return false
	}
	for _, c := range []byte(parts[0]) {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	prefix := purpose + "@"
	if !strings.HasPrefix(parts[1], prefix) {
		return false
	}
	version := strings.TrimPrefix(parts[1], prefix)
	n, err := strconv.ParseUint(version, 10, 31)
	return err == nil && n > 0 && strconv.FormatUint(n, 10) == version
}
func (b Binding) valid() bool {
	if !identity(b.Group, "recovery") || !identity(b.Account, "namecoin") || len(b.Policy) < 1 || len(b.Policy) > 128 {
		return false
	}
	for _, c := range []byte(b.Policy) {
		if c < 33 || c > 126 {
			return false
		}
	}
	return true
}
func lp(dst []byte, value []byte) []byte {
	dst = binary.BigEndian.AppendUint32(dst, uint32(len(value)))
	return append(dst, value...)
}
func bindingBytes(b Binding) []byte {
	raw := lp(nil, []byte(b.Group))
	raw = lp(raw, []byte(b.Account))
	raw = append(raw, b.PublicPin[:]...)
	return lp(raw, []byte(b.Policy))
}

// Locator is a public Keychain account/directory identifier, not authority.
func Locator(b Binding) (string, error) {
	if !b.valid() {
		return "", ErrInvalid
	}
	raw := lp(nil, []byte(b.Group))
	raw = lp(raw, []byte(b.Account))
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}
func genesis(b Binding) [32]byte {
	raw := append([]byte("keyvault/namecoin-journal-genesis/1\x00"), bindingBytes(b)...)
	return sha256.Sum256(raw)
}

type decoder struct {
	raw []byte
	pos int
	bad bool
}

func (d *decoder) take(n int) []byte {
	if n < 0 || d.pos > len(d.raw)-n {
		d.bad = true
		return nil
	}
	p := d.raw[d.pos : d.pos+n]
	d.pos += n
	return p
}
func (d *decoder) u32() uint32 {
	p := d.take(4)
	if d.bad {
		return 0
	}
	return binary.BigEndian.Uint32(p)
}
func (d *decoder) u64() uint64 {
	p := d.take(8)
	if d.bad {
		return 0
	}
	return binary.BigEndian.Uint64(p)
}
func (d *decoder) blob(max int) []byte {
	n := d.u32()
	if n > uint32(max) {
		d.bad = true
		return nil
	}
	return d.take(int(n))
}
func (d *decoder) binding() Binding {
	b := Binding{Group: string(d.blob(80)), Account: string(d.blob(80))}
	copy(b.PublicPin[:], d.take(32))
	b.Policy = string(d.blob(128))
	if !b.valid() {
		d.bad = true
	}
	return b
}
func (d *decoder) end() bool { return !d.bad && d.pos == len(d.raw) }
func (d *decoder) magic(s string) {
	if !bytes.Equal(d.take(len(s)), []byte(s)) {
		d.bad = true
	}
}
