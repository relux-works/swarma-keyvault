package namecoinjournal

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"sync"
)

// derive uses the admitted account scalar32 || chaincode32. It is an internal
// single-block HKDF-SHA256, not a grant key/purpose or account-export operation.
func derive(material []byte, b Binding) ([32]byte, error) {
	var out [32]byte
	order := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe, 0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41}
	var zero [32]byte
	if !b.valid() || len(material) != 64 || bytes.Equal(material[:32], zero[:]) || bytes.Compare(material[:32], order) >= 0 {
		return out, ErrInvalid
	}
	saltInput := []byte("keyvault/namecoin-journal-salt/1\x00")
	saltInput = lp(saltInput, []byte(b.Group))
	saltInput = lp(saltInput, []byte(b.Account))
	saltInput = append(saltInput, b.PublicPin[:]...)
	salt := sha256.Sum256(saltInput)
	extract := hmac.New(sha256.New, salt[:])
	_, _ = extract.Write(material)
	prk := extract.Sum(nil)
	defer clear(prk)
	expand := hmac.New(sha256.New, prk)
	_, _ = expand.Write([]byte("keyvault/namecoin-journal-anchor/1\x00"))
	_, _ = expand.Write([]byte{1})
	result := expand.Sum(nil)
	copy(out[:], result)
	clear(result)
	return out, nil
}
func headToken(key [32]byte, b Binding, sequence uint64, head [32]byte) [32]byte {
	raw := append([]byte("keyvault/namecoin-journal-head/1\x00"), bindingBytes(b)...)
	raw = binary.BigEndian.AppendUint64(raw, sequence)
	raw = append(raw, head[:]...)
	mac := hmac.New(sha256.New, key[:])
	_, _ = mac.Write(raw)
	var token [32]byte
	sum := mac.Sum(nil)
	copy(token[:], sum)
	clear(sum)
	return token
}

// Anchor contains confined integrity state. Never serialize it into a journal,
// receipt, log, argv or pipe. It must remain inside the custody process and its
// qualified protected Keychain item. It is not a Keychain CAS or rollback proof.
// Use pointers; copies of an Anchor are forbidden.
type Anchor struct {
	mu             sync.Mutex
	binding        Binding
	sequence       uint64
	head           [32]byte
	key            [32]byte
	token          [32]byte
	cleared        bool
	accountMatched bool
}

// Format prevents accidental formatting of the confined key/token. It does not
// authorize logging an anchor or make an encoded protected buffer public.
func (*Anchor) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "<confined Namecoin anchor>")
}

// NewInitialization constructs only an in-memory genesis. The native owner must
// first complete separate initialization review and fresh biometry in the first
// post-review adoption sitting, then create-only protected storage/readback.
// No ordinary load/sign/reconcile path may call this on missing state.
func NewInitialization(b Binding, material []byte) (*Anchor, error) {
	key, err := derive(material, b)
	if err != nil {
		return nil, err
	}
	a := &Anchor{binding: b, key: key, head: genesis(b), accountMatched: true}
	clear(key[:])
	a.token = headToken(a.key, b, 0, a.head)
	return a, nil
}
func (a *Anchor) authentic() bool {
	if a.cleared {
		return false
	}
	expected := headToken(a.key, a.binding, a.sequence, a.head)
	return subtle.ConstantTimeCompare(expected[:], a.token[:]) == 1
}

// VerifyAccount must succeed after fresh transaction/reconciliation biometric
// unseal before any private transaction use or authenticated reconciliation.
// Stored attacker-chosen key/head/token cannot substitute for retained authority.
func (a *Anchor) VerifyAccount(material []byte) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.accountMatched = false
	expected, err := derive(material, a.binding)
	defer clear(expected[:])
	if err != nil || !a.authentic() || subtle.ConstantTimeCompare(expected[:], a.key[:]) != 1 {
		return ErrUnknown
	}
	a.accountMatched = true
	return nil
}

// Head returns a public consistency witness only; it does not disclose a token.
func (a *Anchor) Head() (uint64, [32]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.authentic() {
		return 0, [32]byte{}, ErrUnknown
	}
	return a.sequence, a.head, nil
}
func (a *Anchor) Clear() {
	if a == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	clear(a.key[:])
	clear(a.token[:])
	a.cleared = true
	a.accountMatched = false
}

// EncodeProtected returns SECRET bytes for direct same-process protected-item
// storage only. The caller must clear the buffer. No file persistence is provided.
// Existing public Binding values must come from independently trusted selection.
func (a *Anchor) EncodeProtected() ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if !a.authentic() {
		return nil, ErrUnknown
	}
	raw := append([]byte("KVNA1\x00"), bindingBytes(a.binding)...)
	raw = binary.BigEndian.AppendUint64(raw, a.sequence)
	raw = append(raw, a.head[:]...)
	raw = append(raw, a.key[:]...)
	raw = append(raw, a.token[:]...)
	return raw, nil
}

// DecodeProtected never initializes an absent anchor. Authentication with the
// stored key checks internal consistency only; VerifyAccount is still required
// after unseal to detect a recreated item with a substituted integrity authority.
func DecodeProtected(raw []byte, expected Binding) (*Anchor, error) {
	if len(raw) == 0 {
		return nil, ErrMissing
	}
	if len(raw) > 512 || !expected.valid() {
		return nil, ErrUnknown
	}
	d := decoder{raw: raw}
	d.magic("KVNA1\x00")
	b := d.binding()
	a := &Anchor{binding: b, sequence: d.u64()}
	copy(a.head[:], d.take(32))
	copy(a.key[:], d.take(32))
	copy(a.token[:], d.take(32))
	if !d.end() || b != expected || !a.authentic() || a.sequence == 0 && a.head != genesis(b) {
		a.Clear()
		return nil, ErrUnknown
	}
	return a, nil
}
