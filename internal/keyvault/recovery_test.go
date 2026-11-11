package keyvault

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcutil/base58"
)

const recoveryFixturePhrase = "what bleak badge arrange retreat wolf trade produce cricket blur garlic valid proud rude strong choose busy staff weather area salt hollow arm fade"

type recoveryFakeStore struct {
	groups          []RecoveryRecord
	keys            []NostrRecord
	data            map[string][]byte
	stores, deletes int
	fail            bool
}

func (f *recoveryFakeStore) Create(NostrRecord) (NostrRecord, error) {
	return NostrRecord{}, errors.New("unused")
}
func (f *recoveryFakeStore) Sign(NostrRecord, []byte) ([]byte, error) {
	return nil, errors.New("unused")
}
func (f *recoveryFakeStore) List() ([]NostrRecord, error) {
	r := append([]NostrRecord{}, f.keys...)
	for _, g := range f.groups {
		r = append(r, g.NostrRecord())
	}
	return r, nil
}
func (f *recoveryFakeStore) RecoveryList() ([]RecoveryRecord, error) {
	return append([]RecoveryRecord{}, f.groups...), nil
}
func (f *recoveryFakeStore) RecoveryStore(r RecoveryRecord, data []byte) error {
	if f.fail {
		return &RecoveryNotAppliedError{Err: recoveryRefuse("store_refused")}
	}
	if f.data == nil {
		f.data = map[string][]byte{}
	}
	f.data[r.Account()] = bytes.Clone(data)
	f.groups = append(f.groups, r)
	f.stores++
	return nil
}
func (f *recoveryFakeStore) RecoveryDelete(r RecoveryRecord) error {
	if f.fail {
		return &RecoveryNotAppliedError{Err: recoveryRefuse("delete_refused")}
	}
	f.deletes++
	for i, g := range f.groups {
		if g.Account() == r.Account() {
			f.groups = append(f.groups[:i], f.groups[i+1:]...)
			delete(f.data, r.Account())
			return nil
		}
	}
	return ErrNotFound
}
func (f *recoveryFakeStore) NostrDelete(NostrRecord) error { f.deletes++; return nil }

type recoveryFakeTerminal struct {
	identityConfirmation int
	identityRefuse       bool
	plans                []RecoveryPlan
	phrase               []byte
	confirmation, read   int
	refuse               bool
	seen                 [][]byte
}

func (t *recoveryFakeTerminal) ConfirmIdentities(p RecoveryPlan) error {
	t.identityConfirmation++
	t.plans = append(t.plans, p)
	if t.identityRefuse {
		return errors.New("identity mismatch")
	}
	return nil
}

func (t *recoveryFakeTerminal) ConfirmMnemonic(words [][]byte) error {
	t.confirmation++
	t.seen = words
	if t.refuse {
		return errors.New("cancel")
	}
	return nil
}
func (t *recoveryFakeTerminal) ReadMnemonic() ([]byte, error) {
	t.read++
	if t.refuse {
		return nil, io.EOF
	}
	return bytes.Clone(t.phrase), nil
}

type recoveryFakeHelper struct {
	keys        []*ecdh.PrivateKey
	calls       int
	wrongPolicy bool
	failAt      int
}

func (h *recoveryFakeHelper) CreateWrap(purpose string) (recoveryWrap, error) {
	h.calls++
	if h.failAt == h.calls {
		return recoveryWrap{}, recoveryRefuse("helper_refused")
	}
	var raw [32]byte
	raw[31] = byte(h.calls)
	key, err := ecdh.P256().NewPrivateKey(raw[:])
	if err != nil {
		return recoveryWrap{}, err
	}
	h.keys = append(h.keys, key)
	point := key.PublicKey().Bytes()
	fp := sha256.Sum256(point)
	policy := "none"
	refused := false
	if purpose == "namecoin" {
		policy = "biometry-any"
		refused = true
	}
	if h.wrongPolicy && purpose == "namecoin" {
		policy = "user-presence"
	}
	return recoveryWrap{Blob: []byte{1, byte(h.calls)}, Point: point, Fingerprint: hex.EncodeToString(fp[:]), Policy: policy, SilentRefused: refused}, nil
}
func (h *recoveryFakeHelper) UnwrapNostr(e recoveryEnvelope) ([]byte, error) {
	return recoveryTestOpen(h.keys[0], e.Ciphertext)
}

// Test-only receiver follows the published wire, rather than calling the
// production seal path in reverse. Hardware conformance is a separate sitting.
func recoveryTestOpen(key *ecdh.PrivateKey, wire []byte) ([]byte, error) {
	if len(wire) < 81 {
		return nil, errors.New("short")
	}
	peer, err := ecdh.P256().NewPublicKey(wire[:65])
	if err != nil {
		return nil, err
	}
	z, err := key.ECDH(peer)
	if err != nil {
		return nil, err
	}
	defer clear(z)
	h := sha256.New()
	_, _ = h.Write(z)
	_, _ = h.Write([]byte{0, 0, 0, 1})
	_, _ = h.Write(wire[:65])
	k := h.Sum(nil)
	defer clear(k)
	b, err := aes.NewCipher(k[:16])
	if err != nil {
		return nil, err
	}
	g, err := cipher.NewGCMWithNonceSize(b, 16)
	if err != nil {
		return nil, err
	}
	return g.Open(nil, k[16:], wire[65:], nil)
}

func recoveryTestManager(t *testing.T) (*RecoveryManager, *recoveryFakeStore, *recoveryFakeHelper) {
	f := &recoveryFakeStore{}
	h := &recoveryFakeHelper{}
	root := t.TempDir()
	m := NewRecoveryManager(f, FileLock{Path: root + "/recovery.lock", BootstrapDir: root})
	m.helper = h
	m.now = func() time.Time { return time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC) }
	m.random = bytes.NewReader(make([]byte, 4096))
	return m, f, h
}

func recoveryTestRequest() RecoveryRequest {
	return RecoveryRequest{Service: "test", Version: 1, NostrVersion: 2, NamecoinVersion: 1}
}

func recoveryTestRestore(t *testing.T, m *RecoveryManager) RecoveryRecord {
	t.Helper()
	material, err := deriveRecovery([]byte(recoveryFixturePhrase))
	if err != nil {
		t.Fatal(err)
	}
	defer material.clear()
	q := recoveryTestRequest()
	q.ExpectedNPub = material.npub
	q.ExpectedXPub = material.xpub
	q.ExpectedOrigin = material.origin
	r, err := m.Create(q, &recoveryFakeTerminal{phrase: []byte(recoveryFixturePhrase)}, true)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func recoveryCode(t *testing.T, err error, want string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Code != "recovery_"+want {
		t.Fatalf("wanted recovery_%s, got %v", want, err)
	}
}

// One successful restore proves the fixed role/path/pin binding and atomic
// ciphertext-only write in the fake store; wrong key, tag and role swaps fail.
func TestRecoveryAtomicPairAndBinding(t *testing.T) {
	m, f, h := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	if f.stores != 1 || len(f.groups) != 1 || len(f.data) != 1 || h.calls != 2 {
		t.Fatal("not one paired write")
	}
	encoded := f.data[r.Account()]
	if bytes.Contains(encoded, []byte(recoveryFixturePhrase)) || bytes.Contains(encoded, []byte("c15d739894c81a2f")) {
		t.Fatal("private text persisted")
	}
	c, err := parseRecoveryCiphertext(encoded, r)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := h.UnwrapNostr(c.Nostr)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	secret, err := recoveryNostrPlain(r, plain)
	if err != nil {
		t.Fatal(err)
	}
	digest := make([]byte, 32)
	sig, err := signNostrSecret(r.NostrRecord(), bytes.Clone(secret), digest)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := hex.DecodeString(r.Nostr.PublicKey)
	if VerifyNostr(public, digest, sig) != nil {
		t.Fatal("restored key signature mismatch")
	}
	if _, err := recoveryTestOpen(h.keys[1], c.Nostr.Ciphertext); err == nil {
		t.Fatal("other purpose key decrypted Nostr")
	}
	corrupt := bytes.Clone(c.Nostr.Ciphertext)
	corrupt[len(corrupt)-1] ^= 1
	if _, err := recoveryTestOpen(h.keys[0], corrupt); err == nil {
		t.Fatal("bad tag accepted")
	}
	nameplain, err := recoveryTestOpen(h.keys[1], c.Namecoin.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(nameplain)
	if len(nameplain) != 100 {
		t.Fatal("wrong node payload")
	}
	if _, err := recoveryNostrPlain(r, nameplain); err == nil {
		t.Fatal("account node routed into Nostr")
	}
	swapped := r
	swapped.GroupID = strings.Repeat("1", 32)
	_, err = recoveryNostrPlain(swapped, plain)
	recoveryCode(t, err, "binding_mismatch")
	swapped = r
	swapped.Nostr.Version++
	_, err = recoveryNostrPlain(swapped, plain)
	recoveryCode(t, err, "binding_mismatch")
	_, err = recoveryNostrPlain(r, plain[:67])
	recoveryCode(t, err, "invalid_plaintext")
}

// Every pre-store refusal is paired with the valid restore above. Pins reject
// another valid mnemonic, not just a bad checksum, before hardware or storage.
func TestRecoveryRefusalsLeaveNoPartialPair(t *testing.T) {
	for _, name := range []string{"cancel", "checksum", "valid-other-phrase", "12-words", "missing-pins", "malformed-npub", "malformed-xpub", "malformed-origin", "wrong-origin", "helper-second-fails", "passcode-fallback", "store-refused"} {
		t.Run(name, func(t *testing.T) {
			m, f, h := recoveryTestManager(t)
			q := recoveryTestRequest()
			v, err := deriveRecovery([]byte(recoveryFixturePhrase))
			if err != nil {
				t.Fatal(err)
			}
			defer v.clear()
			q.ExpectedNPub = v.npub
			q.ExpectedXPub = v.xpub
			q.ExpectedOrigin = v.origin
			terminal := &recoveryFakeTerminal{phrase: []byte(recoveryFixturePhrase)}
			want := "public_pin_mismatch"
			switch name {
			case "cancel":
				terminal.refuse = true
				want = "terminal_refused"
			case "checksum":
				terminal.phrase = []byte(strings.Repeat("abandon ", 23) + "abandon")
				want = "invalid_checksum"
			case "valid-other-phrase":
				indices, _ := mnemonicIndices(make([]byte, 32))
				terminal.phrase, _ = mnemonicPhrase(indices)
			case "12-words":
				terminal.phrase = []byte("leader monkey parrot ring guide accident before fence cannon height naive bean")
				want = "requires_24_words"
			case "missing-pins":
				q.ExpectedNPub = ""
				want = "public_pins_required"
			case "malformed-npub":
				q.ExpectedNPub = strings.ToUpper(q.ExpectedNPub)
				want = "invalid_public_pins"
			case "malformed-xpub":
				q.ExpectedXPub = q.ExpectedXPub[:len(q.ExpectedXPub)-1] + "0"
				want = "invalid_public_pins"
			case "malformed-origin":
				q.ExpectedOrigin = "[00000000/84h/7h/1h]"
				want = "invalid_public_pins"
			case "wrong-origin":
				q.ExpectedOrigin = "[00000000/84h/7h/0h]"
			case "helper-second-fails":
				h.failAt = 2
				want = "helper_refused"
			case "passcode-fallback":
				h.wrongPolicy = true
				want = "wrapping_policy_refused"
			case "store-refused":
				f.fail = true
				want = "store_refused"
			}
			_, err = m.Create(q, terminal, true)
			recoveryCode(t, err, want)
			if (want == "invalid_public_pins" || want == "public_pins_required") && (terminal.identityConfirmation != 0 || terminal.read != 0) {
				t.Fatal("malformed public pins reached the terminal")
			}
			if f.stores != 0 || len(f.groups) != 0 || len(f.data) != 0 || f.deletes != 0 {
				t.Fatal("refusal changed persistent state")
			}
			if name != "helper-second-fails" && name != "passcode-fallback" && name != "store-refused" && h.calls != 0 {
				t.Fatal("hardware used before confirmation/pins")
			}
		})
	}
}

// Duplicate account/child and unsafe legacy cleanup refuse without redisplay,
// helper creation or deletion; exact public group removal succeeds separately.
func TestRecoveryDuplicateAndExactDeletion(t *testing.T) {
	m, f, h := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	terminal := &recoveryFakeTerminal{}
	_, err := m.Create(recoveryTestRequest(), terminal, false)
	recoveryCode(t, err, "duplicate")
	if terminal.confirmation != 0 || h.calls != 2 || f.stores != 1 {
		t.Fatal("duplicate reached secrets")
	}
	err = recoveryTestDelete(m, r.Service, r.Version, strings.Repeat("1", 32))
	recoveryCode(t, err, "public_pin_mismatch")
	if f.deletes != 0 || len(f.groups) != 1 {
		t.Fatal("wrong pin deleted")
	}
	n := NewNostrManager(f, FileLock{Path: t.TempDir() + "/recovery.lock"})
	err = n.Delete(r.Service, "nostr", r.Nostr.Version, r.Nostr.NPub)
	nostrCode(t, err, "paired_group_requires_group_delete")
	f.fail = true
	err = recoveryTestDelete(m, r.Service, r.Version, r.GroupID)
	recoveryCode(t, err, "delete_refused")
	if f.deletes != 0 || len(f.groups) != 1 {
		t.Fatal("refused delete changed state")
	}
	f.fail = false
	if err := recoveryTestDelete(m, r.Service, r.Version, r.GroupID); err != nil {
		t.Fatal(err)
	}
	if f.deletes != 1 || len(f.groups) != 0 || len(f.data) != 0 {
		t.Fatal("exact group not removed")
	}
}

// Generated words and transient phrase buffers are cleared after the terminal
// has confirmed them. Failed confirmation does not create either hardware key.
func TestRecoveryGenerateConfirmationAndRandomFailure(t *testing.T) {
	m, f, h := recoveryTestManager(t)
	terminal := &recoveryFakeTerminal{}
	r, err := m.Create(recoveryTestRequest(), terminal, false)
	if err != nil {
		t.Fatal(err)
	}
	if terminal.confirmation != 1 || f.stores != 1 || validateRecoveryRecord(r) != nil {
		t.Fatal("generate failed")
	}
	for _, word := range terminal.seen {
		if !bytes.Equal(word, make([]byte, len(word))) {
			t.Fatal("owned word buffer retained")
		}
	}
	m, f, h = recoveryTestManager(t)
	terminal = &recoveryFakeTerminal{refuse: true}
	_, err = m.Create(recoveryTestRequest(), terminal, false)
	recoveryCode(t, err, "confirmation_refused")
	if h.calls != 0 || f.stores != 0 {
		t.Fatal("failed confirmation persisted")
	}
	m.random = bytes.NewReader(nil)
	_, err = m.Create(recoveryTestRequest(), terminal, false)
	recoveryCode(t, err, "random_unavailable")
}

// Closed schema/role validation accepts the exact emitted pair and legacy row,
// while unknown/duplicate fields, swapped envelopes and ambiguous child reject.
func TestRecoveryClosedSchemasAndNamespaceCompatibility(t *testing.T) {
	m, f, _ := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	metadata, _ := json.Marshal(r)
	row := append([]byte(r.Account()+"\x1f"), metadata...)
	row = append(row, 0x1e)
	keys, groups, err := recoveryRows(row)
	if err != nil || len(keys) != 1 || len(groups) != 1 || keys[0].Storage != "enclave-wrapped-keychain" {
		t.Fatal("valid recovery row refused")
	}
	for _, bad := range [][]byte{append(bytes.Clone(metadata), []byte("{}")...), bytes.Replace(metadata, []byte(`"schema":`), []byte(`"extra":0,"schema":`), 1), bytes.Replace(metadata, []byte(`"schema":`), []byte(`"schema":"bad","schema":`), 1), bytes.Replace(metadata, []byte(`"biometry-any"`), []byte(`"user-presence"`), 1)} {
		_, err := parseRecoveryRecord(bad)
		recoveryCode(t, err, "invalid_record")
	}
	legacy := r.NostrRecord()
	legacy.Storage = "keychain-acl"
	old, _ := json.Marshal(legacy)
	oldRow := append([]byte(legacy.Account()+"\x1f"), old...)
	oldRow = append(oldRow, 0x1e)
	if records, _, err := recoveryRows(oldRow); err != nil || len(records) != 1 {
		t.Fatal("valid legacy row refused")
	}
	_, _, err = recoveryRows(append(row, oldRow...))
	recoveryCode(t, err, "duplicate")
	c, _ := parseRecoveryCiphertext(f.data[r.Account()], r)
	c.Nostr, c.Namecoin = c.Namecoin, c.Nostr
	swapped, _ := json.Marshal(c)
	_, err = parseRecoveryCiphertext(swapped, r)
	recoveryCode(t, err, "invalid_envelope")
}

// Valid account metadata is the nearby control. Correctly checksummed xpubs
// with another network, depth or child still refuse; malformed origins and a
// reused purpose wrapping key cannot turn into an accepted account record.
func TestRecoveryAccountMetadataPolicyRefusals(t *testing.T) {
	m, _, _ := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	if validateRecoveryRecord(r) != nil {
		t.Fatal("valid account refused")
	}
	for _, name := range []string{"network", "depth", "child", "origin", "shared-wrap", "presence"} {
		t.Run(name, func(t *testing.T) {
			bad := r
			raw := base58.Decode(r.Namecoin.XPub)
			switch name {
			case "network":
				copy(raw[:4], []byte{4, 0x35, 0x87, 0xcf})
			case "depth":
				raw[4] = 4
			case "child":
				raw[12] = 1
			case "origin":
				bad.Namecoin.Origin = "[AABBCCDD/84h/7h/0h]"
			case "shared-wrap":
				bad.Namecoin.WrappingPoint = bytes.Clone(r.Nostr.WrappingPoint)
				bad.Namecoin.WrappingFingerprint = r.Nostr.WrappingFingerprint
			case "presence":
				bad.Namecoin.Presence = "none"
			}
			first := sha256.Sum256(raw[:78])
			second := sha256.Sum256(first[:])
			copy(raw[78:], second[:4])
			bad.Namecoin.XPub = base58.Encode(raw)
			recoveryCode(t, validateRecoveryRecord(bad), "invalid_record")
		})
	}
}
