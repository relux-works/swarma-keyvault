package keyvault

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

func recoveryIdentityLegacy(t *testing.T) (RecoveryRecord, []byte) {
	t.Helper()
	m, _, _ := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	b, _ := json.Marshal(r)
	b = bytes.Replace(b, []byte(`"schema":"keyvault-recovery/2"`), []byte(`"schema":"keyvault-recovery/1"`), 1)
	for _, purpose := range []string{"nostr", "namecoin"} {
		b = bytes.Replace(b, []byte(`"`+purpose+`":{"service":"test",`), []byte(`"`+purpose+`":{`), 1)
	}
	r, err := parseRecoveryRecord(b)
	if err != nil {
		t.Fatal("legacy public fixture refused", err)
	}
	return r, b
}

func recoveryIdentityV2(raw []byte, a, b string) []byte {
	raw = bytes.Replace(bytes.Clone(raw), []byte(`"schema":"keyvault-recovery/1"`), []byte(`"schema":"keyvault-recovery/2"`), 1)
	raw = bytes.Replace(raw, []byte(`"nostr":{`), []byte(`"nostr":{"service":"`+a+`",`), 1)
	return bytes.Replace(raw, []byte(`"namecoin":{`), []byte(`"namecoin":{"service":"`+b+`",`), 1)
}

// V1 retains its exact canonical bytes. V2 admits equal/different purpose
// identities, but requires both explicit services and the exact Nostr anchor.
func TestRecoveryPurposeIdentityRecordContract(t *testing.T) {
	legacy, raw := recoveryIdentityLegacy(t)
	// Captured from the published v0.1.0 implementation before this revision;
	// these public-fixture bindings constrain both bytes and the old domain.
	for _, q := range []struct {
		p    RecoveryPurpose
		want string
	}{
		{legacy.Nostr, "43405ee1e7b645bafdcb437e8520cc216442c17ad675eef15ac01fa21f60d319"},
		{legacy.Namecoin, "437c8d67d5c3c7769eb6affeeb51a6829cf6dd957c99e9773c2d9b01e3e9065f"},
	} {
		got := recoveryBinding(legacy, q.p)
		if hex.EncodeToString(got[:]) != q.want {
			t.Fatal("legacy binding changed")
		}
	}
	canonical, _ := json.Marshal(legacy)
	if !bytes.Equal(raw, canonical) {
		t.Fatal("v1 canonical bytes changed")
	}
	for _, b := range []string{"test", "other"} {
		wire := recoveryIdentityV2(raw, "test", b)
		r, err := parseRecoveryRecord(wire)
		if err != nil || r.Account() != "test/recovery@1" || r.NostrRecord().Account() != "test/nostr@2" {
			t.Fatalf("valid separate services refused: %v", err)
		}
		encoded, _ := json.Marshal(r)
		if !bytes.Equal(encoded, wire) {
			t.Fatal("v2 canonical bytes changed")
		}
	}
	valid := recoveryIdentityV2(raw, "test", "other")
	for _, bad := range [][]byte{
		bytes.Replace(valid, []byte(`"namecoin":{"service":"other",`), []byte(`"namecoin":{`), 1),
		bytes.Replace(valid, []byte(`"nostr":{"service":"test",`), []byte(`"nostr":{`), 1),
		recoveryIdentityV2(raw, "different", "other"),
		recoveryIdentityV2(raw, "test", "bad/name"),
		bytes.Replace(valid, []byte(`"service":"other"`), []byte(`"service":"other","service":"test"`), 1),
		bytes.Replace(raw, []byte(`"nostr":{`), []byte(`"nostr":{"service":"test",`), 1),
	} {
		_, err := parseRecoveryRecord(bad)
		recoveryCode(t, err, "invalid_record")
	}
}

// Reservations include B/namecoin, independent of physical anchor A. Unequal
// generations and same-generation records in a different purpose stay valid.
func TestRecoveryPurposeIdentityReservations(t *testing.T) {
	legacy, raw := recoveryIdentityLegacy(t)
	paired := recoveryIdentityV2(raw, "test", "other")
	row := append([]byte("test/recovery@1\x1f"), paired...)
	row = append(row, 0x1e)
	for _, q := range []struct {
		service, purpose string
		version          int
		duplicate        bool
	}{
		{"other", "namecoin", 1, true},
		{"other", "namecoin", 2, false},
		{"test", "namecoin", 1, false},
		{"other", "nostr", 2, false},
		{"test", "nostr", 2, true},
	} {
		n := legacy.NostrRecord()
		n.Service, n.Purpose, n.Version, n.Storage = q.service, q.purpose, q.version, "keychain-acl"
		b, _ := json.Marshal(n)
		r := append([]byte(n.Account()+"\x1f"), b...)
		r = append(r, 0x1e)
		for _, combined := range [][]byte{append(bytes.Clone(row), r...), append(bytes.Clone(r), row...)} {
			keys, groups, err := recoveryRows(combined)
			if q.duplicate {
				recoveryCode(t, err, "duplicate")
			} else if err != nil || len(keys) != 2 || len(groups) != 1 {
				t.Fatalf("legitimate neighbour refused: %+v: %v", q, err)
			}
		}
	}
}

// New requests select both services independently. Invalid/mixed inputs cannot
// reach words, hardware or storage. Swapping identities changes namespaces.
func TestRecoveryPurposeIdentityCreation(t *testing.T) {
	for _, ids := range [][2]string{{"north", "south"}, {"north", "north"}, {"south", "north"}} {
		m, f, h := recoveryTestManager(t)
		q := RecoveryRequest{NostrIdentity: ids[0], NamecoinIdentity: ids[1], Version: 1, NostrVersion: 2, NamecoinVersion: 3}
		r, err := m.Create(q, &recoveryFakeTerminal{}, false)
		if err != nil || r.Schema != "keyvault-recovery/2" || r.Account() != ids[0]+"/recovery@1" || r.NostrRecord().Account() != ids[0]+"/nostr@2" || r.PurposeAccount(r.Namecoin) != ids[1]+"/namecoin@3" || f.stores != 1 || h.calls != 2 {
			t.Fatalf("separate identities were not selected: %v", err)
		}
		c, err := parseRecoveryCiphertext(f.data[r.Account()], r)
		if err != nil || c.Schema != "keyvault-recovery-ciphertext/2" {
			t.Fatal("v2 ciphertext schema not selected", err)
		}
		crossed := bytes.Replace(f.data[r.Account()], []byte(`"keyvault-recovery-ciphertext/2"`), []byte(`"keyvault-recovery-ciphertext/1"`), 1)
		_, err = parseRecoveryCiphertext(crossed, r)
		recoveryCode(t, err, "invalid_envelope")
		nostrPlain, err := recoveryTestOpen(h.keys[0], c.Nostr.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		// The unchanged Nostr record is the positive control. Altering only
		// the other purpose's service also invalidates the whole-pair binding.
		if _, err := recoveryNostrPlain(r, nostrPlain); err != nil {
			t.Fatal("valid Nostr binding refused", err)
		}
		// Metadata alone cannot retarget an existing retained ciphertext.
		r.Namecoin.Service = "elsewhere"
		_, err = recoveryNostrPlain(r, nostrPlain)
		recoveryCode(t, err, "binding_mismatch")
		clear(nostrPlain)
		plain, err := recoveryTestOpen(h.keys[1], c.Namecoin.Ciphertext)
		if err != nil {
			t.Fatal(err)
		}
		binding := recoveryBinding(r, r.Namecoin)
		if bytes.Equal(plain[4:36], binding[:]) {
			t.Fatal("changed service retained plaintext binding")
		}
		clear(plain)
	}
	for _, q := range []RecoveryRequest{
		{NostrIdentity: "north"}, {NamecoinIdentity: "south"},
		{NostrIdentity: "bad/name", NamecoinIdentity: "south"},
		{Service: "legacy", NostrIdentity: "north", NamecoinIdentity: "south"},
	} {
		m, f, h := recoveryTestManager(t)
		q.Version, q.NostrVersion, q.NamecoinVersion = 1, 2, 3
		term := &recoveryFakeTerminal{}
		_, err := m.Create(q, term, false)
		if err == nil || f.stores != 0 || h.calls != 0 || term.confirmation != 0 || term.read != 0 {
			t.Fatal("invalid identities reached effect/words")
		}
	}
}

func recoveryTestDelete(m *RecoveryManager, service string, version int, pin string) error {
	_, err := m.Delete(RecoveryDeleteRequest{NostrIdentity: service, Version: version, ExpectedGroupID: pin}, &recoveryFakeTerminal{})
	return err
}

// Frozen metadata and ciphertext emitted by v0.1.0 are read unchanged through
// its v1 binding, toy ECDH unwrap and BIP-340 signature path. Wrapping scalars
// 1 and 2 belong solely to the published public fixture. This establishes
// software compatibility, with no native/ACL/Enclave qualification claim.
func TestFrozenV1CiphertextToSignature(t *testing.T) {
	raw, err := os.ReadFile("testdata/recovery/v1-public-record.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecoveryRecord(raw)
	if err != nil || r.Schema != "keyvault-recovery/1" {
		t.Fatal("frozen v1 record refused", err)
	}
	encoded, err := os.ReadFile("testdata/recovery/v1-public-ciphertext.json")
	if err != nil {
		t.Fatal(err)
	}
	c, err := parseRecoveryCiphertext(encoded, r)
	if err != nil {
		t.Fatal("frozen v1 ciphertext refused", err)
	}
	var scalar [32]byte
	scalar[31] = 1
	wrapping, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	plain, err := recoveryTestOpen(wrapping, c.Nostr.Ciphertext)
	if err != nil {
		t.Fatal("frozen envelope failed to unwrap", err)
	}
	defer clear(plain)
	secret, err := recoveryNostrPlain(r, plain)
	if err != nil {
		t.Fatal("v1 binding changed", err)
	}
	digest := make([]byte, 32)
	sig, err := signNostrSecret(r.NostrRecord(), bytes.Clone(secret), digest)
	public, _ := hex.DecodeString(r.Nostr.PublicKey)
	if err != nil || VerifyNostr(public, digest, sig) != nil {
		t.Fatal("v1 key signature failed", err)
	}
	changed := bytes.Clone(digest)
	changed[0] = 1
	if err := VerifyNostr(public, changed, sig); err == nil {
		t.Fatal("changed digest accepted")
	}
	scalar[31] = 2
	other, err := ecdh.P256().NewPrivateKey(scalar[:])
	if err != nil {
		t.Fatal(err)
	}
	if _, err := recoveryTestOpen(other, c.Nostr.Ciphertext); err == nil {
		t.Fatal("wrong wrapping purpose opened v1")
	}
	v2, err := parseRecoveryRecord(recoveryIdentityV2(raw, r.Service, "other"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = parseRecoveryCiphertext(encoded, v2)
	recoveryCode(t, err, "invalid_envelope")
	changedCipher := bytes.Replace(encoded, []byte("keyvault-recovery-ciphertext/1"), []byte("keyvault-recovery-ciphertext/2"), 1)
	_, err = parseRecoveryCiphertext(changedCipher, r)
	recoveryCode(t, err, "invalid_envelope")
	_, err = recoveryNostrPlain(v2, plain)
	recoveryCode(t, err, "binding_mismatch")
	canonical, _ := json.Marshal(r)
	if !bytes.Equal(canonical, raw) {
		t.Fatal("frozen v1 metadata bytes changed")
	}
}

// Split-purpose pair reservations and standalone records reject the same
// exact account in both manager creation orders. Neighboring purpose, service
// or generation controls remain usable; collision leaves bytes and counters.
func TestSplitIdentityManagerReservationsBothOrders(t *testing.T) {
	q := RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south", Version: 3, NostrVersion: 5, NamecoinVersion: 7}
	for _, slot := range []struct {
		service, purpose string
		version          int
		collision        bool
	}{
		{"north", "recovery", 3, true}, {"north", "nostr", 5, true}, {"south", "namecoin", 7, true},
		{"north", "namecoin", 7, false}, {"south", "nostr", 5, false}, {"south", "namecoin", 8, false},
	} {
		for _, pairFirst := range []bool{false, true} {
			m, f, h := recoveryTestManager(t)
			store := &recoveryNamespaceStore{recoveryFakeStore: f}
			m.backend = store
			n := NewNostrManager(store, m.lock)
			terminal := &recoveryFakeTerminal{}
			if pairFirst {
				r, err := m.Create(q, terminal, false)
				if err != nil {
					t.Fatal(err)
				}
				before := bytes.Clone(f.data[r.Account()])
				_, err = n.Generate(slot.service, slot.purpose, slot.version)
				if slot.collision {
					var refusal *Refusal
					if !errors.As(err, &refusal) || refusal.Code != "nostr_duplicate" || store.creates != 0 {
						t.Fatal("pair-first collision admitted", err)
					}
				} else if err != nil || store.creates != 1 {
					t.Fatal("pair-first valid neighbor refused", err)
				}
				if f.stores != 1 || h.calls != 2 || !bytes.Equal(before, f.data[r.Account()]) {
					t.Fatal("standalone attempt changed paired ciphertext")
				}
			} else {
				if _, err := n.Generate(slot.service, slot.purpose, slot.version); err != nil {
					t.Fatal(err)
				}
				before, _ := json.Marshal(f.keys)
				_, err := m.Create(q, terminal, false)
				if slot.collision {
					recoveryCode(t, err, "duplicate")
					if f.stores != 0 || h.calls != 0 || terminal.confirmation != 0 || terminal.read != 0 {
						t.Fatal("standalone-first collision reached words/wrap/write")
					}
				} else if err != nil || f.stores != 1 || h.calls != 2 {
					t.Fatal("standalone-first neighbor refused", err)
				}
				after, _ := json.Marshal(f.keys)
				if !bytes.Equal(before, after) || store.creates != 1 {
					t.Fatal("pair attempt changed standalone record")
				}
			}
			if _, _, err := store.rows(); err != nil {
				t.Fatal("manager left inconsistent namespace", err)
			}
		}
	}
}

// The unchanged frozen v1 group reserves its physical, Nostr and Namecoin
// accounts through both managers. Collisions reach no words, wraps or writes,
// preserve retained bytes, and neighboring allocations still succeed.
func TestFrozenV1ManagerReservations(t *testing.T) {
	raw, err := os.ReadFile("testdata/recovery/v1-public-record.json")
	if err != nil {
		t.Fatal(err)
	}
	retained, err := parseRecoveryRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := os.ReadFile("testdata/recovery/v1-public-ciphertext.json")
	if err != nil {
		t.Fatal(err)
	}
	seed := func() (*RecoveryManager, *recoveryNamespaceStore, *recoveryFakeHelper) {
		m, f, h := recoveryTestManager(t)
		f.groups = []RecoveryRecord{retained}
		f.data = map[string][]byte{retained.Account(): bytes.Clone(ciphertext)}
		store := &recoveryNamespaceStore{recoveryFakeStore: f}
		m.backend = store
		return m, store, h
	}
	for _, slot := range []struct {
		purpose   string
		version   int
		collision bool
	}{{"recovery", 1, true}, {"nostr", 2, true}, {"namecoin", 1, true},
		{"recovery", 2, false}, {"nostr", 3, false}, {"namecoin", 2, false}} {
		t.Run("standalone/"+slot.purpose+"/"+fmt.Sprint(slot.version), func(t *testing.T) {
			m, store, h := seed()
			_, err := NewNostrManager(store, m.lock).Generate(retained.Service, slot.purpose, slot.version)
			if slot.collision {
				var refusal *Refusal
				if !errors.As(err, &refusal) || refusal.Code != "nostr_duplicate" || store.creates != 0 {
					t.Fatal("retained v1 standalone collision admitted", err)
				}
			} else if err != nil || store.creates != 1 {
				t.Fatal("valid standalone neighbor refused", err)
			}
			if h.calls != 0 || store.stores != 0 || !bytes.Equal(store.data[retained.Account()], ciphertext) {
				t.Fatal("standalone attempt changed retained group")
			}
			encoded, _ := json.Marshal(store.groups[0])
			if !bytes.Equal(encoded, raw) {
				t.Fatal("retained v1 metadata changed")
			}
		})
	}
	for _, tc := range []struct {
		name      string
		request   RecoveryRequest
		collision bool
	}{
		{"physical", RecoveryRequest{NostrIdentity: "test", NamecoinIdentity: "south", Version: 1, NostrVersion: 11, NamecoinVersion: 11}, true},
		{"nostr", RecoveryRequest{NostrIdentity: "test", NamecoinIdentity: "south", Version: 11, NostrVersion: 2, NamecoinVersion: 11}, true},
		{"namecoin", RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "test", Version: 11, NostrVersion: 11, NamecoinVersion: 1}, true},
		{"neighbor-generations", RecoveryRequest{NostrIdentity: "test", NamecoinIdentity: "test", Version: 2, NostrVersion: 3, NamecoinVersion: 2}, false},
		{"neighbor-services", RecoveryRequest{NostrIdentity: "north", NamecoinIdentity: "south", Version: 1, NostrVersion: 2, NamecoinVersion: 1}, false},
	} {
		t.Run("split/"+tc.name, func(t *testing.T) {
			m, store, h := seed()
			terminal := &recoveryFakeTerminal{}
			_, err := m.Create(tc.request, terminal, false)
			if tc.collision {
				recoveryCode(t, err, "duplicate")
				if store.stores != 0 || h.calls != 0 || terminal.identityConfirmation != 1 || terminal.confirmation != 0 || terminal.read != 0 {
					t.Fatal("retained v1 collision reached words/wrap/write")
				}
			} else if err != nil || store.stores != 1 || h.calls != 2 {
				t.Fatal("valid split neighbor refused", err)
			}
			encoded, _ := json.Marshal(store.groups[0])
			if store.creates != 0 || !bytes.Equal(encoded, raw) || !bytes.Equal(store.data[retained.Account()], ciphertext) {
				t.Fatal("split attempt changed retained v1 bytes")
			}
		})
	}
}
