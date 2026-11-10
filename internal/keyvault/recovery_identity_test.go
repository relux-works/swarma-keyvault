package keyvault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
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
	_, err := m.Delete(RecoveryDeleteRequest{NostrIdentity: service, NamecoinIdentity: service, Version: version, ExpectedGroupID: pin}, &recoveryFakeTerminal{})
	return err
}
