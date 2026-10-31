//go:build darwin && cgo

package keyvault

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/testguard"
	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

// GuardedStore wraps a Backend and fails the test process before any Create,
// Delete, UpdateTag or Sign whose label is outside the test namespace
// (service "test", see IsTestLabel) reaches the real keychain. Every
// integration test in this repository goes through it. Every mutating or
// private-key-using Backend method must be overridden here: an embedded
// method Go promotes unchanged is a guard bypass (review rev1 F1 found Sign
// promoted that way).
type GuardedStore struct {
	Backend
	touched []string
}

// ErrGuardedLabel is returned when a test tries to touch a non-test label.
var ErrGuardedLabel = errors.New("test guard: label outside the test namespace " + TestLabelPrefix)

func (g *GuardedStore) guard(label string) error {
	if !IsTestLabel(label) {
		return fmt.Errorf("%w: %q", ErrGuardedLabel, label)
	}
	g.touched = append(g.touched, label)
	return nil
}

func (g *GuardedStore) Create(opts CreateOptions) (Item, error) {
	if err := g.guard(opts.Label); err != nil {
		return Item{}, err
	}
	return g.Backend.Create(opts)
}

func (g *GuardedStore) Delete(label string) error {
	if err := g.guard(label); err != nil {
		return err
	}
	return g.Backend.Delete(label)
}

func (g *GuardedStore) UpdateTag(label string, tag []byte) error {
	if err := g.guard(label); err != nil {
		return err
	}
	return g.Backend.UpdateTag(label, tag)
}

// Sign is guarded too: the private half of a foreign key must never be used
// from a test, even though signing does not modify the item.
func (g *GuardedStore) Sign(label string, digest []byte) ([]byte, error) {
	if err := g.guard(label); err != nil {
		return nil, err
	}
	return g.Backend.Sign(label, digest)
}

// Decrypt is guarded like Sign: it uses the private half.
func (g *GuardedStore) Decrypt(label string, envelope []byte) ([]byte, error) {
	if err := g.guard(label); err != nil {
		return nil, err
	}
	decrypter, ok := g.Backend.(StoreDecrypter)
	if !ok {
		return nil, fmt.Errorf("backend %T cannot decrypt", g.Backend)
	}
	return decrypter.Decrypt(label, envelope)
}

func newGuardedSecurityStore(t *testing.T) *GuardedStore {
	t.Helper()
	testguard.Require(t)
	store := &GuardedStore{Backend: NewSecurityStore()}
	t.Cleanup(func() {
		for _, label := range store.touched {
			if err := store.Backend.Delete(label); err != nil && !errors.Is(err, ErrNotFound) {
				t.Errorf("cleanup %s: %v", label, err)
			}
		}
	})
	return store
}

// testLabel is works.relux.mac-keyvault.key.test.<suffix>-<pid>.v1: kind
// key, service "test", purpose "<suffix>-<pid>", version 1.
func testLabel(t *testing.T, suffix string) string {
	return tl(fmt.Sprintf("%s-%d", suffix, os.Getpid()), 1)
}

func testTag(t *testing.T, label string) []byte {
	t.Helper()
	tag, err := EncodeRecord(testRecord(label))
	if err != nil {
		t.Fatal(err)
	}
	return tag
}

// The guard itself refuses non-test labels (positive control for every
// integration test below): a foreign or production-prefixed label never
// reaches the wrapped backend through Create, Delete, UpdateTag or Sign —
// Sign included, so the private half of a production key is never used by
// a test (rev1 F1: an embedded Backend.Sign was promoted around the guard).
// The store holds a signing-capable production key so that a leaked Sign
// would succeed rather than fail for another reason; the test then asserts
// zero recorded signs. Test-namespace labels sign through the guard
// (positive control).
func TestGuardedStoreRefusesNonTestLabels(t *testing.T) {
	inner := newFakeStore(LabelPrefix + "prod")
	inner.installSigner(t, LabelPrefix+"prod")
	store := &GuardedStore{Backend: inner}
	digest := testDigest("guard sign")
	for _, label := range []string{LabelPrefix + "prod", LabelPrefix + "key.kvctl.pki.v1", LabelPrefix + "key.testx.a.v1", "com.apple.security.key", TestLabelPrefix, LabelPrefix + "test.", ""} {
		if _, err := store.Create(CreateOptions{Label: label, Store: StoreKeychain}); !errors.Is(err, ErrGuardedLabel) {
			t.Fatalf("create %q: err = %v", label, err)
		}
		if err := store.Delete(label); !errors.Is(err, ErrGuardedLabel) {
			t.Fatalf("delete %q: err = %v", label, err)
		}
		if err := store.UpdateTag(label, nil); !errors.Is(err, ErrGuardedLabel) {
			t.Fatalf("update %q: err = %v", label, err)
		}
		if sig, err := store.Sign(label, digest); !errors.Is(err, ErrGuardedLabel) || sig != nil {
			t.Fatalf("sign %q: sig=%x err = %v", label, sig, err)
		}
		if plain, err := store.Decrypt(label, []byte("envelope")); !errors.Is(err, ErrGuardedLabel) || plain != nil {
			t.Fatalf("decrypt %q: plain=%x err = %v", label, plain, err)
		}
	}
	if len(inner.creates) != 0 || len(inner.deletes) != 0 || len(inner.updates) != 0 || len(inner.signs) != 0 {
		t.Fatalf("guard leaked calls: creates=%v deletes=%v updates=%v signs=%v", inner.creates, inner.deletes, inner.updates, inner.signs)
	}
	if _, ok := inner.keys[LabelPrefix+"prod"]; !ok {
		t.Fatal("production key was deleted through the guard")
	}
	if len(inner.keys) != 1 {
		t.Fatalf("guard let a create through: %v", inner.keys)
	}
	for _, label := range []string{tl("ok", 1), LabelPrefix + "secret.test.tok.v2", LabelPrefix + "test.rev1-leftover"} {
		if _, err := store.Create(CreateOptions{Label: label, Store: StoreKeychain}); err != nil {
			t.Fatalf("test label %s refused: %v", label, err)
		}
	}
	inner.installSigner(t, tl("ok", 1))
	if sig, err := store.Sign(tl("ok", 1), digest); err != nil || len(sig) == 0 || len(inner.signs) != 1 || inner.signs[0] != tl("ok", 1) {
		t.Fatalf("test label sign: err=%v sig=%x signs=%v", err, sig, inner.signs)
	}
}

// Login-keychain ECIES on this Mac: an envelope sealed in pure Go to a new
// non-extractable test key opens through Security.framework with the
// payload intact, and the same envelope with one ciphertext byte or one tag
// byte changed fails with errSecParam and no plaintext. Attended runs only,
// like every real-keychain test.
func TestSecurityStoreDecryptOpensGoEnvelope(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "kek")
	item, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain})
	if err != nil {
		t.Fatal(err)
	}
	kek := bytes.Repeat([]byte{0x5a}, kekclient.KEKLen)
	spec := kekclient.WrapSpec{SPKI: item.SPKI, Fingerprint: kekclient.Fingerprint(item.SPKI), Address: "test/kek", Generation: 1, Requirement: `cdhash H"` + strings.Repeat("ab", 20) + `"`, InstallPath: "/opt/test/proxy"}
	sealed, err := kekclient.Wrap(spec, kek)
	if err != nil {
		t.Fatal(err)
	}
	env, err := kekclient.ParseEnvelope(sealed)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := store.Decrypt(label, env.ECIES)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := kekclient.ParsePayload(plain, env)
	if err != nil || !bytes.Equal(payload.KEK, kek) || payload.Requirement != spec.Requirement {
		t.Fatalf("payload = %+v, %v", payload, err)
	}
	for _, i := range []int{70, len(env.ECIES) - 1} {
		tampered := bytes.Clone(env.ECIES)
		tampered[i] ^= 1
		plain, err := store.Decrypt(label, tampered)
		var status *StatusError
		if plain != nil || !errors.As(err, &status) || status.Status != errSecParam {
			t.Fatalf("tampered byte %d: plain=%x err=%v", i, plain, err)
		}
	}
}

// Login-keychain round trip on this Mac: Create persists a P-256 pair whose
// SPKI is a 91-byte DER, List returns it with the exact record tag, UpdateTag
// replaces the tag in place, Delete removes both key halves so a second
// Delete is ErrNotFound.
func TestSecurityStoreKeychainRoundTrip(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "roundtrip")
	tag := testTag(t, label)

	item, err := store.Create(CreateOptions{Label: label, Tag: tag, Store: StoreKeychain})
	if err != nil {
		t.Fatal(err)
	}
	if len(item.SPKI) != 91 || (Key{SPKI: item.SPKI}).Fingerprint() == "" {
		t.Fatalf("spki = %x", item.SPKI)
	}

	find := func() *Item {
		items, err := store.List()
		if err != nil {
			t.Fatal(err)
		}
		for i := range items {
			if !strings.HasPrefix(items[i].Label, LabelPrefix) {
				t.Fatalf("bridge listed a foreign label %q", items[i].Label)
			}
			if items[i].Label == label {
				return &items[i]
			}
		}
		return nil
	}
	listed := find()
	if listed == nil {
		t.Fatal("created key missing from list")
	}
	if string(listed.Tag) != string(tag) || (Key{SPKI: listed.SPKI}).Fingerprint() != (Key{SPKI: item.SPKI}).Fingerprint() {
		t.Fatalf("listed = %+v, created = %+v", *listed, item)
	}
	rec, problem := DecodeRecord(listed.Tag)
	if problem != "" || rec.Schema != 2 || rec.Service != TestService || !strings.HasPrefix(rec.Purpose, "roundtrip-") {
		t.Fatalf("listed record = %+v (%s)", rec, problem)
	}

	rec.Meta["owner"] = "alexis"
	updated, _ := EncodeRecord(rec)
	if err := store.UpdateTag(label, updated); err != nil {
		t.Fatal(err)
	}
	if listed = find(); listed == nil || string(listed.Tag) != string(updated) {
		t.Fatalf("tag after update = %+v", listed)
	}
	if err := store.UpdateTag(testLabel(t, "never-created"), updated); !errors.Is(err, ErrNotFound) {
		t.Fatalf("update of a missing label: %v", err)
	}

	if err := store.Delete(label); err != nil {
		t.Fatal(err)
	}
	if err := store.Delete(label); !errors.Is(err, ErrNotFound) {
		t.Fatalf("second delete err = %v, want ErrNotFound (a key half survived)", err)
	}
	if find() != nil {
		t.Fatal("deleted key still listed")
	}
}

// errSecDataNotAvailable is what Security.framework answers when private
// material of a CSSM_KEYATTR_EXTRACTABLE-cleared key is requested.
const errSecDataNotAvailable = -25316

// Attestation (review F5): the private half the bridge creates cannot leave
// the keychain. SecKeyCopyExternalRepresentation and
// SecItemExport(kSecFormatWrappedPKCS8) both fail with errSecDataNotAvailable
// and hand back zero bytes, while the public half stays readable. Bound: the
// probe runs from the binary the ACL trusts, so a success here would mean the
// item itself is extractable, not that the ACL was bypassed.
func TestSecurityStorePrivateKeyIsNotExtractable(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "noexport")
	item, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain})
	if err != nil {
		t.Fatal(err)
	}
	probe, err := store.Backend.(*SecurityStore).ProbeExport(label)
	if err != nil {
		t.Fatal(err)
	}
	if probe.RepresentationStatus != errSecDataNotAvailable || probe.ExportStatus != errSecDataNotAvailable || probe.LeakedBytes != 0 {
		t.Fatalf("private key export probe = %+v; want both paths refused with %d and zero bytes", probe, errSecDataNotAvailable)
	}
	if len(item.SPKI) != 91 {
		t.Fatalf("public half unreadable after non-extractable create: %x", item.SPKI)
	}
	if _, err := store.Backend.(*SecurityStore).ProbeExport(testLabel(t, "never-created")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("probe of a missing label: %v", err)
	}
}

// Attestation (review F5): the SecAccess installed on the private half
// trusts exactly the calling binary for every private-key authorization
// (sign, decrypt, derive, export) and no entry grants one of those to any
// application. The Encrypt/Integrity/PartitionID entries the keychain adds
// for public operations are allowed to be open; ChangeACL trusts nobody.
func TestSecurityStoreACLTrustsOnlyCallingBinary(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "acl")
	if _, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain}); err != nil {
		t.Fatal(err)
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	self, _ = filepath.EvalSymlinks(self)
	entries, err := store.Backend.(*SecurityStore).DescribeACL(label)
	if err != nil {
		t.Fatal(err)
	}
	private := map[string]bool{"ACLAuthorizationSign": true, "ACLAuthorizationDecrypt": true, "ACLAuthorizationDerive": true, "ACLAuthorizationExportClear": true, "ACLAuthorizationExportWrapped": true, "ACLAuthorizationMAC": true}
	covered := map[string]bool{}
	for _, entry := range entries {
		guardsPrivate := false
		for _, auth := range entry.Authorizations {
			if private[auth] {
				guardsPrivate = true
				covered[auth] = true
			}
		}
		if !guardsPrivate {
			continue
		}
		apps := make([]string, 0, len(entry.Applications))
		for _, app := range entry.Applications {
			resolved, _ := filepath.EvalSymlinks(app)
			apps = append(apps, resolved)
		}
		if entry.AnyApplication || len(apps) != 1 || apps[0] != self {
			t.Fatalf("private-key ACL entry %v trusts %v (any=%v); want exactly %s", entry.Authorizations, entry.Applications, entry.AnyApplication, self)
		}
	}
	for auth := range private {
		if !covered[auth] {
			t.Fatalf("no ACL entry covers %s: %+v", auth, entries)
		}
	}
	if _, err := store.Backend.(*SecurityStore).DescribeACL(testLabel(t, "never-created")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("acl of a missing label: %v", err)
	}
}

// Creating the same label twice at the bridge level is possible in the legacy
// keychain, which is why Manager must gate duplicates itself under the lock;
// this test pins that bound so the gate is not mistaken for a keychain
// guarantee.
func TestSecurityStoreDoesNotRefuseDuplicateLabelsItself(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "dupbridge")
	for i := 0; i < 2; i++ {
		if _, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain}); err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
	}
	rec := testRecord(label)
	if _, err := newTestManager(t, store).Init(validSpec(rec.Purpose)); refusalCode(t, err) != CodeDuplicate {
		t.Fatal("manager admitted the duplicate")
	}
	if err := store.Delete(label); err != nil {
		t.Fatal(err)
	}
}

// On this unprovisioned binary the Secure Enclave and user-presence shapes
// return exactly -34018 from Security.framework and leave no key behind.
// Bound: on a binary signed with a provisioning profile these creates would
// succeed and this test would report that as a failure to re-decide.
func TestSecurityStoreEnclaveAndUserPresenceReturnMissingEntitlement(t *testing.T) {
	store := newGuardedSecurityStore(t)
	for name, opts := range map[string]CreateOptions{
		"enclave":       {Store: StoreEnclave},
		"user-presence": {Store: StoreKeychain, UserPresence: true},
	} {
		t.Run(name, func(t *testing.T) {
			opts.Label = testLabel(t, name)
			opts.Tag = testTag(t, opts.Label)
			_, err := store.Create(opts)
			var status *StatusError
			if !errors.As(err, &status) || status.Status != errSecMissingEntitlement {
				t.Fatalf("err = %v, want OSStatus -34018", err)
			}
			if err := store.Backend.Delete(opts.Label); !errors.Is(err, ErrNotFound) {
				t.Fatalf("a key was persisted despite -34018: delete err = %v", err)
			}
		})
	}
}

// Deleting a test label that does not exist is ErrNotFound rather than a
// silent success.
func TestSecurityStoreDeleteMissingIsNotFound(t *testing.T) {
	store := newGuardedSecurityStore(t)
	if err := store.Delete(testLabel(t, "never-created")); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
}

// Bridge records are framed by US/RS bytes with a hex point; a truncated
// record is an error, an unreadable point yields an item without SPKI, the
// tag bytes pass through verbatim, and a point containing framing bytes
// survives because it is hex encoded.
func TestParseListRecords(t *testing.T) {
	gx := "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	gy := "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	record := func(label, tag, status, point string) string {
		return label + "\x1f" + tag + "\x1f" + status + "\x1f" + point + "\x1e"
	}
	items, err := parseListRecords([]byte(record(LabelPrefix+"a", `{"schema":2}`, "0", "04"+gx+gy) + record(LabelPrefix+"b", "", "-2", "")))
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || len(items[0].SPKI) != 91 || string(items[0].Tag) != `{"schema":2}` || len(items[1].SPKI) != 0 || len(items[1].Tag) != 0 {
		t.Fatalf("items = %+v", items)
	}
	if _, err := parseListRecords([]byte("only\x1ftwo\x1e")); err == nil {
		t.Fatal("truncated record accepted")
	}
	if _, err := parseListRecords([]byte(record(LabelPrefix+"c", "", "0", "zz"))); err == nil {
		t.Fatal("malformed hex accepted")
	}
	if _, err := parseListRecords([]byte(record(LabelPrefix+"d", "", "0", "04"+gx+gx))); err == nil {
		t.Fatal("off-curve point accepted")
	}
}

// ACL records decode "auths|apps" entries: "*" is any application, an
// empty application column is no application.
func TestParseACLRecords(t *testing.T) {
	entries := parseACLRecords([]byte("ACLAuthorizationEncrypt|*\x1eACLAuthorizationSign,ACLAuthorizationDecrypt|/a;/b\x1eACLAuthorizationChangeACL|\x1e"))
	if len(entries) != 3 || !entries[0].AnyApplication || len(entries[1].Applications) != 2 || entries[1].Authorizations[1] != "ACLAuthorizationDecrypt" || entries[2].AnyApplication || len(entries[2].Applications) != 0 {
		t.Fatalf("entries = %+v", entries)
	}
}

// SecurityStore.Sign on this Mac: the bridge signs a 32-byte digest with the
// keychain private half (digest variant, so the bytes are signed as the
// digest, not re-hashed) and the DER it returns parses strictly and
// verifies under the item's own SPKI with crypto/ecdsa; two signatures of
// one digest differ (fresh k). A mis-sized digest is invalid_digest without
// a Security call, and a label with no key is ErrNotFound. The high-S
// share of corecrypto's output is not assumed either way: whatever comes
// back, its low-S form verifies.
func TestSecurityStoreSign(t *testing.T) {
	store := newGuardedSecurityStore(t)
	label := testLabel(t, "sign")
	item, err := store.Create(CreateOptions{Label: label, Tag: testTag(t, label), Store: StoreKeychain})
	if err != nil {
		t.Fatal(err)
	}
	digest := testDigest("security store sign")
	first, err := store.Sign(label, digest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Sign(label, digest)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("two ECDSA signatures of one digest are identical; k is not fresh")
	}
	for _, der := range [][]byte{first, second} {
		sig, err := ParseSignature(der, FormatSignatureDERLowS)
		if err != nil {
			t.Fatalf("bridge DER is not strict: %v (%x)", err, der)
		}
		if ok, err := VerifyDigest(item.SPKI, digest, sig); err != nil || !ok {
			t.Fatalf("bridge signature does not verify as given: %v %v", ok, err)
		}
		if ok, err := VerifyDigest(item.SPKI, digest, sig.LowS()); err != nil || !ok {
			t.Fatalf("low-S form does not verify: %v %v", ok, err)
		}
	}
	if ok, _ := VerifyDigest(item.SPKI, testDigest("another"), mustParse(t, first)); ok {
		t.Fatal("signature verified over a different digest")
	}
	if _, err := store.Sign(label, digest[:31]); refusalCode(t, err) != CodeInvalidDigest {
		t.Fatalf("31-byte digest: %v", err)
	}
	if _, err := store.Sign(tl(fmt.Sprintf("absent-%d", os.Getpid()), 1), digest); !errors.Is(err, ErrNotFound) {
		t.Fatalf("absent label: %v", err)
	}
}

func mustParse(t *testing.T, der []byte) Signature {
	t.Helper()
	sig, err := ParseSignature(der, FormatSignatureDERLowS)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}
