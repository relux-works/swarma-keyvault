package keyvault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

// fakeEnclave stands in for mac-keyvault-enclave: each blob names a Go key,
// and a key created with presence refuses every signature as the Secure
// Enclave does without a finger (errSecInteractionNotAllowed), unless
// fingerOK is set.
type fakeEnclave struct {
	keys     map[string]*ecdsa.PrivateKey
	presence map[string]bool
	requests []EnclaveRequest
	// interactive records the interactive flag of each call.
	interactive []bool
	// enforced overrides the presence verdict create reports.
	enforced *bool
	fingerOK bool
	failWith *EnclaveHelperError
	// pointFor overrides the public half sign reports.
	pointFor []byte
}

func newFakeEnclave() *fakeEnclave {
	return &fakeEnclave{keys: map[string]*ecdsa.PrivateKey{}, presence: map[string]bool{}}
}

func point(key *ecdsa.PrivateKey) []byte {
	return elliptic.Marshal(elliptic.P256(), key.X, key.Y)
}

func (f *fakeEnclave) Call(req EnclaveRequest, interactive bool) (EnclaveResponse, error) {
	f.requests = append(f.requests, req)
	f.interactive = append(f.interactive, interactive)
	if f.failWith != nil {
		return EnclaveResponse{}, f.failWith
	}
	switch req.Op {
	case "create":
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		blob := fmt.Sprintf("blob-%d", len(f.keys))
		f.keys[blob] = key
		f.presence[blob] = req.Presence == enclavePresenceUser
		enforced := f.presence[blob]
		if f.enforced != nil {
			enforced = *f.enforced
		}
		return EnclaveResponse{Blob: []byte(blob), Point: point(key), PresenceEnforced: &enforced}, nil
	case "sign":
		key, ok := f.keys[string(req.Blob)]
		if !ok {
			return EnclaveResponse{}, &EnclaveHelperError{Code: "invalid_blob", Status: -26275, Message: "the Secure Enclave refused the key blob"}
		}
		if req.Presence == enclavePresenceRequired && !f.presence[string(req.Blob)] {
			return EnclaveResponse{}, &EnclaveHelperError{Code: "presence_not_enforced", Status: -25293, Message: "the key signs without user presence although its record requires it; nothing was signed"}
		}
		if f.presence[string(req.Blob)] && (req.Interaction == "none" || !f.fingerOK) {
			return EnclaveResponse{}, &EnclaveHelperError{Code: "presence_required", Status: -25308, Message: "sign: user presence is required and interaction is not allowed"}
		}
		der, err := ecdsa.SignASN1(rand.Reader, key, req.Digest)
		if err != nil {
			return EnclaveResponse{}, err
		}
		p := point(key)
		if f.pointFor != nil {
			p = f.pointFor
		}
		return EnclaveResponse{DER: der, Point: p}, nil
	}
	return EnclaveResponse{}, &EnclaveHelperError{Code: "bad_request", Status: -50, Message: "unknown op"}
}

// enclaveFixture is a RoutedBackend over a recording keychain fake and an
// enclave store in a private temp dir.
func enclaveFixture(t *testing.T) (*Manager, *fakeStore, *EnclaveStore, *fakeEnclave) {
	t.Helper()
	helper := newFakeEnclave()
	enclave := NewEnclaveStore(filepath.Join(t.TempDir(), "enclave"), helper)
	keychain := newFakeStore()
	return newTestManager(t, RoutedBackend{Keychain: keychain, Enclave: enclave}), keychain, enclave, helper
}

func enclaveSpec(purpose string, presence bool) InitSpec {
	spec := validSpec(purpose)
	spec.Store = StoreEnclave
	spec.UserPresence = presence
	return spec
}

func refusalOf(t *testing.T, err error) *Refusal {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("err = %v, want a Refusal", err)
	}
	return refusal
}

// init --enclave --user-presence goes to the enclave store only, asks the
// helper for a user-presence key, stores one private file and lists it with its
// public half; the keychain is never touched (no fallback).
func TestEnclaveInitStoresPresenceKeyWithoutKeychain(t *testing.T) {
	m, keychain, enclave, helper := enclaveFixture(t)
	key, err := m.Init(enclaveSpec("owner", true))
	if err != nil {
		t.Fatal(err)
	}
	if key.Record.Store != StoreEnclave || !key.Record.UserPresence || len(key.SPKI) == 0 {
		t.Fatalf("key = %+v", key)
	}
	if len(keychain.creates) != 0 {
		t.Fatalf("keychain create was called: %+v", keychain.creates)
	}
	if len(helper.requests) != 1 || helper.requests[0].Op != "create" || helper.requests[0].Presence != enclavePresenceUser {
		t.Fatalf("helper requests = %+v", helper.requests)
	}
	info, err := os.Lstat(filepath.Join(enclave.Dir, key.Label+".json"))
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file: %v %v", info, err)
	}
	if dir, _ := os.Lstat(enclave.Dir); dir.Mode().Perm() != 0o700 {
		t.Fatalf("dir mode %o", dir.Mode().Perm())
	}
	listed, err := m.Describe(Address{Kind: KindKey, Service: TestService, Purpose: "owner"})
	if err != nil || listed.Fingerprint() != key.Fingerprint() || listed.RecordProblem != "" {
		t.Fatalf("describe: %+v %v", listed, err)
	}
	// Positive control of the other store: a keychain init still goes to
	// the keychain and never to the helper.
	if _, err := m.Init(validSpec("plain")); err != nil || len(keychain.creates) != 1 || len(helper.requests) != 1 {
		t.Fatalf("keychain init: %v creates=%d helper=%d", err, len(keychain.creates), len(helper.requests))
	}
}

// A key whose measured presence differs from the request is refused in both
// directions and nothing is stored; a helper failure creates nothing and
// never falls back to the keychain.
func TestEnclaveInitRefusesWrongPresenceAndNeverFallsBack(t *testing.T) {
	for _, tc := range []struct {
		name      string
		requested bool
		measured  bool
	}{
		{"asked presence, key has none", true, false},
		{"asked none, key enforces presence", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, keychain, enclave, helper := enclaveFixture(t)
			helper.enforced = &tc.measured
			_, err := m.Init(enclaveSpec("owner", tc.requested))
			if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !refusal.Failure {
				t.Fatalf("refusal = %+v", refusal)
			}
			if entries, _ := os.ReadDir(enclave.Dir); len(entries) != 0 || len(keychain.creates) != 0 {
				t.Fatalf("something was stored: files=%d keychain=%d", len(entries), len(keychain.creates))
			}
		})
	}
	t.Run("helper reports no Secure Enclave", func(t *testing.T) {
		m, keychain, enclave, helper := enclaveFixture(t)
		helper.failWith = &EnclaveHelperError{Code: "enclave_unavailable", Status: -25291, Message: "the Secure Enclave is not available"}
		_, err := m.Init(enclaveSpec("owner", true))
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || refusal.Status != -25291 {
			t.Fatalf("refusal = %+v", refusal)
		}
		if entries, _ := os.ReadDir(enclave.Dir); len(entries) != 0 || len(keychain.creates) != 0 {
			t.Fatalf("something was stored: files=%d keychain=%d", len(entries), len(keychain.creates))
		}
	})
}

// Signing a presence key asks the helper interactively with presence
// required and a reason naming the address; the signature verifies under
// the stored key. A key without presence signs silently.
func TestEnclaveSignRoutesPresencePolicy(t *testing.T) {
	m, keychain, _, helper := enclaveFixture(t)
	helper.fingerOK = true
	digest := sha256.Sum256([]byte("owner signs"))
	for _, tc := range []struct {
		purpose     string
		presence    bool
		wantMode    string
		interactive bool
	}{
		{"owner", true, enclavePresenceRequired, true},
		{"silent", false, enclavePresenceNone, false},
	} {
		if _, err := m.Init(enclaveSpec(tc.purpose, tc.presence)); err != nil {
			t.Fatal(err)
		}
		result, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: tc.purpose}, digest[:])
		if err != nil {
			t.Fatalf("%s: %v", tc.purpose, err)
		}
		if ok, err := VerifyDigest(result.Key.SPKI, digest[:], result.Signature); err != nil || !ok {
			t.Fatalf("%s: signature does not verify", tc.purpose)
		}
		last := helper.requests[len(helper.requests)-1]
		if last.Op != "sign" || last.Presence != tc.wantMode || helper.interactive[len(helper.interactive)-1] != tc.interactive || last.Interaction != "" {
			t.Fatalf("%s: request %+v interactive=%v", tc.purpose, last, helper.interactive)
		}
		if want := "mac-keyvault: sign sha256 " + hex.EncodeToString(digest[:4]) + " with test/" + tc.purpose + " v1"; last.Reason != want {
			t.Fatalf("reason %q, want %q", last.Reason, want)
		}
	}
	if len(keychain.signs) != 0 {
		t.Fatalf("keychain signed: %v", keychain.signs)
	}
}

// Without the owner's finger a presence key yields no signature: the
// refusal is security with errSecInteractionNotAllowed (or the canceled
// prompt's errSecUserCanceled), and NonInteractive forbids the prompt.
func TestEnclaveSignWithoutPresenceIsRefused(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("no finger"))
	t.Run("no finger", func(t *testing.T) {
		m, _, _, _ := enclaveFixture(t)
		if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
			t.Fatal(err)
		}
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || refusal.Status != -25308 || !strings.Contains(refusal.Message, "errSecInteractionNotAllowed") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("non-interactive store", func(t *testing.T) {
		m, _, enclave, helper := enclaveFixture(t)
		helper.fingerOK = true
		enclave.NonInteractive = true
		if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
			t.Fatal(err)
		}
		_, err := m.Sign(addr, digest[:])
		last := helper.requests[len(helper.requests)-1]
		if refusal := refusalOf(t, err); refusal.Status != -25308 || last.Interaction != "none" || helper.interactive[len(helper.interactive)-1] {
			t.Fatalf("refusal = %+v request = %+v", refusal, last)
		}
	})
	t.Run("canceled prompt", func(t *testing.T) {
		m, _, _, helper := enclaveFixture(t)
		if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
			t.Fatal(err)
		}
		helper.failWith = &EnclaveHelperError{Code: "user_canceled", Status: -128, Message: "sign: the presence prompt was canceled"}
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Status != -128 || !strings.Contains(refusal.Message, "errSecUserCanceled") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
}

// A file whose blob, public half or presence no longer match is never used:
// a swapped blob, a blob that signs silently under a presence record, and a
// helper-reported public half that differs from the stored one all refuse
// without emitting a signature.
func TestEnclaveSignRefusesSwappedOrTamperedKeys(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("tamper"))
	setup := func(t *testing.T) (*Manager, *EnclaveStore, *fakeEnclave, string) {
		m, _, enclave, helper := enclaveFixture(t)
		helper.fingerOK = true
		key, err := m.Init(enclaveSpec("owner", true))
		if err != nil {
			t.Fatal(err)
		}
		return m, enclave, helper, key.Label
	}
	rewrite := rewriteEnclaveFile
	t.Run("blob of another presence key", func(t *testing.T) {
		m, enclave, helper, label := setup(t)
		other, _ := helper.Call(EnclaveRequest{Op: "create", Presence: enclavePresenceUser}, false)
		rewrite(t, enclave, label, func(f *enclaveFile) { f.Blob = other.Blob })
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "does not belong to the stored public key") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("blob of a key without presence", func(t *testing.T) {
		m, enclave, helper, label := setup(t)
		other, _ := helper.Call(EnclaveRequest{Op: "create", Presence: enclavePresenceNone}, false)
		rewrite(t, enclave, label, func(f *enclaveFile) { f.Blob, f.Point = other.Blob, other.Point })
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "without user presence") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("unknown blob", func(t *testing.T) {
		m, enclave, _, label := setup(t)
		rewrite(t, enclave, label, func(f *enclaveFile) { f.Blob = []byte("not a blob") })
		_, err := m.Sign(addr, digest[:])
		if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "refused the key blob") {
			t.Fatalf("refusal = %+v", refusal)
		}
	})
	t.Run("helper reports another public half", func(t *testing.T) {
		m, _, helper, _ := setup(t)
		stranger, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		helper.pointFor = point(stranger)
		if _, err := m.Sign(addr, digest[:]); refusalOf(t, err).Code != CodeSecurity {
			t.Fatalf("err = %v", err)
		}
	})
	// Positive control: the untouched key signs.
	t.Run("untouched control", func(t *testing.T) {
		m, _, _, _ := setup(t)
		if _, err := m.Sign(addr, digest[:]); err != nil {
			t.Fatal(err)
		}
	})
}

// Unsafe key files are listed with a problem and never used: a symlink, a
// group-readable file, a file whose label differs from its name and a
// non-JSON file. An open directory refuses the whole store.
func TestEnclaveStoreRefusesUnsafeFiles(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("unsafe"))
	for name, damage := range map[string]func(t *testing.T, path string){
		"symlink": func(t *testing.T, path string) {
			moved := path + ".real"
			if err := os.Rename(path, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(moved, path); err != nil {
				t.Fatal(err)
			}
		},
		"group readable": func(t *testing.T, path string) {
			if err := os.Chmod(path, 0o640); err != nil {
				t.Fatal(err)
			}
		},
		"label mismatch": func(t *testing.T, path string) {
			data, _ := os.ReadFile(path)
			if err := os.WriteFile(path, []byte(strings.Replace(string(data), ".owner.v1", ".other.v1", 1)), 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"second hard link": func(t *testing.T, path string) {
			if err := os.Link(path, path+".alias"); err != nil {
				t.Fatal(err)
			}
		},
		"not json": func(t *testing.T, path string) {
			if err := os.WriteFile(path, []byte("{broken"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			m, _, enclave, helper := enclaveFixture(t)
			helper.fingerOK = true
			key, err := m.Init(enclaveSpec("owner", true))
			if err != nil {
				t.Fatal(err)
			}
			damage(t, filepath.Join(enclave.Dir, key.Label+".json"))
			described, err := m.Describe(addr)
			if err != nil || !strings.HasPrefix(described.RecordProblem, "enclave file refused") {
				t.Fatalf("describe: %+v %v", described, err)
			}
			signs := len(helper.requests)
			if _, err := m.Sign(addr, digest[:]); refusalOf(t, err).Code != CodeMetadataUnknown || len(helper.requests) != signs {
				t.Fatalf("sign: %v helper calls %d -> %d", err, signs, len(helper.requests))
			}
			if _, err := enclave.Sign(key.Label, digest[:]); err == nil || len(helper.requests) != signs {
				t.Fatalf("store sign reached the helper: %v", err)
			}
		})
	}
	// Review F3: the store directory itself replaced by a symlink to a
	// valid private directory is refused, not followed.
	t.Run("symlinked directory", func(t *testing.T) {
		m, _, enclave, _ := enclaveFixture(t)
		if _, err := m.Init(enclaveSpec("owner", false)); err != nil {
			t.Fatal(err)
		}
		moved := enclave.Dir + ".real"
		if err := os.Rename(enclave.Dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(moved, enclave.Dir); err != nil {
			t.Fatal(err)
		}
		if _, err := m.List("", ""); err == nil || !strings.Contains(err.Error(), "not a plain directory") {
			t.Fatalf("symlinked directory listed: %v", err)
		}
	})
	t.Run("open directory", func(t *testing.T) {
		m, _, enclave, _ := enclaveFixture(t)
		if _, err := m.Init(enclaveSpec("owner", false)); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(enclave.Dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if _, err := m.List("", ""); err == nil {
			t.Fatal("an open enclave directory was listed")
		}
	})
}

// A label present in both stores is listed with a problem on both sides and
// never signed; meta updates rewrite only the record of an enclave key.
func TestRoutedBackendDuplicateLabelAndMeta(t *testing.T) {
	m, keychain, enclave, helper := enclaveFixture(t)
	helper.fingerOK = true
	key, err := m.Init(enclaveSpec("owner", true))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := enclave.read(key.Label)
	if _, err := m.MetaSet(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, "role", "ca"); err != nil {
		t.Fatal(err)
	}
	after, _ := enclave.read(key.Label)
	if string(after.Blob) != string(before.Blob) || string(after.Point) != string(before.Point) || !strings.Contains(after.Tag, `"role":"ca"`) || len(keychain.updates) != 0 {
		t.Fatalf("meta rewrite: before %+v after %+v keychain updates %v", before, after, keychain.updates)
	}
	keychain.keys[key.Label] = testItem(key.Label)
	digest := sha256.Sum256([]byte("dup"))
	if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:]); refusalOf(t, err).Code != CodeMetadataUnknown {
		t.Fatalf("duplicate label signed: %v", err)
	}
	keys, _ := m.List("", "")
	problems := 0
	for _, k := range keys {
		if k.Label == key.Label && strings.Contains(k.RecordProblem, "both the keychain and the enclave store") {
			problems++
		}
	}
	if problems != 2 {
		t.Fatalf("problems = %d, keys %+v", problems, keys)
	}
}

// Without a resolvable helper enclave keys are still listed and deletable,
// but sign refuses as unsupported_primitive before any helper call, and
// keychain keys keep working.
func TestEnclaveStoreWithoutHelper(t *testing.T) {
	m, keychain, enclave, helper := enclaveFixture(t)
	if _, err := m.Init(enclaveSpec("owner", false)); err != nil {
		t.Fatal(err)
	}
	enclave.helperErr = errors.New("mac-keyvault-enclave is missing")
	calls := len(helper.requests)
	digest := sha256.Sum256([]byte("no helper"))
	if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:]); refusalOf(t, err).Code != CodeUnsupportedPrimitive || len(helper.requests) != calls {
		t.Fatalf("sign without helper: %v", err)
	}
	if _, err := m.Init(enclaveSpec("second", false)); err == nil {
		t.Fatal("created an enclave key without a helper")
	}
	plain := tl("plain", 1)
	keychain.keys[plain] = testItem(plain)
	if keys, err := m.List("", ""); err != nil || len(keys) != 2 {
		t.Fatalf("list: %v %d", err, len(keys))
	}
	if label, err := m.Delete(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, true); err != nil || !strings.HasSuffix(label, ".owner.v1") {
		t.Fatalf("delete: %v", err)
	}
	if entries, _ := os.ReadDir(enclave.Dir); len(entries) != 0 {
		t.Fatalf("file left after delete: %d", len(entries))
	}
}

// rewriteEnclaveFile changes one stored key file in place, as an attacker
// with this user's file access could.
func rewriteEnclaveFile(t *testing.T, enclave *EnclaveStore, label string, change func(*enclaveFile)) {
	t.Helper()
	dir, err := openEnclaveDir(enclave.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	file, err := readEnclaveFile(dir, label)
	if err != nil {
		t.Fatal(err)
	}
	change(&file)
	name, _ := fileName(label)
	if err := writeEnclaveFile(dir, name, file, true); err != nil {
		t.Fatal(err)
	}
}

// Review F1: a keychain item whose record claims store enclave (with or
// without presence) is listed with a problem and never signed by the
// keychain, and an enclave file whose record claims the keychain is never
// signed either. The Manager signs in the store the record names. Positive
// control: an honest keychain record still signs in the keychain.
func TestRoutedBackendBindsSignatureToDeclaredStore(t *testing.T) {
	digest := sha256.Sum256([]byte("declared store"))
	t.Run("keychain item claiming enclave", func(t *testing.T) {
		m, keychain, _, helper := enclaveFixture(t)
		label := tl("forged", 1)
		keychain.keys[label] = Item{Label: label}
		keychain.installSigner(t, label)
		rec := testRecord(label)
		rec.Store, rec.UserPresence = StoreEnclave, true
		item := keychain.keys[label]
		item.Tag, _ = EncodeRecord(rec)
		keychain.keys[label] = item
		_, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "forged"}, digest[:])
		if refusalOf(t, err).Code != CodeMetadataUnknown || len(keychain.signs) != 0 || len(helper.requests) != 0 {
			t.Fatalf("forged keychain item: %v keychain signs %v helper %d", err, keychain.signs, len(helper.requests))
		}
		described, _ := m.Describe(Address{Kind: KindKey, Service: TestService, Purpose: "forged"})
		if !strings.Contains(described.RecordProblem, "declares another store") {
			t.Fatalf("problem = %q", described.RecordProblem)
		}
	})
	t.Run("enclave file claiming keychain", func(t *testing.T) {
		m, keychain, enclave, helper := enclaveFixture(t)
		helper.fingerOK = true
		key, err := m.Init(enclaveSpec("owner", true))
		if err != nil {
			t.Fatal(err)
		}
		rewriteEnclaveFile(t, enclave, key.Label, func(f *enclaveFile) {
			rec, _ := DecodeRecord([]byte(f.Tag))
			rec.Store, rec.UserPresence = StoreKeychain, false
			tag, _ := EncodeRecord(rec)
			f.Tag = string(tag)
		})
		calls := len(helper.requests)
		_, err = m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:])
		if refusalOf(t, err).Code != CodeMetadataUnknown || len(keychain.signs) != 0 || len(helper.requests) != calls {
			t.Fatalf("enclave file claiming keychain: %v", err)
		}
	})
	t.Run("honest keychain record", func(t *testing.T) {
		m, keychain, _, helper := enclaveFixture(t)
		label := tl("plain", 1)
		keychain.keys[label] = testItem(label)
		keychain.installSigner(t, label)
		if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "plain"}, digest[:]); err != nil || len(keychain.signs) != 1 || len(helper.requests) != 0 {
			t.Fatalf("keychain control: %v signs %v", err, keychain.signs)
		}
	})
}

// Review F2: a failed write of a metadata update leaves the old key file
// byte-for-byte in place, returns the failure and leaves no temporary file;
// the next successful write goes through.
func TestEnclaveFailedWriteKeepsOriginal(t *testing.T) {
	m, _, enclave, _ := enclaveFixture(t)
	key, err := m.Init(enclaveSpec("owner", true))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(enclave.Dir, key.Label+".json")
	before, _ := os.ReadFile(path)
	previous := enclaveWriteAll
	enclaveWriteAll = func(file *os.File, data []byte) error {
		_, _ = file.Write(data[:len(data)/2])
		return errors.New("no space left on device")
	}
	t.Cleanup(func() { enclaveWriteAll = previous })
	if _, err := m.MetaSet(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, "role", "ca"); err == nil || !strings.Contains(err.Error(), "no space left") {
		t.Fatalf("meta set over a failed write: %v", err)
	}
	after, _ := os.ReadFile(path)
	entries, _ := os.ReadDir(enclave.Dir)
	if string(after) != string(before) || len(entries) != 1 {
		t.Fatalf("original changed or temporary left: %d entries", len(entries))
	}
	enclaveWriteAll = previous
	if _, err := m.MetaSet(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, "role", "ca"); err != nil {
		t.Fatalf("control write: %v", err)
	}
}

// Review F4: a metadata update that would make the key file larger than the
// reader accepts is refused before anything is written and the key still
// signs; an update just under the bound is stored and read back.
func TestEnclaveWriteRefusesOversizedFile(t *testing.T) {
	m, _, enclave, helper := enclaveFixture(t)
	helper.fingerOK = true
	key, err := m.Init(enclaveSpec("owner", true))
	if err != nil {
		t.Fatal(err)
	}
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	path := filepath.Join(enclave.Dir, key.Label+".json")
	before, _ := os.ReadFile(path)
	if _, err := m.MetaSet(addr, "blob", strings.Repeat("x", enclaveFileMax)); refusalOf(t, err).Code != CodeInvalidMeta {
		t.Fatalf("oversized meta: %v", err)
	}
	if after, _ := os.ReadFile(path); string(after) != string(before) {
		t.Fatal("oversized update changed the file")
	}
	// The JSON tag is embedded as a string in the file, so its quotes are
	// escaped once more; leave room for that and for the rest of the file.
	if _, err := m.MetaSet(addr, "note", strings.Repeat("y", enclaveFileMax-len(before)-256)); err != nil {
		t.Fatalf("near-bound meta: %v", err)
	}
	digest := sha256.Sum256([]byte("still signs"))
	if _, err := m.Sign(addr, digest[:]); err != nil {
		t.Fatalf("sign after near-bound meta: %v", err)
	}
}

// racingBackend plants a file between the Manager's listing and its
// signature, as a concurrent writer could.
type racingBackend struct {
	RoutedBackend
	afterList func()
}

func (r racingBackend) List() ([]Item, error) {
	items, err := r.RoutedBackend.List()
	if r.afterList != nil {
		r.afterList()
	}
	return items, err
}

// Review F1, signing side: when an enclave file appears under an honest
// keychain label after the listing, the Manager still signs in the keychain
// the authorized record names (SignIn), never in whichever store holds the
// label at signing time.
func TestManagerSignsInTheAuthorizedStore(t *testing.T) {
	_, keychain, enclave, helper := enclaveFixture(t)
	helper.fingerOK = true
	other := NewManager(RoutedBackend{Keychain: newFakeStore(), Enclave: enclave}, NoLock{}, testOrigin)
	if _, err := other.Init(enclaveSpec("donor", false)); err != nil {
		t.Fatal(err)
	}
	label := tl("plain", 1)
	keychain.keys[label] = testItem(label)
	keychain.installSigner(t, label)
	planted := false
	m := newTestManager(t, racingBackend{RoutedBackend: RoutedBackend{Keychain: keychain, Enclave: enclave}, afterList: func() {
		if planted {
			return
		}
		planted = true
		rewriteEnclaveFile(t, enclave, tl("donor", 1), func(*enclaveFile) {})
		dir, _ := openEnclaveDir(enclave.Dir)
		defer dir.Close()
		donor, _ := readEnclaveFile(dir, tl("donor", 1))
		donor.Label = label
		if err := writeEnclaveFile(dir, label+".json", donor, false); err != nil {
			t.Fatal(err)
		}
	}})
	digest := sha256.Sum256([]byte("authorized store"))
	calls := len(helper.requests)
	if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "plain"}, digest[:]); err != nil || len(keychain.signs) != 1 || len(helper.requests) != calls {
		t.Fatalf("sign: %v keychain signs %v helper calls %d -> %d", err, keychain.signs, calls, len(helper.requests))
	}
}

// Review r2 F1: at the moment a new key file is published it already has
// exactly one link and no temporary file is left in the directory, so an
// interruption after publication leaves a key the reader accepts.
func TestEnclaveCreatePublishesOneLink(t *testing.T) {
	m, _, enclave, _ := enclaveFixture(t)
	var links uint64
	var leftovers []string
	previous := enclaveAfterPublish
	enclaveAfterPublish = func(dir *os.File, name string) {
		info, err := os.Lstat(filepath.Join(enclave.Dir, name))
		if err == nil {
			links = uint64(info.Sys().(*syscall.Stat_t).Nlink)
		}
		entries, _ := os.ReadDir(enclave.Dir)
		for _, e := range entries {
			if e.Name() != name {
				leftovers = append(leftovers, e.Name())
			}
		}
	}
	t.Cleanup(func() { enclaveAfterPublish = previous })
	if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
		t.Fatal(err)
	}
	if links != 1 || len(leftovers) != 0 {
		t.Fatalf("at publication: links=%d leftovers=%v", links, leftovers)
	}
}

// Review r2 F2: what is read is judged on the opened descriptor. A key file
// swapped for a group-readable copy, or the directory swapped for a symlink
// to a private copy, between every earlier check and the signature's own
// open is refused with no helper call; a swap for an identical private copy
// (control) still signs. A check-by-path-then-open implementation fails it.
func TestEnclaveSwapBeforeOpenIsJudgedOnTheDescriptor(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("swap before open"))
	for _, tc := range []struct {
		name  string
		swap  func(t *testing.T, dir, file string)
		which string
		signs bool
	}{
		{"file swapped for a 0644 copy", func(t *testing.T, dir, file string) {
			data, _ := os.ReadFile(file)
			os.WriteFile(file+".x", data, 0o644)
			os.Chmod(file+".x", 0o644)
			if err := os.Rename(file+".x", file); err != nil {
				t.Fatal(err)
			}
		}, "file", false},
		{"directory swapped for a symlink", func(t *testing.T, dir, file string) {
			if err := os.Rename(dir, dir+".real"); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(dir+".real", dir); err != nil {
				t.Fatal(err)
			}
		}, "dir", false},
		{"file swapped for a private copy", func(t *testing.T, dir, file string) {
			data, _ := os.ReadFile(file)
			os.WriteFile(file+".x", data, 0o600)
			if err := os.Rename(file+".x", file); err != nil {
				t.Fatal(err)
			}
		}, "file", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, enclave, helper := enclaveFixture(t)
			helper.fingerOK = true
			key, err := m.Init(enclaveSpec("owner", true))
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(enclave.Dir, key.Label+".json")
			// The listing opens the directory and the file once, the
			// signature's own read opens them again: swap right before
			// that second open, after any check the listing made.
			swapped, opens := false, 0
			previous := enclaveBeforeOpen
			enclaveBeforeOpen = func(name string) {
				if (tc.which == "dir") != (name == "") || (tc.which == "file" && name != key.Label+".json") {
					return
				}
				if opens++; opens == 2 {
					swapped = true
					tc.swap(t, enclave.Dir, file)
				}
			}
			t.Cleanup(func() { enclaveBeforeOpen = previous })
			calls := len(helper.requests)
			_, err = m.Sign(addr, digest[:])
			if !swapped {
				t.Fatal("the swap point was never reached")
			}
			if tc.signs {
				if err != nil || len(helper.requests) != calls+1 {
					t.Fatalf("control: %v", err)
				}
				return
			}
			if err == nil || len(helper.requests) != calls {
				t.Fatalf("swapped %s signed or reached the helper: %v", tc.which, err)
			}
		})
	}
}

// Review r3: a key file swapped, between authorization and the signature's
// own read, for a private copy with the same blob and public half but
// another record (user_presence flipped either way) is refused with no
// helper call; an identical copy (control) still signs.
func TestEnclaveSignBindsTheAuthorizedRecord(t *testing.T) {
	addr := Address{Kind: KindKey, Service: TestService, Purpose: "owner"}
	digest := sha256.Sum256([]byte("authorized record"))
	for _, tc := range []struct {
		name    string
		created bool
		listed  bool
		swapped bool
		refused bool
	}{
		{"silent key claiming presence, swapped to silent", false, true, false, true},
		{"presence key swapped to a silent record", true, true, false, true},
		{"identical record (control)", true, true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m, _, enclave, helper := enclaveFixture(t)
			helper.fingerOK = true
			key, err := m.Init(enclaveSpec("owner", tc.created))
			if err != nil {
				t.Fatal(err)
			}
			setPresence := func(f *enclaveFile, presence bool) {
				rec, _ := DecodeRecord([]byte(f.Tag))
				rec.UserPresence = presence
				tag, _ := EncodeRecord(rec)
				f.Tag = string(tag)
			}
			rewriteEnclaveFile(t, enclave, key.Label, func(f *enclaveFile) { setPresence(f, tc.listed) })
			opens := 0
			previous := enclaveBeforeOpen
			enclaveBeforeOpen = func(name string) {
				if name != key.Label+".json" {
					return
				}
				if opens++; opens == 2 {
					enclaveBeforeOpen = previous
					rewriteEnclaveFile(t, enclave, key.Label, func(f *enclaveFile) { setPresence(f, tc.swapped) })
				}
			}
			t.Cleanup(func() { enclaveBeforeOpen = previous })
			calls := len(helper.requests)
			_, err = m.Sign(addr, digest[:])
			if opens < 2 {
				t.Fatal("the swap point was never reached")
			}
			if !tc.refused {
				if err != nil || len(helper.requests) != calls+1 || helper.requests[calls].Presence != enclavePresenceRequired {
					t.Fatalf("control: %v %+v", err, helper.requests[calls:])
				}
				return
			}
			if refusal := refusalOf(t, err); refusal.Code != CodeSecurity || !strings.Contains(refusal.Message, "changed after it was authorized") || len(helper.requests) != calls {
				t.Fatalf("refusal = %+v helper calls %d -> %d", refusal, calls, len(helper.requests))
			}
		})
	}
}

// The presence prompt names what is signed: by default the sha256 prefix of
// the digest and the key address; a Describe hook that recognises the digest
// replaces the "what" part, and a hook returning "" keeps the default. The
// prompt reaches the helper unchanged on the interactive sign request.
func TestEnclavePromptNamesWhatIsSigned(t *testing.T) {
	m, _, enclave, helper := enclaveFixture(t)
	helper.fingerOK = true
	if _, err := m.Init(enclaveSpec("owner", true)); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("statement"))
	key := fmt.Sprintf("%s/owner v1", TestService)
	cases := []struct {
		name     string
		describe func([]byte) string
		want     string
	}{
		{"default", nil, "mac-keyvault: sign sha256 " + hex.EncodeToString(digest[:4]) + " with " + key},
		{"described", func(d []byte) string {
			if bytes.Equal(d, digest[:]) {
				return "authorize vpn-core install 07d46cd2"
			}
			return ""
		}, "mac-keyvault: authorize vpn-core install 07d46cd2 with " + key},
		{"not recognised", func([]byte) string { return "" }, "mac-keyvault: sign sha256 " + hex.EncodeToString(digest[:4]) + " with " + key},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			enclave.Describe = tc.describe
			if _, err := m.Sign(Address{Kind: KindKey, Service: TestService, Purpose: "owner"}, digest[:]); err != nil {
				t.Fatal(err)
			}
			last := helper.requests[len(helper.requests)-1]
			if last.Op != "sign" || last.Reason != tc.want || !helper.interactive[len(helper.interactive)-1] {
				t.Fatalf("sign request reason %q interactive %v, want %q", last.Reason, helper.interactive[len(helper.interactive)-1], tc.want)
			}
		})
	}
}
