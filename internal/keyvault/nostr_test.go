package keyvault

import (
	"bytes"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func nostrTestHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatal("invalid public test fixture encoding")
	}
	return b
}
func nostrCode(t *testing.T, err error, code string) {
	t.Helper()
	var r *Refusal
	if !errors.As(err, &r) || r.Code != "nostr_"+code {
		t.Fatalf("expected nostr_%s refusal, got %v", code, err)
	}
}

// Every official CSV row is judged: the 15 original 32-byte verification
// vectors and their four signing controls, plus explicit refusal of the four
// newer variable-length messages outside this digest-only contract.
func TestNostrBIP340Vectors(t *testing.T) {
	f, err := os.Open("testdata/nostr/bip340.csv")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 20 {
		t.Fatalf("fixture row count changed: %d", len(rows))
	}
	var signed, outside, accepted, rejected int
	for _, row := range rows[1:] {
		t.Run(row[0], func(t *testing.T) {
			pub := nostrTestHex(t, row[2])
			digest := nostrTestHex(t, row[4])
			sig := nostrTestHex(t, row[5])
			err := VerifyNostr(pub, digest, sig)
			if len(digest) != 32 {
				outside++
				nostrCode(t, err, "invalid_digest")
				if row[1] != "" {
					var aux [32]byte
					copy(aux[:], nostrTestHex(t, row[3]))
					_, err = signNostrWithAux(nostrTestHex(t, row[1]), digest, aux)
					nostrCode(t, err, "invalid_digest")
				}
				return
			}
			if row[6] == "TRUE" {
				accepted++
				if err != nil {
					t.Fatalf("valid official vector refused: %v", err)
				}
			} else {
				rejected++
				if err == nil {
					t.Fatal("invalid official vector accepted")
				}
			}
			if row[1] != "" {
				var aux [32]byte
				copy(aux[:], nostrTestHex(t, row[3]))
				got, err := signNostrWithAux(nostrTestHex(t, row[1]), digest, aux)
				if err != nil || !bytes.Equal(got, sig) {
					t.Fatal("official signing vector mismatch")
				}
				signed++
			}
		})
	}
	if signed != 4 || outside != 4 || accepted != 5 || rejected != 10 {
		t.Fatalf("coverage counts: sign=%d outside=%d valid=%d invalid=%d", signed, outside, accepted, rejected)
	}
}

// The independently published NIP-19 public fixture pins the HRP, bit conversion
// and original bech32 checksum. Invalid points and wrong lengths are refused.
func TestNostrNPub(t *testing.T) {
	public := nostrTestHex(t, "7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e")
	got, err := NostrNPub(public)
	if err != nil || got != "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg" {
		t.Fatal("NIP-19 public fixture mismatch")
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), bytes.Repeat([]byte{255}, 32), make([]byte, 33)} {
		_, err := NostrNPub(bad)
		nostrCode(t, err, "invalid_public_key")
	}
}

func nostrTestRequest() NostrRecord {
	return NostrRecord{Schema: "nostr-key/1", Service: "test", Purpose: "nostr", Version: 1, Algorithm: "secp256k1-bip340", Storage: "keychain-acl", Created: "2026-11-09T00:00:00Z"}
}

// These are published test scalars, never live credentials.
func nostrTestMaterial(t *testing.T, n byte) (NostrRecord, []byte) {
	t.Helper()
	seed := make([]byte, 32)
	seed[31] = n
	r, s, err := newNostrMaterialWithRandom(nostrTestRequest(), bytes.NewReader(seed))
	if err != nil {
		t.Fatal(err)
	}
	return r, s
}

// Both valid signing and wrong-key/malformed-input/error paths clear the owned
// scalar buffer. This checks explicit buffers, not Go runtime/library copies.
func TestNostrSigningAndWipe(t *testing.T) {
	r, secret := nostrTestMaterial(t, 3)
	digest := make([]byte, 32)
	sig, err := signNostrSecretWithRandom(r, secret, digest, bytes.NewReader(make([]byte, 32)))
	if err != nil || VerifyNostr(nostrTestHex(t, r.PublicKey), digest, sig) != nil {
		t.Fatal("valid signature failed")
	}
	if !bytes.Equal(secret, make([]byte, 32)) {
		t.Fatal("scalar buffer not cleared")
	}
	_, wrong := nostrTestMaterial(t, 4)
	_, err = signNostrSecret(r, wrong, digest)
	nostrCode(t, err, "key_mismatch")
	if !bytes.Equal(wrong, make([]byte, 32)) {
		t.Fatal("wrong-key buffer not cleared")
	}
	for _, n := range []int{0, 1, 31, 33, 64} {
		_, s := nostrTestMaterial(t, 3)
		_, err := signNostrSecret(r, s, make([]byte, n))
		nostrCode(t, err, "invalid_digest")
		if !bytes.Equal(s, make([]byte, 32)) {
			t.Fatal("malformed-input buffer not cleared")
		}
	}
	_, s := nostrTestMaterial(t, 3)
	_, err = signNostrSecretWithRandom(r, s, digest, bytes.NewReader([]byte{1}))
	nostrCode(t, err, "random_unavailable")
	if !bytes.Equal(s, make([]byte, 32)) {
		t.Fatal("entropy-failure buffer not cleared")
	}
	changed := append([]byte(nil), digest...)
	changed[0] = 1
	nostrCode(t, VerifyNostr(nostrTestHex(t, r.PublicKey), changed, sig), "invalid_signature")
	other, _ := nostrTestMaterial(t, 4)
	nostrCode(t, VerifyNostr(nostrTestHex(t, other.PublicKey), digest, sig), "invalid_signature")
}

// Sampling rejects zero and out-of-range scalars instead of reducing them;
// missing/partial/exhausted randomness yields neither a record nor a scalar.
func TestNostrGenerationEntropy(t *testing.T) {
	valid := make([]byte, 32)
	valid[31] = 3
	for _, prefix := range [][]byte{make([]byte, 32), bytes.Repeat([]byte{255}, 32)} {
		r, s, err := newNostrMaterialWithRandom(nostrTestRequest(), bytes.NewReader(append(prefix, valid...)))
		if err != nil || r.PublicKey == "" || len(s) != 32 {
			t.Fatal("rejection sampling lost valid control")
		}
		clear(s)
	}
	for _, random := range []io.Reader{nil, bytes.NewReader(nil), bytes.NewReader([]byte{1}), bytes.NewReader(make([]byte, 4096))} {
		r, s, err := newNostrMaterialWithRandom(nostrTestRequest(), random)
		nostrCode(t, err, "random_unavailable")
		if r != (NostrRecord{}) || s != nil {
			t.Fatal("partial generation output")
		}
	}
	for _, bad := range [][]byte{nil, make([]byte, 31), make([]byte, 32), bytes.Repeat([]byte{255}, 32), nostrTestHex(t, "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141")} {
		_, err := nostrPrivate(bad)
		nostrCode(t, err, "invalid_secret")
	}
}

type nostrFake struct {
	records        []NostrRecord
	secret         []byte
	calls          []string
	failure        error
	commitThenFail bool
}

func (f *nostrFake) List() ([]NostrRecord, error) {
	f.calls = append(f.calls, "list")
	if f.failure != nil {
		return nil, f.failure
	}
	return append([]NostrRecord(nil), f.records...), nil
}
func (f *nostrFake) Create(r NostrRecord) (NostrRecord, error) {
	f.calls = append(f.calls, "create")
	for _, old := range f.records {
		if old.Account() == r.Account() {
			return NostrRecord{}, nostrRefuse("duplicate")
		}
	}
	if f.failure != nil {
		return NostrRecord{}, f.failure
	}
	seed := make([]byte, 32)
	seed[31] = 3
	created, secret, err := newNostrMaterialWithRandom(r, bytes.NewReader(seed))
	if err != nil {
		return NostrRecord{}, err
	}
	f.records = append(f.records, created)
	f.secret = secret
	if f.commitThenFail {
		return NostrRecord{}, errors.New("simulated interrupted output after atomic creation")
	}
	return created, nil
}
func (f *nostrFake) Sign(r NostrRecord, d []byte) ([]byte, error) {
	f.calls = append(f.calls, "sign")
	if f.failure != nil {
		return nil, f.failure
	}
	return signNostrSecretWithRandom(r, append([]byte(nil), f.secret...), d, bytes.NewReader(make([]byte, 32)))
}

// Manager controls pair successful generation/read/signing with malformed,
// duplicate, missing, locked/untrusted-store and interrupted-output refusals.
// Fakes test policy and forbidden calls, not actual macOS ACL enforcement.
func TestNostrManager(t *testing.T) {
	f := &nostrFake{}
	m := NewNostrManager(f, NoLock{})
	m.now = func() time.Time { return time.Date(2026, 11, 9, 0, 0, 0, 0, time.UTC) }
	r, err := m.Generate("test", "nostr", 1)
	if err != nil {
		t.Fatal(err)
	}
	if r.Storage != "keychain-acl" || r.Presence || r.PrivateExport {
		t.Fatal("false custody claim")
	}
	before := len(f.calls)
	_, err = m.Generate("test", "nostr", 1)
	nostrCode(t, err, "duplicate")
	if strings.Contains(strings.Join(f.calls[before:], ","), "create") {
		t.Fatal("duplicate generation reached create")
	}
	before = len(f.calls)
	_, err = m.Sign("test", "nostr", 1, make([]byte, 31))
	nostrCode(t, err, "invalid_digest")
	if len(f.calls) != before {
		t.Fatal("malformed digest touched backend")
	}
	_, err = m.Sign("test", "nostr", 1, make([]byte, 32))
	if err != nil {
		t.Fatal(err)
	}
	_, err = m.Describe("test", "missing", 1)
	if !errors.Is(err, ErrNotFound) {
		t.Fatal("missing item not refused")
	}
	for _, code := range []int{-25308, -25293, -67050} {
		f.failure = &StatusError{Op: "test store", Status: code}
		before = len(f.calls)
		_, err = m.Generate("test", "other", 1)
		var got *StatusError
		if !errors.As(err, &got) || got.Status != code {
			t.Fatal("backend refusal changed")
		}
		if strings.Contains(strings.Join(f.calls[before:], ","), "create") {
			t.Fatal("store failure created key")
		}
		f.failure = nil
	}
	for _, s := range []string{"", "foreign/name", "../escape", "UPPER"} {
		before = len(f.calls)
		_, err = m.Generate(s, "nostr", 1)
		nostrCode(t, err, "invalid_address")
		if len(f.calls) != before {
			t.Fatal("foreign address touched backend")
		}
	}
	interrupted := &nostrFake{commitThenFail: true}
	mi := NewNostrManager(interrupted, NoLock{})
	_, err = mi.Generate("test", "retry", 1)
	if err == nil {
		t.Fatal("lost interruption")
	}
	_, err = mi.Generate("test", "retry", 1)
	nostrCode(t, err, "duplicate")
	if len(interrupted.records) != 1 {
		t.Fatal("retry duplicated key")
	}
}

// Canonical metadata admits the emitted record and rejects unknown/duplicate
// fields, namespace mismatches and every forged policy/public-key field.
func TestNostrRecordBoundary(t *testing.T) {
	r, _ := nostrTestMaterial(t, 3)
	raw, _ := json.Marshal(r)
	wrap := func(account, metadata string) []byte { return []byte(account + "\x1f" + metadata + "\x1e") }
	if got, err := parseNostrList(wrap(r.Account(), string(raw))); err != nil || len(got) != 1 {
		t.Fatal("valid native metadata refused")
	}
	bad := []string{string(raw) + "{}", strings.Replace(string(raw), "{", "{\"unknown\":1,", 1), strings.Replace(string(raw), "{", "{\"schema\":\"wrong\",", 1)}
	for _, metadata := range bad {
		_, err := parseNostrList(wrap(r.Account(), metadata))
		nostrCode(t, err, "invalid_record")
	}
	_, err := parseNostrList(wrap("other/key@1", string(raw)))
	nostrCode(t, err, "invalid_record")
	for _, mutate := range []func(*NostrRecord){func(r *NostrRecord) { r.Schema = "other" }, func(r *NostrRecord) { r.Storage = "enclave" }, func(r *NostrRecord) { r.Presence = true }, func(r *NostrRecord) { r.PrivateExport = true }, func(r *NostrRecord) { r.Algorithm = "ec-p256" }, func(r *NostrRecord) { r.Created = "bad" }, func(r *NostrRecord) { r.PublicKey = strings.ToUpper(r.PublicKey) }, func(r *NostrRecord) { r.NPub = "nsec1bad" }, func(r *NostrRecord) { r.Version = 0 }} {
		forged := r
		mutate(&forged)
		if validateNostrRecord(forged) == nil {
			t.Fatal("forged record accepted")
		}
	}
	f := &nostrFake{records: []NostrRecord{r, r}}
	_, err = NewNostrManager(f, NoLock{}).List()
	nostrCode(t, err, "duplicate")
}
