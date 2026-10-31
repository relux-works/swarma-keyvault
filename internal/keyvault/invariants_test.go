package keyvault_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/recordtest"
)

// recordingStore is the minimal Backend the forgery table drives: it holds
// one stored item and counts every call so a refusal can be proven to have
// made zero creates and zero tag rewrites.
type recordingStore struct {
	keys    map[string]keyvault.Item
	creates int
	updates int
	signs   int
	// priv signs for every stored item (storeWith installs its SPKI).
	priv *ecdsa.PrivateKey
}

func (s *recordingStore) Sign(label string, digest []byte) ([]byte, error) {
	s.signs++
	if _, ok := s.keys[label]; !ok {
		return nil, keyvault.ErrNotFound
	}
	return ecdsa.SignASN1(rand.Reader, s.priv, digest)
}

func (s *recordingStore) Create(opts keyvault.CreateOptions) (keyvault.Item, error) {
	s.creates++
	spki, _ := x509.MarshalPKIXPublicKey(&s.priv.PublicKey)
	item := keyvault.Item{Label: opts.Label, Tag: opts.Tag, SPKI: spki}
	s.keys[opts.Label] = item
	return item, nil
}

func (s *recordingStore) List() ([]keyvault.Item, error) {
	items := []keyvault.Item{}
	for _, item := range s.keys {
		items = append(items, item)
	}
	return items, nil
}

func (s *recordingStore) Delete(label string) error {
	if _, ok := s.keys[label]; !ok {
		return keyvault.ErrNotFound
	}
	delete(s.keys, label)
	return nil
}

func (s *recordingStore) UpdateTag(label string, tag []byte) error {
	s.updates++
	item, ok := s.keys[label]
	if !ok {
		return keyvault.ErrNotFound
	}
	item.Tag = tag
	s.keys[label] = item
	return nil
}

// digest32 is a fixed SHA-256-sized digest for the sign gate rows.
var digest32 = sha256.Sum256([]byte("forgery table digest"))

var origin = keyvault.Origin{User: "tester", Host: "testhost", Tool: "mac-keyvault/test", Source: keyvault.SourceGenerated}

// storedKey is a valid schema-2 key record for key/test/<purpose> v1.
func storedKey(purpose string) keyvault.Record {
	return keyvault.Record{Schema: keyvault.SchemaVersion, Kind: keyvault.KindKey, Service: keyvault.TestService, Purpose: purpose, Version: 1,
		Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreKeychain, Extraction: keyvault.ExtractionNone, Usages: []string{"sign", "verify"},
		Format:  keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS},
		Created: keyvault.NewTime(time.Unix(1_700_000_000, 0)), Origin: origin, Meta: map[string]any{"owner": "t"}}
}

// storeWith stores rec under label (which may disagree with the record).
func storeWith(t *testing.T, label string, rec keyvault.Record) (*recordingStore, *keyvault.Manager, string) {
	t.Helper()
	tag, err := keyvault.EncodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	store := &recordingStore{keys: map[string]keyvault.Item{label: {Label: label, Tag: tag, SPKI: spki}}, priv: priv}
	manager := keyvault.NewManager(store, keyvault.FileLock{Path: filepath.Join(t.TempDir(), "lock")}, origin)
	manager.SetClock(func() time.Time { return time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC) })
	return store, manager, label
}

func code(t *testing.T, err error) string {
	t.Helper()
	var refusal *keyvault.Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a Refusal, got %v", err)
	}
	return refusal.Code
}

// The invariant table has exactly one row per JSON field of Record, in
// declaration order; user_presence is the one stated bound (a request flag
// the backend answers, no value rule). A field added to Record without a
// row fails here, and every forgery names a field the table governs.
func TestRecordInvariantsCoverEveryField(t *testing.T) {
	var fields []string
	typ := reflect.TypeOf(keyvault.Record{})
	for i := 0; i < typ.NumField(); i++ {
		name := strings.Split(typ.Field(i).Tag.Get("json"), ",")[0]
		if name == "user_presence" {
			continue
		}
		fields = append(fields, name)
	}
	if got := keyvault.InvariantFields(); !reflect.DeepEqual(got, fields) {
		t.Fatalf("invariant rows %v\nrecord fields   %v", got, fields)
	}
	governed := map[string]bool{}
	for _, field := range fields {
		governed[field] = true
	}
	for _, forgery := range recordtest.Forgeries() {
		if !governed[forgery.Field] {
			t.Fatalf("forgery %q names %q, which no row governs", forgery.Name, forgery.Field)
		}
	}
}

// Every forged field on a stored schema-2 key is refused by Manager.Rotate
// (metadata_unknown naming the row's code, zero creates, old tag
// byte-identical), refused by Manager.MetaSet and MetaUnset (zero tag
// rewrites), and reported by Describe as record_invalid:<code> while the
// item stays readable. The positive controls (validity both null, only a
// future not_after) rotate once and describe with no finding.
func TestForgedStoredRecordRefusedEverywhere(t *testing.T) {
	forgeries := append(recordtest.Forgeries(), recordtest.Forgery{Name: "label mismatch", Field: "version", Code: keyvault.CodeMetadataUnknown, Mutate: recordtest.LabelMismatch})
	for _, forgery := range forgeries {
		t.Run(forgery.Name, func(t *testing.T) {
			rec := storedKey("forged")
			label := rec.Label()
			forgery.Mutate(&rec)
			// The forged record is stored under the unforged label.
			store, manager, _ := storeWith(t, label, rec)
			before := store.keys[label].Tag
			a := keyvault.Address{Kind: keyvault.KindKey, Service: keyvault.TestService, Purpose: "forged"}

			_, err := manager.Rotate(a)
			if got := code(t, err); got != keyvault.CodeMetadataUnknown || !strings.Contains(err.Error(), forgery.Code) {
				t.Fatalf("rotate: code %s, err %v; want %s naming %s", got, err, keyvault.CodeMetadataUnknown, forgery.Code)
			}
			if _, err := manager.MetaSet(a, "note", "x"); code(t, err) != keyvault.CodeMetadataUnknown {
				t.Fatalf("meta set: %v", err)
			}
			if _, err := manager.MetaUnset(a, "owner"); code(t, err) != keyvault.CodeMetadataUnknown {
				t.Fatalf("meta unset: %v", err)
			}
			// Sign (T2) runs the same trust gate: a forged record never
			// reaches the private key, and verify never trusts its SPKI.
			if _, err := manager.Sign(a, digest32[:]); code(t, err) != keyvault.CodeMetadataUnknown {
				t.Fatalf("sign: %v", err)
			}
			if _, err := manager.PublicKeyFor(a); code(t, err) != keyvault.CodeMetadataUnknown {
				t.Fatalf("verify key: %v", err)
			}
			if store.creates != 0 || store.updates != 0 || store.signs != 0 || len(store.keys) != 1 || !bytes.Equal(store.keys[label].Tag, before) {
				t.Fatalf("a gate touched the store: creates=%d updates=%d signs=%d keys=%d tag-equal=%v", store.creates, store.updates, store.signs, len(store.keys), bytes.Equal(store.keys[label].Tag, before))
			}
			key, err := manager.Describe(a)
			if err != nil {
				t.Fatalf("describe: %v", err)
			}
			_, findings := key.Findings(time.Unix(1_750_000_000, 0))
			want := keyvault.FindingRecordInvalid + ":" + forgery.Code
			found := false
			for _, finding := range findings {
				found = found || finding == want
			}
			if !found {
				t.Fatalf("describe findings %v do not name %s", findings, want)
			}
		})
	}
	for name, control := range recordtest.PositiveControls() {
		t.Run("control "+name, func(t *testing.T) {
			rec := storedKey("control")
			control(&rec)
			store, manager, label := storeWith(t, rec.Label(), rec)
			a := keyvault.Address{Kind: keyvault.KindKey, Service: keyvault.TestService, Purpose: "control"}
			key, err := manager.Describe(a)
			if err != nil {
				t.Fatal(err)
			}
			if _, findings := key.Findings(time.Unix(1_750_000_000, 0)); len(findings) != 0 {
				t.Fatalf("valid record reported findings %v", findings)
			}
			result, err := manager.Rotate(a)
			if err != nil || store.creates != 1 || result.New.Record.Version != 2 || result.New.Record.Validity.NotBefore != nil {
				t.Fatalf("control rotate: %v creates=%d new=%+v", err, store.creates, result.New.Record)
			}
			if !reflect.DeepEqual(result.New.Record.Validity, rec.Validity) {
				t.Fatalf("validity not copied: %+v vs %+v", result.New.Record.Validity, rec.Validity)
			}
			if _, err := manager.MetaSet(a, "note", "x"); err != nil || store.updates != 1 {
				t.Fatalf("control meta set: %v updates=%d", err, store.updates)
			}
			if _, ok := store.keys[label]; !ok {
				t.Fatal("old generation removed")
			}
			signed, err := manager.Sign(a, digest32[:])
			if err != nil || store.signs != 1 || !signed.Signature.IsLowS() {
				t.Fatalf("control sign: %v signs=%d", err, store.signs)
			}
			if ok, err := keyvault.VerifyDigest(signed.Key.SPKI, digest32[:], signed.Signature); err != nil || !ok {
				t.Fatalf("control signature does not verify: %v %v", ok, err)
			}
		})
	}
}

// ValidateRecord applies the per-kind rows that ValidateNew cannot reach
// (it refuses every non-key kind as unsupported_kind first): a certificate
// needs both validity bounds and a complete issuer, public material carries
// no extraction policy, and each kind has its own algorithm and format
// vocabulary.
func TestValidateRecordPerKind(t *testing.T) {
	at := func(unix int64) *keyvault.Time {
		t := keyvault.NewTime(time.Unix(unix, 0))
		return &t
	}
	certificate := storedKey("cert")
	certificate.Kind = keyvault.KindCertificate
	certificate.Format = keyvault.Format{Public: "x509-der"}
	certificate.Issuer = &keyvault.Issuer{DN: "CN=x", Fingerprint: "sha256:00"}
	certificate.Validity = keyvault.Validity{NotBefore: at(10), NotAfter: at(20)}
	secret := storedKey("tok")
	secret.Kind = keyvault.KindSecret
	secret.Algorithm = keyvault.AlgorithmAES256GCM
	secret.Format = keyvault.Format{Envelope: "json"}
	publicKey := storedKey("peer")
	publicKey.Kind = keyvault.KindPublicKey
	for name, tc := range map[string]struct {
		base   keyvault.Record
		mutate func(*keyvault.Record)
		code   string
	}{
		"certificate valid":            {certificate, func(*keyvault.Record) {}, ""},
		"secret valid":                 {secret, func(*keyvault.Record) {}, ""},
		"public-key valid":             {publicKey, func(*keyvault.Record) {}, ""},
		"secret opaque der":            {secret, func(r *keyvault.Record) { r.Algorithm = keyvault.AlgorithmOpaque; r.Format.Envelope = "der" }, ""},
		"secret extraction agent":      {secret, func(r *keyvault.Record) { r.Extraction = keyvault.ExtractionAgent }, ""},
		"certificate no not_before":    {certificate, func(r *keyvault.Record) { r.Validity.NotBefore = nil }, keyvault.CodeInvalidValidity},
		"certificate no not_after":     {certificate, func(r *keyvault.Record) { r.Validity.NotAfter = nil }, keyvault.CodeInvalidValidity},
		"certificate inverted":         {certificate, func(r *keyvault.Record) { r.Validity = keyvault.Validity{NotBefore: at(20), NotAfter: at(10)} }, keyvault.CodeInvalidValidity},
		"certificate no issuer":        {certificate, func(r *keyvault.Record) { r.Issuer = nil }, keyvault.CodeInvalidIssuer},
		"certificate extraction human": {certificate, func(r *keyvault.Record) { r.Extraction = keyvault.ExtractionHuman }, keyvault.CodeInvalidExtraction},
		"certificate format spki":      {certificate, func(r *keyvault.Record) { r.Format.Public = "spki-der" }, keyvault.CodeInvalidFormat},
		"certificate format signature": {certificate, func(r *keyvault.Record) { r.Format.Signature = "ecdsa-raw" }, keyvault.CodeInvalidFormat},
		"certificate aes":              {certificate, func(r *keyvault.Record) { r.Algorithm = keyvault.AlgorithmAES256GCM }, keyvault.CodeInvalidAlgorithm},
		"secret ec-p256":               {secret, func(r *keyvault.Record) { r.Algorithm = keyvault.AlgorithmECP256 }, keyvault.CodeInvalidAlgorithm},
		"secret format public":         {secret, func(r *keyvault.Record) { r.Format.Public = "spki-der" }, keyvault.CodeInvalidFormat},
		"secret envelope unknown":      {secret, func(r *keyvault.Record) { r.Format.Envelope = "cbor" }, keyvault.CodeInvalidFormat},
		"secret not_before":            {secret, func(r *keyvault.Record) { r.Validity.NotBefore = at(10) }, keyvault.CodeInvalidValidity},
		"secret issuer":                {secret, func(r *keyvault.Record) { r.Issuer = &keyvault.Issuer{DN: "x", Fingerprint: "y"} }, keyvault.CodeInvalidIssuer},
		"public-key extraction agent":  {publicKey, func(r *keyvault.Record) { r.Extraction = keyvault.ExtractionAgent }, keyvault.CodeInvalidExtraction},
		"public-key not_before":        {publicKey, func(r *keyvault.Record) { r.Validity.NotBefore = at(10) }, keyvault.CodeInvalidValidity},
		"schema 3":                     {storedKey("k"), func(r *keyvault.Record) { r.Schema = 3 }, keyvault.CodeInvalidSchema},
		"origin imported":              {storedKey("k"), func(r *keyvault.Record) { r.Origin.Source = "imported:" + strings.Repeat("ab", 32) }, ""},
		"origin imported uppercase":    {storedKey("k"), func(r *keyvault.Record) { r.Origin.Source = "imported:" + strings.Repeat("AB", 32) }, keyvault.CodeInvalidOrigin},
	} {
		t.Run(name, func(t *testing.T) {
			rec := tc.base
			rec.Meta = map[string]any{}
			tc.mutate(&rec)
			err := keyvault.ValidateRecord(rec)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if got := code(t, err); got != tc.code {
				t.Fatalf("code = %s, want %s (%v)", got, tc.code, err)
			}
		})
	}
}
