package keyvault

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"errors"
	"math/big"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// fakeStore records every call so tests can prove which labels reached the
// store and which refusals happened before any store call. listGate, when
// set, holds List until two callers are inside it: that is the barrier the
// duplicate-race regression uses to force both Inits into the
// check-then-create window at once.
type fakeStore struct {
	mu        sync.Mutex
	keys      map[string]Item
	creates   []CreateOptions
	deletes   []string
	updates   []string
	lists     int
	createE   error
	signs     []string
	signE     error
	signHighS bool
	signers   map[string]*ecdsa.PrivateKey
	listGate  *barrier
	listDone  *barrier
	// createGate, when set, holds Create until both callers have taken
	// their List snapshot (or a short timeout): with the lock held across
	// check-and-create the peer cannot list, the gate times out and the
	// second caller sees the first key; with the lock released early the
	// peer lists an empty store while the first Create is still waiting
	// and both create. That makes the early-release mutant deterministic
	// instead of a scheduler race.
	createGate *barrier
}

// barrier releases every waiter once `need` calls arrived, or after a short
// timeout so a caller serialised by a lock (which keeps the peer from ever
// arriving) is not deadlocked.
type barrier struct {
	mu      sync.Mutex
	arrived int
	need    int
	release chan struct{}
}

func newBarrier(need int) *barrier {
	return &barrier{need: need, release: make(chan struct{})}
}

func (b *barrier) wait() {
	b.arrive()
	select {
	case <-b.release:
	case <-time.After(300 * time.Millisecond):
	}
}

// arrive counts a caller without waiting.
func (b *barrier) arrive() {
	b.mu.Lock()
	b.arrived++
	if b.arrived == b.need {
		close(b.release)
	}
	b.mu.Unlock()
}

func newFakeStore(labels ...string) *fakeStore {
	s := &fakeStore{keys: map[string]Item{}}
	for _, label := range labels {
		s.keys[label] = testItem(label)
	}
	return s
}

// tl is the test label of key/test/<purpose> version N.
func tl(purpose string, version int) string {
	return Address{Kind: KindKey, Service: TestService, Purpose: purpose, Version: version}.Label()
}

// testItem builds a schema-2 item whose record derives from the label.
func testItem(label string) Item {
	rec := testRecord(label)
	tag, _ := EncodeRecord(rec)
	return Item{Label: label, Tag: tag, SPKI: []byte{0x30, 0x59, byte(len(label))}}
}

var testOrigin = Origin{User: "tester", Host: "testhost", Tool: "mac-keyvault/test", Source: SourceGenerated}

func testRecord(label string) Record {
	addr, ok := ParseLabel(label)
	if !ok {
		addr = Address{Kind: KindKey, Service: Unknown, Purpose: Unknown, Version: 1}
	}
	return Record{Schema: SchemaVersion, Kind: addr.Kind, Service: addr.Service, Purpose: addr.Purpose, Version: addr.Version, Algorithm: AlgorithmECP256,
		Store: StoreKeychain, Extraction: ExtractionNone, Usages: []string{"sign", "verify"},
		Format: Format{Public: FormatPublicSPKIDER, Signature: FormatSignatureDERLowS}, Created: NewTime(time.Unix(1_700_000_000, 0)),
		Origin: testOrigin, Meta: map[string]any{}}
}

func (s *fakeStore) Create(opts CreateOptions) (Item, error) {
	if s.createGate != nil {
		select {
		case <-s.createGate.release:
		case <-time.After(300 * time.Millisecond):
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.creates = append(s.creates, opts)
	if s.createE != nil {
		return Item{}, s.createE
	}
	item := Item{Label: opts.Label, Tag: opts.Tag, SPKI: []byte{0x30, 0x59, byte(len(s.creates))}}
	s.keys[opts.Label] = item
	return item, nil
}

func (s *fakeStore) List() ([]Item, error) {
	if s.listGate != nil {
		s.listGate.wait()
	}
	s.mu.Lock()
	s.lists++
	var out []Item
	for _, item := range s.keys {
		out = append(out, item)
	}
	s.mu.Unlock()
	// Hold the snapshot until the peer has taken its own, so that under a
	// loaded scheduler the first caller cannot list, return and create
	// before the second has listed; only then is the race real.
	if s.listDone != nil {
		s.listDone.wait()
	}
	if s.createGate != nil {
		s.createGate.arrive()
	}
	return out, nil
}

func (s *fakeStore) Delete(label string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes = append(s.deletes, label)
	if _, ok := s.keys[label]; !ok {
		return ErrNotFound
	}
	delete(s.keys, label)
	return nil
}

func (s *fakeStore) UpdateTag(label string, tag []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, label)
	item, ok := s.keys[label]
	if !ok {
		return ErrNotFound
	}
	item.Tag = tag
	s.keys[label] = item
	return nil
}

// Sign records the call; it signs with the real P-256 key registered for
// the label by installSigner (so Manager.Sign's self-check passes), low-S,
// and is ErrNotFound otherwise. signHighS makes it hand back the high-S
// twin, the shape corecrypto may emit, to drive normalisation.
func (s *fakeStore) Sign(label string, digest []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.signs = append(s.signs, label)
	if s.signE != nil {
		return nil, s.signE
	}
	priv, ok := s.signers[label]
	if !ok {
		return nil, ErrNotFound
	}
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	// crypto/ecdsa does not normalise; the fake picks the half itself.
	sig, err := ParseSignature(der, FormatSignatureDERLowS)
	if err != nil {
		return nil, err
	}
	sig = sig.LowS()
	if s.signHighS {
		sig = Signature{R: sig.R, S: new(big.Int).Sub(p256Order, sig.S)}
	}
	return sig.Encode(FormatSignatureDERLowS)
}

// installSigner gives the item under label a real key pair: the SPKI the
// store lists and the private key its Sign uses.
func (s *fakeStore) installSigner(t *testing.T, label string) *ecdsa.PrivateKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.signers == nil {
		s.signers = map[string]*ecdsa.PrivateKey{}
	}
	s.signers[label] = priv
	item := s.keys[label]
	item.SPKI = spki
	s.keys[label] = item
	return priv
}

func (s *fakeStore) calls() (creates, deletes, updates, lists int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.creates), len(s.deletes), len(s.updates), s.lists
}

func refusalCode(t *testing.T, err error) string {
	t.Helper()
	var refusal *Refusal
	if !errors.As(err, &refusal) {
		t.Fatalf("expected a Refusal, got %v", err)
	}
	if refusal.Hint == "" {
		t.Fatalf("refusal %s carries no hint: %v", refusal.Code, err)
	}
	return refusal.Code
}

func newTestManager(t *testing.T, store Backend) *Manager {
	t.Helper()
	m := NewManager(store, FileLock{Path: filepath.Join(t.TempDir(), "init.lock")}, testOrigin)
	m.SetClock(func() time.Time { return time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC) })
	return m
}

func validSpec(purpose string) InitSpec {
	return InitSpec{Service: TestService, Purpose: purpose, Kind: KindKey, Algorithm: AlgorithmECP256, Store: StoreKeychain,
		Extraction: ExtractionNone, Usages: []string{"sign", "verify"}, Format: Format{Public: FormatPublicSPKIDER, Signature: FormatSignatureDERLowS}, Meta: map[string]any{}}
}

func mustErr(_ Key, err error) error { return err }

func addr(purpose string, version int) Address {
	return Address{Kind: KindKey, Service: TestService, Purpose: purpose, Version: version}
}

// ParseAddress accepts only <service>/<purpose> with a kind and version;
// every input without a slash — a bare name, a reverse-DNS label, a full
// label inside or outside the prefix — is foreign_label, and bad parts are
// refused with their own code. Nothing is rewritten under the prefix
// (review F1, model §1). ParseLabel inverts Label exactly.
func TestParseAddressAndLabel(t *testing.T) {
	for name, tc := range map[string]struct {
		input   string
		kind    string
		version int
		want    Address
		code    string
	}{
		"address":                {input: "kvctl/pki-root", kind: KindKey, want: Address{Kind: KindKey, Service: "kvctl", Purpose: "pki-root"}},
		"address with version":   {input: "kvctl/pki-root", kind: KindKey, version: 3, want: Address{Kind: KindKey, Service: "kvctl", Purpose: "pki-root", Version: 3}},
		"certificate kind":       {input: "kvctl/pki-root", kind: KindCertificate, want: Address{Kind: KindCertificate, Service: "kvctl", Purpose: "pki-root"}},
		"full own label":         {input: tl("x", 1), kind: KindKey, code: CodeForeignLabel},
		"rev1 label":             {input: LabelPrefix + "signer", kind: KindKey, code: CodeForeignLabel},
		"foreign reverse dns":    {input: "com.apple.security.key", kind: KindKey, code: CodeForeignLabel},
		"foreign lookalike":      {input: "works.relux.mac-keyvaultX.key", kind: KindKey, code: CodeForeignLabel},
		"foreign sibling":        {input: "works.relux.other.key", kind: KindKey, code: CodeForeignLabel},
		"bare short name":        {input: "signer", kind: KindKey, code: CodeForeignLabel},
		"bare prefix":            {input: LabelPrefix, kind: KindKey, code: CodeForeignLabel},
		"empty":                  {input: "", kind: KindKey, code: CodeForeignLabel},
		"uppercase service":      {input: "Kvctl/pki", kind: KindKey, code: CodeInvalidService},
		"service too long":       {input: strings.Repeat("a", 41) + "/pki", kind: KindKey, code: CodeInvalidService},
		"empty purpose":          {input: "kvctl/", kind: KindKey, code: CodeInvalidPurpose},
		"dotted purpose":         {input: "kvctl/pki.root", kind: KindKey, code: CodeInvalidPurpose},
		"versioned purpose text": {input: "kvctl/pki.v2", kind: KindKey, code: CodeInvalidPurpose},
		"two slashes":            {input: "a/b/c", kind: KindKey, code: CodeInvalidPurpose},
		"unknown kind":           {input: "kvctl/pki", kind: "keypair", code: CodeInvalidKind},
		"negative version":       {input: "kvctl/pki", kind: KindKey, version: -1, code: CodeInvalidPurpose},
	} {
		t.Run(name, func(t *testing.T) {
			got, err := ParseAddress(tc.input, tc.kind, tc.version)
			if tc.code != "" {
				if refusalCode(t, err) != tc.code {
					t.Fatalf("code = %v, want %s", err, tc.code)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("ParseAddress(%q) = %+v, %v; want %+v", tc.input, got, err, tc.want)
			}
		})
	}
	if got := (Address{Kind: KindKey, Service: "kvctl", Purpose: "pki-root", Version: 1}).Label(); got != LabelPrefix+"key.kvctl.pki-root.v1" {
		t.Fatalf("label = %s", got)
	}
	for label, want := range map[string]Address{
		LabelPrefix + "key.kvctl.pki-root.v1":     {Kind: KindKey, Service: "kvctl", Purpose: "pki-root", Version: 1},
		LabelPrefix + "certificate.kvctl.pki.v12": {Kind: KindCertificate, Service: "kvctl", Purpose: "pki", Version: 12},
	} {
		if got, ok := ParseLabel(label); !ok || got != want {
			t.Fatalf("ParseLabel(%s) = %+v %v", label, got, ok)
		}
	}
	for _, bad := range []string{LabelPrefix + "kvctl.pki-root.v1", LabelPrefix + "key.kvctl.pki-root", LabelPrefix + "key.kvctl.pki-root.v0", LabelPrefix + "key.kvctl.pki-root.vx", LabelPrefix + "keypair.kvctl.pki.v1", LabelPrefix + "key.Kvctl.pki.v1", "com.apple.key.a.b.v1", LabelPrefix + "signer", ""} {
		if _, ok := ParseLabel(bad); ok {
			t.Fatalf("ParseLabel(%q) accepted", bad)
		}
	}
	for _, label := range []string{tl("x", 1), LabelPrefix + "secret.test.tok.v3", LabelPrefix + "test.rev1-leftover"} {
		if !IsTestLabel(label) {
			t.Fatalf("test label %s not recognised", label)
		}
	}
	for _, label := range []string{LabelPrefix + "key.kvctl.pki.v1", LabelPrefix + "test.", LabelPrefix, "com.apple.key"} {
		if IsTestLabel(label) {
			t.Fatalf("non-test label %s admitted", label)
		}
	}
}

// RequireOwnLabel admits only labels strictly inside LabelPrefix; the bare
// prefix, lookalike prefixes, and other namespaces are refused.
func TestRequireOwnLabel(t *testing.T) {
	for _, label := range []string{LabelPrefix + "a", tl("x", 2)} {
		if err := RequireOwnLabel(label); err != nil {
			t.Fatalf("own label %q refused: %v", label, err)
		}
	}
	for _, label := range []string{"", LabelPrefix, "works.relux.other.a", "works.relux.mac-keyvaultX.a", "com.apple.security.key", " " + LabelPrefix + "a"} {
		if refusalCode(t, RequireOwnLabel(label)) != CodeForeignLabel {
			t.Fatalf("foreign label %q was admitted", label)
		}
	}
}

// Record.Label derives prefix.kind.service.purpose.vN and the record
// round-trips through the tag encoding with origin, null issuer, meta value
// types and timestamps intact; a v1 tag decodes as schema 1 with
// service/purpose/kind/algorithm unknown, an absent tag is schema 0 without
// a problem, and a malformed tag is schema 0 with a problem — none of them
// is upgraded.
func TestRecordEncodingAndLegacyTags(t *testing.T) {
	rec := testRecord(tl("purp", 1))
	rec.Title, rec.Description = "t", "d"
	rec.Meta = map[string]any{"owner": "alexis", "n": 1.5, "flag": true}
	notAfter := NewTime(time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC))
	rec.Validity.NotAfter = &notAfter
	if rec.Label() != LabelPrefix+"key.test.purp.v1" {
		t.Fatalf("label = %s", rec.Label())
	}
	rec.Version = 2
	if rec.Label() != LabelPrefix+"key.test.purp.v2" {
		t.Fatalf("v2 label = %s", rec.Label())
	}
	tag, err := EncodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	var generic map[string]any
	if err := json.Unmarshal(tag, &generic); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"schema", "kind", "service", "purpose", "version", "title", "description", "algorithm", "store", "extraction", "usages", "format", "created", "origin", "issuer", "validity", "meta"} {
		if _, ok := generic[field]; !ok {
			t.Fatalf("encoded record lacks %s: %s", field, tag)
		}
	}
	for _, derived := range []string{"label", "fingerprint", "exposure", "operations"} {
		if _, ok := generic[derived]; ok {
			t.Fatalf("derived field %s was stored: %s", derived, tag)
		}
	}
	if generic["issuer"] != nil || generic["origin"].(map[string]any)["source"] != SourceGenerated || generic["format"].(map[string]any)["envelope"] != nil {
		t.Fatalf("origin/issuer/format: %s", tag)
	}
	if generic["created"] != "2023-11-14T22:13:20Z" || generic["validity"].(map[string]any)["not_before"] != nil || generic["validity"].(map[string]any)["not_after"] != "2027-01-01T00:00:00Z" {
		t.Fatalf("timestamps: %s", tag)
	}
	decoded, problem := DecodeRecord(tag)
	if problem != "" || decoded.Schema != 2 || decoded.Service != TestService || decoded.Purpose != "purp" || decoded.Version != 2 || decoded.Meta["n"] != json.Number("1.5") || decoded.Meta["flag"] != true || !decoded.Created.Equal(rec.Created.Time) || decoded.Validity.NotAfter == nil || decoded.Origin != testOrigin || decoded.Issuer != nil {
		t.Fatalf("decoded = %+v (%s)", decoded, problem)
	}

	legacy, problem := DecodeRecord([]byte("mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z"))
	if problem != "" || legacy.Schema != 1 || legacy.Service != Unknown || legacy.Purpose != Unknown || legacy.Kind != Unknown || legacy.Algorithm != Unknown || legacy.Store != StoreKeychain || !legacy.Created.Equal(time.Date(2026, 9, 15, 8, 0, 0, 0, time.UTC)) {
		t.Fatalf("legacy = %+v (%s)", legacy, problem)
	}
	if legacy, _ := DecodeRecord([]byte("mac-keyvault/1 store=tpm created=garbage")); legacy.Store != StoreUnknown || !legacy.Created.IsZero() {
		t.Fatalf("legacy with bad fields = %+v", legacy)
	}
	absent, problem := DecodeRecord(nil)
	if problem != "" || absent.Schema != 0 || absent.Store != StoreUnknown || absent.Service != Unknown {
		t.Fatalf("absent = %+v (%s)", absent, problem)
	}
	// A schema-2 record followed by a second document, token or garbage is
	// a read failure, not a readable record (review F12); whitespace around
	// the single document stays readable (positive control below).
	trailing := [][]byte{
		append(append([]byte{}, tag...), []byte(` {"schema":2,"store":"enclave"}`)...),
		append(append([]byte{}, tag...), []byte("\n1")...),
		append(append([]byte{}, tag...), '}'),
		append(append([]byte{}, tag...), ']'),
		append(append([]byte{}, tag...), []byte(" null")...),
	}
	for _, bad := range append([][]byte{[]byte("{not json"), []byte(`{"schema":3}`), []byte("something-else")}, trailing...) {
		unreadable, problem := DecodeRecord(bad)
		if problem == "" || unreadable.Schema != 0 || unreadable.Store != StoreUnknown {
			t.Fatalf("DecodeRecord(%q) = %+v (%q): a read failure must not look like an absence", bad, unreadable, problem)
		}
	}
	padded, problem := DecodeRecord(append(append([]byte("\n  "), tag...), []byte("\n\t\n")...))
	if problem != "" || padded.Schema != 2 || padded.Version != 2 {
		t.Fatalf("whitespace-padded single record = %+v (%s)", padded, problem)
	}
	// A member the schema does not define, at the top level or inside a
	// nested struct, is a read failure (review F14); the same name inside
	// meta is an ordinary open-map key and stays readable.
	withMember := func(path ...string) []byte {
		var doc map[string]any
		if err := json.Unmarshal(tag, &doc); err != nil {
			t.Fatal(err)
		}
		node := doc
		for _, key := range path[:len(path)-1] {
			node = node[key].(map[string]any)
		}
		node[path[len(path)-1]] = "deny"
		out, _ := json.Marshal(doc)
		return out
	}
	for _, path := range [][]string{{"future_top_level_policy"}, {"format", "future_format_policy"}, {"origin", "pid"}, {"validity", "renew_after"}} {
		unreadable, problem := DecodeRecord(withMember(path...))
		if !strings.Contains(problem, "unknown field") || unreadable.Schema != 0 || unreadable.Store != StoreUnknown {
			t.Fatalf("DecodeRecord with unknown member %v = %+v (%q): an undefined field must be a read failure, not erased", path, unreadable, problem)
		}
	}
	open, problem := DecodeRecord(withMember("meta", "future_top_level_policy"))
	if problem != "" || open.Meta["future_top_level_policy"] != "deny" {
		t.Fatalf("meta member = %+v (%s): meta is an open map", open.Meta, problem)
	}
}

// ValidateNew refuses every invalid or unsupported field with its own code
// and admits the valid spec plus the literal extraction human/agent choices
// for a key (positive controls). Each row names the exact class the gate
// must reject.
func TestValidateNew(t *testing.T) {
	base := func() Record {
		return Record{Schema: SchemaVersion, Kind: KindKey, Service: "kvctl", Purpose: "pki-root", Version: 1, Algorithm: AlgorithmECP256, Store: StoreKeychain,
			Extraction: ExtractionNone, Usages: []string{"sign"}, Format: Format{Public: FormatPublicSPKIDER, Signature: FormatSignatureDERLowS},
			Created: NewTime(time.Unix(1_700_000_000, 0)), Origin: testOrigin, Meta: map[string]any{}}
	}
	if err := ValidateNew(base()); err != nil {
		t.Fatalf("valid record refused: %v", err)
	}
	// The title bound is 80 characters, not bytes: 80 two-byte letters
	// (160 bytes) pass, 81 characters of either width fail (review F7).
	armenian := strings.Repeat("\u0561", 80)
	rec := base()
	rec.Title = armenian
	if err := ValidateNew(rec); err != nil || len(armenian) != 160 {
		t.Fatalf("80-character title (%d bytes) refused: %v", len(armenian), err)
	}
	rec.Title = strings.Repeat("x", 80)
	if err := ValidateNew(rec); err != nil {
		t.Fatalf("80 ASCII characters refused: %v", err)
	}
	for _, extraction := range []string{ExtractionHuman, ExtractionAgent} {
		rec := base()
		rec.Extraction = extraction
		if err := ValidateNew(rec); err != nil {
			t.Fatalf("extraction %s refused for a key: %v", extraction, err)
		}
	}
	for name, tc := range map[string]struct {
		mutate func(*Record)
		code   string
	}{
		"service uppercase":  {func(r *Record) { r.Service = "KVCTL" }, CodeInvalidService},
		"service empty":      {func(r *Record) { r.Service = "" }, CodeInvalidService},
		"service dot":        {func(r *Record) { r.Service = "a.b" }, CodeInvalidService},
		"service slash":      {func(r *Record) { r.Service = "a/b" }, CodeInvalidService},
		"service too long":   {func(r *Record) { r.Service = strings.Repeat("a", 41) }, CodeInvalidService},
		"purpose underscore": {func(r *Record) { r.Purpose = "pki_root" }, CodeInvalidPurpose},
		"purpose empty":      {func(r *Record) { r.Purpose = "" }, CodeInvalidPurpose},
		"kind unknown":       {func(r *Record) { r.Kind = "keypair" }, CodeInvalidKind},
		"kind secret unsupported": {func(r *Record) {
			r.Kind = KindSecret
			r.Algorithm = AlgorithmAES256GCM
			r.Format = Format{Envelope: "json"}
		}, CodeUnsupportedKind},
		"kind certificate":         {func(r *Record) { r.Kind = KindCertificate; r.Format = Format{Public: "x509-der"} }, CodeUnsupportedKind},
		"algorithm unknown":        {func(r *Record) { r.Algorithm = "p256" }, CodeInvalidAlgorithm},
		"algorithm aes for key":    {func(r *Record) { r.Algorithm = AlgorithmAES256GCM }, CodeInvalidAlgorithm},
		"algorithm opaque for key": {func(r *Record) { r.Algorithm = AlgorithmOpaque }, CodeInvalidAlgorithm},
		"algorithm ed25519":        {func(r *Record) { r.Algorithm = AlgorithmEd25519 }, CodeUnsupportedAlgorithm},
		"algorithm p384 reserved":  {func(r *Record) { r.Algorithm = AlgorithmECP384 }, CodeUnsupportedAlgorithm},
		"algorithm rsa reserved":   {func(r *Record) { r.Algorithm = AlgorithmRSA3072 }, CodeUnsupportedAlgorithm},
		"store tpm":                {func(r *Record) { r.Store = "tpm" }, CodeUnsupportedStore},
		"usages empty":             {func(r *Record) { r.Usages = nil }, CodeInvalidUsages},
		"usage unknown":            {func(r *Record) { r.Usages = []string{"sign", "export"} }, CodeInvalidUsages},
		"usage duplicate":          {func(r *Record) { r.Usages = []string{"sign", "sign"} }, CodeInvalidUsages},
		"format public unknown":    {func(r *Record) { r.Format.Public = "x509-der" }, CodeInvalidFormat},
		"format signature unknown": {func(r *Record) { r.Format.Signature = "rsa-pss" }, CodeInvalidFormat},
		"format envelope for key":  {func(r *Record) { r.Format.Envelope = "json" }, CodeInvalidFormat},
		"extraction unknown":       {func(r *Record) { r.Extraction = "always" }, CodeInvalidExtraction},
		"extraction human enclave": {func(r *Record) { r.Extraction = ExtractionHuman; r.Store = StoreEnclave }, CodeInvalidExtraction},
		"extraction agent enclave": {func(r *Record) { r.Extraction = ExtractionAgent; r.Store = StoreEnclave }, CodeInvalidExtraction},
		"title too long":           {func(r *Record) { r.Title = strings.Repeat("x", 81) }, CodeInvalidTitle},
		"title 81 armenian":        {func(r *Record) { r.Title = strings.Repeat("\u0561", 81) }, CodeInvalidTitle},
		"issuer on key":            {func(r *Record) { r.Issuer = &Issuer{DN: "CN=x", Fingerprint: "sha256:00"} }, CodeInvalidIssuer},
		"issuer dn only on key":    {func(r *Record) { r.Issuer = &Issuer{DN: "CN=x"} }, CodeInvalidIssuer},
		"issuer empty on key":      {func(r *Record) { r.Issuer = &Issuer{} }, CodeInvalidIssuer},
		// A key never carries not_before (certificate-derived); the F13
		// shape is a non-null not_before with null not_after.
		"validity not_before on key": {func(r *Record) {
			a := NewTime(time.Unix(10, 0))
			r.Validity = Validity{NotBefore: &a}
		}, CodeInvalidValidity},
		"created null":        {func(r *Record) { r.Created = Time{} }, CodeInvalidCreated},
		"origin source bogus": {func(r *Record) { r.Origin.Source = "typed" }, CodeInvalidOrigin},
		"origin host empty":   {func(r *Record) { r.Origin.Host = "" }, CodeInvalidOrigin},
		"version zero":        {func(r *Record) { r.Version = 0 }, CodeInvalidVersion},
		"schema 1":            {func(r *Record) { r.Schema = 1 }, CodeInvalidSchema},
		"validity inverted": {func(r *Record) {
			a, b := NewTime(time.Unix(20, 0)), NewTime(time.Unix(10, 0))
			r.Validity = Validity{NotBefore: &a, NotAfter: &b}
		}, CodeInvalidValidity},
		"meta reserved schema":        {func(r *Record) { r.Meta = map[string]any{"schema": 3} }, CodeInvalidMeta},
		"meta reserved fingerprint":   {func(r *Record) { r.Meta = map[string]any{"fingerprint": "x"} }, CodeInvalidMeta},
		"meta reserved operations":    {func(r *Record) { r.Meta = map[string]any{"operations": "x"} }, CodeInvalidMeta},
		"meta reserved label":         {func(r *Record) { r.Meta = map[string]any{"label": "x"} }, CodeInvalidMeta},
		"meta reserved exposure":      {func(r *Record) { r.Meta = map[string]any{"exposure": "never"} }, CodeInvalidMeta},
		"meta reserved origin":        {func(r *Record) { r.Meta = map[string]any{"origin": "x"} }, CodeInvalidMeta},
		"meta reserved user_presence": {func(r *Record) { r.Meta = map[string]any{"user_presence": true} }, CodeInvalidMeta},
		"meta empty name":             {func(r *Record) { r.Meta = map[string]any{"": "x"} }, CodeInvalidMeta},
		"meta nested object":          {func(r *Record) { r.Meta = map[string]any{"owner": map[string]any{"a": 1}} }, CodeInvalidMeta},
		"meta list":                   {func(r *Record) { r.Meta = map[string]any{"owner": []any{"a"}} }, CodeInvalidMeta},
		"meta null":                   {func(r *Record) { r.Meta = map[string]any{"owner": nil} }, CodeInvalidMeta},
	} {
		t.Run(name, func(t *testing.T) {
			rec := base()
			tc.mutate(&rec)
			if code := refusalCode(t, ValidateNew(rec)); code != tc.code {
				t.Fatalf("code = %s, want %s", code, tc.code)
			}
		})
	}
	// Every reserved name is refused inside meta, and a free name with each
	// supported value type is admitted; meta.checksum stays free for secrets.
	for _, name := range ReservedMetaNames {
		if refusalCode(t, ValidateMetaEntry(name, "x")) != CodeInvalidMeta {
			t.Fatalf("reserved %q admitted", name)
		}
	}
	for _, value := range []any{"s", 1, int64(2), 3.5, true, json.Number("4")} {
		if err := ValidateMetaEntry("owner", value); err != nil {
			t.Fatalf("meta value %T refused: %v", value, err)
		}
	}
	if err := ValidateMetaEntry("checksum", "sha256:abc"); err != nil {
		t.Fatalf("meta.checksum refused: %v", err)
	}
}

// validateIssuer is the kind-specific invariant: a key, public-key or
// secret must carry issuer null; a certificate must carry both dn and
// fingerprint. Exercised directly because ValidateNew refuses every
// non-key kind as unsupported_kind before reaching it (review F8).
func TestValidateIssuerPerKind(t *testing.T) {
	full := &Issuer{DN: "CN=x", Fingerprint: "sha256:00"}
	for name, tc := range map[string]struct {
		kind   string
		issuer *Issuer
		code   string
	}{
		"key null":                {KindKey, nil, ""},
		"public-key null":         {KindPublicKey, nil, ""},
		"secret null":             {KindSecret, nil, ""},
		"key issuer":              {KindKey, full, CodeInvalidIssuer},
		"public-key issuer":       {KindPublicKey, full, CodeInvalidIssuer},
		"secret issuer":           {KindSecret, full, CodeInvalidIssuer},
		"certificate full":        {KindCertificate, full, ""},
		"certificate null":        {KindCertificate, nil, CodeInvalidIssuer},
		"certificate dn only":     {KindCertificate, &Issuer{DN: "CN=x"}, CodeInvalidIssuer},
		"certificate fingerprint": {KindCertificate, &Issuer{Fingerprint: "sha256:00"}, CodeInvalidIssuer},
	} {
		t.Run(name, func(t *testing.T) {
			err := validateIssuer(tc.kind, tc.issuer)
			if tc.code == "" {
				if err != nil {
					t.Fatalf("refused: %v", err)
				}
				return
			}
			if code := refusalCode(t, err); code != tc.code {
				t.Fatalf("code = %s, want %s", code, tc.code)
			}
		})
	}
}

// Init refuses an invalid spec and --generate for a key before any store
// call, refuses a duplicate (kind, service, purpose) in any version before
// create, and creates a fresh record with schema 2, version 1, the .v1
// label, origin generated, null issuer and the clock's creation time.
func TestManagerInitValidatesThenGatesDuplicates(t *testing.T) {
	store := newFakeStore(tl("dup", 1), tl("rotated", 2))
	manager := newTestManager(t, store)

	bad := validSpec("x")
	bad.Algorithm = AlgorithmEd25519
	if code := refusalCode(t, mustErr(manager.Init(bad))); code != CodeUnsupportedAlgorithm {
		t.Fatalf("code = %s", code)
	}
	generate := validSpec("x")
	generate.Generate = "token:32"
	if code := refusalCode(t, mustErr(manager.Init(generate))); code != CodeInvalidGenerate {
		t.Fatalf("generate code = %s", code)
	}
	if creates, _, _, lists := store.calls(); creates != 0 || lists != 0 {
		t.Fatalf("invalid spec reached the store: creates=%d lists=%d", creates, lists)
	}
	if code := refusalCode(t, mustErr(manager.Init(validSpec("dup")))); code != CodeDuplicate {
		t.Fatalf("code = %s", code)
	}
	if code := refusalCode(t, mustErr(manager.Init(validSpec("rotated")))); code != CodeDuplicate {
		t.Fatalf("rotated generation not treated as duplicate: %s", code)
	}
	if creates, _, _, _ := store.calls(); creates != 0 {
		t.Fatalf("duplicate reached the store: %+v", store.creates)
	}

	spec := validSpec("fresh")
	spec.Title, spec.Description, spec.Extraction = "Fresh", "a fresh key", ExtractionAgent
	spec.Meta = map[string]any{"owner": "alexis"}
	key, err := manager.Init(spec)
	if err != nil {
		t.Fatal(err)
	}
	if key.Label != tl("fresh", 1) || len(store.creates) != 1 || store.creates[0].Label != key.Label || store.creates[0].Store != StoreKeychain || store.creates[0].UserPresence {
		t.Fatalf("create options = %+v", store.creates)
	}
	rec := key.Record
	if rec.Schema != 2 || rec.Version != 1 || rec.Origin != testOrigin || rec.Issuer != nil || rec.Extraction != ExtractionAgent || !rec.Created.Equal(time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC)) || rec.Meta["owner"] != "alexis" || rec.Title != "Fresh" || key.Fingerprint() == "" {
		t.Fatalf("created record = %+v", rec)
	}
	stored, problem := DecodeRecord(store.keys[key.Label].Tag)
	if problem != "" || stored.Service != TestService || stored.Purpose != "fresh" || stored.Kind != KindKey {
		t.Fatalf("stored tag = %+v (%s)", stored, problem)
	}
}

// Two Inits of the same address that both reach the check-then-create window
// (a barrier in List holds each until the other arrives, and Create waits
// until both have listed) produce exactly one create under the file lock;
// the positive control without the lock produces two, proving the barriers
// really force the race (review F2). Bound: both callers are in one process
// with separate lock descriptors; the cross-process shape is the reviewer's
// two-binary race.
func TestManagerInitDuplicateRefusalIsAtomic(t *testing.T) {
	race := func(t *testing.T, lockA, lockB Locker) (creates int, errs []error) {
		store := newFakeStore()
		store.listGate, store.listDone, store.createGate = newBarrier(2), newBarrier(2), newBarrier(2)
		managers := []*Manager{NewManager(store, lockA, testOrigin), NewManager(store, lockB, testOrigin)}
		var wg sync.WaitGroup
		results := make([]error, 2)
		for i, manager := range managers {
			wg.Add(1)
			go func(i int, manager *Manager) {
				defer wg.Done()
				_, results[i] = manager.Init(validSpec("race"))
			}(i, manager)
		}
		wg.Wait()
		creates, _, _, _ = store.calls()
		return creates, results
	}

	path := filepath.Join(t.TempDir(), "init.lock")
	creates, errs := race(t, FileLock{Path: path}, FileLock{Path: path})
	if creates != 1 {
		t.Fatalf("locked race created %d keys, want 1: %v", creates, errs)
	}
	refused := 0
	for _, err := range errs {
		var refusal *Refusal
		if errors.As(err, &refusal) && refusal.Code == CodeDuplicate {
			refused++
		} else if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	}
	if refused != 1 {
		t.Fatalf("want exactly one duplicate refusal, got %d: %v", refused, errs)
	}

	creates, errs = race(t, NoLock{}, NoLock{})
	if creates != 2 || errs[0] != nil || errs[1] != nil {
		t.Fatalf("positive control: without the lock the race must admit both creates, got creates=%d errs=%v", creates, errs)
	}
}

// A -34018 from the store on an --enclave or --user-presence request becomes
// missing_entitlement: an operational failure (exit-1 class) carrying the
// OSStatus and the provisioning-profile hint; exactly one create attempt is
// made and no keychain fallback create follows.
func TestManagerInitMissingEntitlementIsExplicit(t *testing.T) {
	for name, tc := range map[string]struct {
		store        StoreKind
		userPresence bool
	}{
		"enclave":       {store: StoreEnclave},
		"user-presence": {store: StoreKeychain, userPresence: true},
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeStore()
			store.createE = &StatusError{Op: "create", Status: errSecMissingEntitlement}
			spec := validSpec("se")
			spec.Store, spec.UserPresence = tc.store, tc.userPresence
			_, err := newTestManager(t, store).Init(spec)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Code != CodeMissingEntitlement || !refusal.Failure || refusal.Status != errSecMissingEntitlement {
				t.Fatalf("err = %v, want missing_entitlement failure with -34018", err)
			}
			if !strings.Contains(refusal.Hint, "provisioning profile") || !strings.Contains(refusal.Hint, "login keychain") {
				t.Fatalf("hint lacks the documented remedy: %s", refusal.Hint)
			}
			if len(store.creates) != 1 || store.creates[0].Store != tc.store || store.creates[0].UserPresence != tc.userPresence {
				t.Fatalf("store creates = %+v; want exactly the requested shape and no fallback", store.creates)
			}
			if len(store.keys) != 0 {
				t.Fatalf("a key was created despite the refusal: %v", store.keys)
			}
		})
	}
}

// Other Security errors become the security code: an operational failure
// with the OSStatus name in the message, never a policy refusal.
func TestManagerInitOtherStatusErrorIsSecurityFailure(t *testing.T) {
	store := newFakeStore()
	store.createE = &StatusError{Op: "create", Status: -25293}
	_, err := newTestManager(t, store).Init(validSpec("x"))
	var refusal *Refusal
	if !errors.As(err, &refusal) || refusal.Code != CodeSecurity || !refusal.Failure || refusal.Status != -25293 || !strings.Contains(refusal.Message, "errSecAuthFailed") {
		t.Fatalf("err = %v", err)
	}
}

// Delete refuses without confirmation before the store is called; a
// confirmed address deletes the newest generation or the exact version; a
// confirmed missing address is ErrNotFound naming the generations that do
// exist.
func TestManagerDeleteGates(t *testing.T) {
	own, ownV2 := tl("victim", 1), tl("victim", 2)
	for name, tc := range map[string]struct {
		addr      Address
		confirmed bool
		code      string
		notFound  bool
		deleted   string
	}{
		"own unconfirmed":         {addr: addr("victim", 0), code: CodeConfirmationRequired},
		"own version unconfirmed": {addr: addr("victim", 1), code: CodeConfirmationRequired},
		"own confirmed newest":    {addr: addr("victim", 0), confirmed: true, deleted: ownV2},
		"own confirmed version":   {addr: addr("victim", 1), confirmed: true, deleted: own},
		"own missing confirmed":   {addr: addr("missing", 0), confirmed: true, notFound: true},
		"own missing version":     {addr: addr("victim", 7), confirmed: true, notFound: true},
		"other kind confirmed":    {addr: Address{Kind: KindCertificate, Service: TestService, Purpose: "victim"}, confirmed: true, notFound: true},
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeStore(own, ownV2, "com.apple.security.key")
			label, err := newTestManager(t, store).Delete(tc.addr, tc.confirmed)
			switch {
			case tc.code != "":
				if refusalCode(t, err) != tc.code {
					t.Fatalf("code = %v, want %s", err, tc.code)
				}
				if _, _, _, lists := store.calls(); lists != 0 {
					t.Fatal("unconfirmed delete listed the store")
				}
			case tc.notFound:
				if !errors.Is(err, ErrNotFound) {
					t.Fatalf("err = %v, want ErrNotFound", err)
				}
				var nf *NotFoundError
				if !errors.As(err, &nf) || (tc.addr.Purpose == "victim" && !strings.Contains(nf.Hint(), "key v1, key v2")) {
					t.Fatalf("not-found hint = %v", err)
				}
			case err != nil:
				t.Fatal(err)
			default:
				if label != tc.deleted {
					t.Fatalf("deleted %s, want %s", label, tc.deleted)
				}
			}
			for _, deleted := range store.deletes {
				if deleted != tc.deleted {
					t.Fatalf("store delete %q, want only %q", deleted, tc.deleted)
				}
			}
			if _, ok := store.keys["com.apple.security.key"]; !ok {
				t.Fatal("foreign key deleted")
			}
			for _, survivor := range []string{own, ownV2} {
				if _, ok := store.keys[survivor]; !ok && survivor != tc.deleted {
					t.Fatalf("%s deleted by %s", survivor, name)
				}
			}
		})
	}
}

// Rotate creates version N+1 of the newest generation with the record
// copied (title, usages, format, extraction, meta, validity, user presence)
// and a fresh origin/created, keeps every existing version, follows the
// family from any version given, and reports a missing address as
// ErrNotFound.
func TestManagerRotate(t *testing.T) {
	for name, tc := range map[string]struct {
		existing []string
		addr     Address
		wantNew  string
		wantOld  string
		notFound bool
	}{
		"first rotation":  {existing: []string{tl("rot", 1)}, addr: addr("rot", 0), wantNew: tl("rot", 2), wantOld: tl("rot", 1)},
		"second rotation": {existing: []string{tl("rot", 1), tl("rot", 2)}, addr: addr("rot", 0), wantNew: tl("rot", 3), wantOld: tl("rot", 2)},
		"gap in versions": {existing: []string{tl("rot", 1), tl("rot", 5)}, addr: addr("rot", 0), wantNew: tl("rot", 6), wantOld: tl("rot", 5)},
		"older version":   {existing: []string{tl("rot", 1), tl("rot", 2)}, addr: addr("rot", 1), wantNew: tl("rot", 3), wantOld: tl("rot", 2)},
		"base deleted":    {existing: []string{tl("rot", 2)}, addr: addr("rot", 0), wantNew: tl("rot", 3), wantOld: tl("rot", 2)},
		"sibling purpose": {existing: []string{tl("rot", 1), tl("rotx", 1)}, addr: addr("rot", 0), wantNew: tl("rot", 2), wantOld: tl("rot", 1)},
		"missing":         {existing: nil, addr: addr("rot", 0), notFound: true},
		"only sibling":    {existing: []string{tl("rotx", 1)}, addr: addr("rot", 0), notFound: true},
		"other kind":      {existing: []string{tl("rot", 1)}, addr: Address{Kind: KindSecret, Service: TestService, Purpose: "rot"}, notFound: true},
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeStore(tc.existing...)
			for label, item := range store.keys {
				rec, _ := DecodeRecord(item.Tag)
				rec.Title, rec.Usages, rec.Meta, rec.Extraction = "titled", []string{"sign", "decrypt"}, map[string]any{"pki": "bsim"}, ExtractionHuman
				item.Tag, _ = EncodeRecord(rec)
				store.keys[label] = item
			}
			manager := newTestManager(t, store)
			result, err := manager.Rotate(tc.addr)
			if tc.notFound {
				if !errors.Is(err, ErrNotFound) || len(store.creates) != 0 {
					t.Fatalf("err = %v, creates = %v", err, store.creates)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.New.Label != tc.wantNew || result.Old.Label != tc.wantOld {
				t.Fatalf("rotate = %s -> %s, want %s -> %s", result.Old.Label, result.New.Label, tc.wantOld, tc.wantNew)
			}
			rec := result.New.Record
			if rec.Version != result.Old.Record.Version+1 || rec.Title != "titled" || strings.Join(rec.Usages, ",") != "sign,decrypt" || rec.Meta["pki"] != "bsim" || rec.Extraction != ExtractionHuman || rec.Origin != testOrigin || rec.Created.Equal(result.Old.Record.Created.Time) || rec.Store != StoreKeychain {
				t.Fatalf("new record = %+v, old = %+v", rec, result.Old.Record)
			}
			for _, label := range tc.existing {
				if _, ok := store.keys[label]; !ok {
					t.Fatalf("rotate removed %s", label)
				}
			}
			if len(store.deletes) != 0 {
				t.Fatalf("rotate deleted %v", store.deletes)
			}
		})
	}
}

// Rotate refuses, with no create, every key whose store or policy is not
// known: a schema-1 tag, an absent tag, an unreadable tag, a schema-2 record
// with an unknown store, and a record that contradicts its label. The
// keychain is never assumed (review F4).
func TestManagerRotateRefusesUnknownMetadata(t *testing.T) {
	label := tl("origin", 1)
	unknownStore := testRecord(label)
	unknownStore.Store = StoreUnknown
	unknownStoreTag, _ := EncodeRecord(unknownStore)
	mismatch := testRecord(tl("other", 1))
	mismatchTag, _ := EncodeRecord(mismatch)
	// A schema-2 key record carrying a forged non-null issuer must not be
	// reproduced into the next generation (review F8).
	forgedIssuer := testRecord(label)
	forgedIssuer.Issuer = &Issuer{DN: "CN=forged", Fingerprint: "sha256:00"}
	forgedIssuerTag, _ := EncodeRecord(forgedIssuer)
	// A key record carrying a forged non-null not_before with null
	// not_after passes the ordering check alone; the kind-specific
	// nullability row must refuse it (review F13).
	forgedNotBefore := testRecord(label)
	notBefore := NewTime(time.Unix(1_800_000_000, 0))
	forgedNotBefore.Validity = Validity{NotBefore: &notBefore}
	forgedNotBeforeTag, _ := EncodeRecord(forgedNotBefore)
	// A valid schema-2 record followed by a second JSON document, token or
	// garbage in the tag is unreadable, not readable (review F12).
	validTag, _ := EncodeRecord(testRecord(label))
	enclaveShadow := testRecord(label)
	enclaveShadow.Store = StoreEnclave
	enclaveShadowTag, _ := EncodeRecord(enclaveShadow)
	for name, tag := range map[string][]byte{
		"forged issuer":     forgedIssuerTag,
		"forged not_before": forgedNotBeforeTag,
		"trailing document": append(append(append([]byte{}, validTag...), ' '), enclaveShadowTag...),
		"trailing token":    append(append([]byte{}, validTag...), []byte("\n1")...),
		"trailing garbage":  append(append([]byte{}, validTag...), '}'),
		"schema 1 keychain": []byte("mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z"),
		"schema 1 enclave":  []byte("mac-keyvault/1 store=enclave created=2026-09-15T08:00:00Z"),
		"absent tag":        nil,
		"unreadable tag":    []byte("{broken"),
		"unknown store":     unknownStoreTag,
		"label mismatch":    mismatchTag,
	} {
		t.Run(name, func(t *testing.T) {
			store := newFakeStore()
			store.keys[label] = Item{Label: label, Tag: tag, SPKI: []byte{0x30}}
			manager := newTestManager(t, store)
			_, err := manager.Rotate(addr("origin", 0))
			if code := refusalCode(t, err); code != CodeMetadataUnknown {
				t.Fatalf("code = %s, want %s", code, CodeMetadataUnknown)
			}
			if name == "forged not_before" && !strings.Contains(err.Error(), CodeInvalidValidity) {
				t.Fatalf("forged not_before refused for another reason: %v", err)
			}
			if len(store.creates) != 0 || len(store.keys) != 1 || !bytes.Equal(store.keys[label].Tag, tag) {
				t.Fatalf("rotate guessed a store or touched the old item: creates=%+v tag=%q", store.creates, store.keys[label].Tag)
			}
			// The same key is still readable and reported with its real schema.
			key, err := manager.Describe(addr("origin", 0))
			if err != nil {
				t.Fatalf("describe = %+v, %v", key, err)
			}
			if strings.HasPrefix(name, "trailing") && (key.RecordProblem == "" || key.Record.Schema != 0) {
				t.Fatalf("trailing data reported as a readable schema-%d record: %+v", key.Record.Schema, key)
			}
		})
	}
	// Positive control: the same address with a complete schema-2 record
	// (issuer null) rotates once and the new generation carries issuer null.
	store := newFakeStore(label)
	result, err := newTestManager(t, store).Rotate(addr("origin", 0))
	if err != nil || len(store.creates) != 1 || result.New.Record.Issuer != nil {
		t.Fatalf("positive control failed: %v %+v", err, result.New.Record.Issuer)
	}
}

// List drops anything outside the namespace even if the store returns it,
// sorts by label, filters by service and kind from the label, and reports
// v1 items as schema 1; Describe resolves the newest generation and exact
// versions by label, so an unreadable record is still found.
func TestManagerListAndDescribe(t *testing.T) {
	store := newFakeStore(tl("b", 1), tl("a", 1), tl("a", 2), LabelPrefix+"secret.test.tok.v1", "com.apple.leak", LabelPrefix)
	legacy := tl("legacy", 1)
	store.keys[legacy] = Item{Label: legacy, Tag: []byte("mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z"), SPKI: []byte{0x30}}
	store.keys[LabelPrefix+"signer"] = Item{Label: LabelPrefix + "signer", Tag: []byte("mac-keyvault/1 store=keychain"), SPKI: []byte{0x30}}
	manager := newTestManager(t, store)
	keys, err := manager.List("", "")
	if err != nil {
		t.Fatal(err)
	}
	var labels []string
	for _, key := range keys {
		labels = append(labels, key.Label)
	}
	if strings.Join(labels, " ") != strings.Join([]string{tl("a", 1), tl("a", 2), tl("b", 1), tl("legacy", 1), LabelPrefix + "secret.test.tok.v1", LabelPrefix + "signer"}, " ") {
		t.Fatalf("list = %v", labels)
	}
	if keys[3].Record.Schema != 1 || keys[3].Record.Service != Unknown {
		t.Fatalf("legacy = %+v", keys[3].Record)
	}
	if filtered, _ := manager.List(TestService, ""); len(filtered) != 5 {
		t.Fatalf("service filter = %d", len(filtered))
	}
	if filtered, _ := manager.List(TestService, KindSecret); len(filtered) != 1 || filtered[0].Label != LabelPrefix+"secret.test.tok.v1" {
		t.Fatalf("kind filter = %+v", filtered)
	}
	if filtered, _ := manager.List("other", ""); len(filtered) != 0 {
		t.Fatalf("other service = %+v", filtered)
	}
	if key, err := manager.Describe(addr("a", 0)); err != nil || key.Label != tl("a", 2) {
		t.Fatalf("newest = %+v, %v", key, err)
	}
	if key, err := manager.Describe(addr("a", 1)); err != nil || key.Label != tl("a", 1) {
		t.Fatalf("v1 = %+v, %v", key, err)
	}
	if key, err := manager.Describe(addr("legacy", 0)); err != nil || key.Record.Schema != 1 {
		t.Fatalf("legacy describe = %+v, %v", key, err)
	}
	if _, err := manager.Describe(addr("a", 3)); !errors.Is(err, ErrNotFound) {
		t.Fatalf("err = %v", err)
	}
	if _, err := manager.Describe(Address{Kind: KindSecret, Service: TestService, Purpose: "a"}); !errors.Is(err, ErrNotFound) {
		t.Fatalf("other kind = %v", err)
	}
}

// MetaSet/MetaUnset rewrite only the record's meta through UpdateTag under
// the lock: reserved names and bad types are refused before the store is
// touched, a v1 record is never rewritten, and an unknown name is
// ErrNotFound.
func TestManagerMeta(t *testing.T) {
	label, legacy := tl("m", 1), tl("legacy", 1)
	store := newFakeStore(label)
	store.keys[legacy] = Item{Label: legacy, Tag: []byte("mac-keyvault/1 store=keychain"), SPKI: []byte{0x30}}
	manager := newTestManager(t, store)
	a := addr("m", 0)
	for _, name := range []string{"schema", "label", "fingerprint", "origin"} {
		if code := refusalCode(t, mustErr(manager.MetaSet(a, name, "x"))); code != CodeInvalidMeta {
			t.Fatalf("%s: code = %s", name, code)
		}
	}
	if code := refusalCode(t, mustErr(manager.MetaSet(a, "owner", []string{"x"}))); code != CodeInvalidMeta {
		t.Fatalf("bad type code = %s", code)
	}
	if _, _, updates, lists := store.calls(); updates != 0 || lists != 0 {
		t.Fatalf("refused meta reached the store: updates=%d lists=%d", updates, lists)
	}
	key, err := manager.MetaSet(a, "owner", "alexis")
	if err != nil || key.Record.Meta["owner"] != "alexis" {
		t.Fatalf("set: %+v %v", key.Record.Meta, err)
	}
	if _, err := manager.MetaSet(a, "n", 2.5); err != nil {
		t.Fatal(err)
	}
	stored, _ := DecodeRecord(store.keys[label].Tag)
	if stored.Meta["owner"] != "alexis" || stored.Meta["n"] != json.Number("2.5") || stored.Service != TestService {
		t.Fatalf("stored = %+v", stored)
	}
	if _, err := manager.MetaUnset(a, "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("unset missing = %v", err)
	}
	if key, err := manager.MetaUnset(a, "owner"); err != nil || key.Record.Meta["owner"] != nil {
		t.Fatalf("unset: %+v %v", key.Record.Meta, err)
	}
	if code := refusalCode(t, mustErr(manager.MetaSet(addr("legacy", 0), "owner", "x"))); code != CodeMetadataUnknown {
		t.Fatalf("legacy code = %s", code)
	}
	if string(store.keys[legacy].Tag) != "mac-keyvault/1 store=keychain" {
		t.Fatal("legacy tag was rewritten")
	}
	for _, updated := range store.updates {
		if updated != label {
			t.Fatalf("update touched %s", updated)
		}
	}
}

// Operations derives from the registry and the policy: the single ec-p256
// keychain row yields sign only with usage sign and before not_after,
// decrypt only with usage decrypt, wrap gates ecdh, export-public is always
// there, export-private only when extraction is not none (human adds
// human_authorized); a (kind, algorithm, store) without a row yields [] with
// unsupported_primitive and exposure unknown, never a guess.
func TestOperationsRegistry(t *testing.T) {
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	names := func(ops []Operation) string {
		var out []string
		for _, op := range ops {
			out = append(out, op.Name)
		}
		return strings.Join(out, ",")
	}
	rec := testRecord(tl("ops", 1))
	rec.Usages = []string{"sign", "verify"}
	ops, findings := Operations(rec, now)
	if names(ops) != "ecdsa-sha256-sign,ecdsa-sha256-verify,ecies-p256-encrypt,export-public" || len(findings) != 0 || Exposure(rec) != ExposureNever {
		t.Fatalf("sign/verify: %s %v", names(ops), findings)
	}
	rec.Usages = []string{"decrypt", "wrap"}
	if ops, _ := Operations(rec, now); names(ops) != "ecdsa-sha256-verify,ecdh-p256,ecies-p256-encrypt,ecies-p256-decrypt,export-public" {
		t.Fatalf("decrypt/wrap: %s", names(ops))
	}
	rec.Usages = []string{"sign", "decrypt"}
	expired := NewTime(now.Add(-time.Hour))
	rec.Validity.NotAfter = &expired
	if ops, findings := Operations(rec, now); strings.Contains(names(ops), "sign") || strings.Contains(names(ops), "decrypt") || strings.Join(findings, ",") != FindingValidityExpired {
		t.Fatalf("expired: %s %v", names(ops), findings)
	}
	future := NewTime(now.Add(time.Hour))
	rec.Validity.NotAfter = &future
	ops, _ = Operations(rec, now)
	if !strings.Contains(names(ops), "ecdsa-sha256-sign") {
		t.Fatalf("unexpired lost sign: %s", names(ops))
	}
	for _, op := range ops {
		if op.Name == "export-public" && op.Via != "pub" {
			t.Fatalf("export-public via %s", op.Via)
		}
		// mac-keyvault implements sign and verify; ECIES decryption is
		// performed by the separate broker mac-keyvault-kek and names it;
		// every other crypto operation of the row is still reserved so a
		// consumer never assumes it works.
		if op.Name == OperationSign && op.Via != "sign" {
			t.Fatalf("sign advertised via %s", op.Via)
		}
		if op.Name == OperationVerify && op.Via != "verify" {
			t.Fatalf("verify advertised via %s", op.Via)
		}
		if op.Name == OperationDecrypt && op.Via != "mac-keyvault-kek unwrap" {
			t.Fatalf("decrypt advertised via %s", op.Via)
		}
		if (op.Name == "ecdh-p256" || op.Name == "ecies-p256-encrypt") && op.Via != ViaReserved {
			t.Fatalf("%s advertised via %s before it is implemented", op.Name, op.Via)
		}
		if op.Name == "export-private" {
			t.Fatal("export-private advertised for extraction none")
		}
	}
	for extraction, human := range map[string]bool{ExtractionHuman: true, ExtractionAgent: false} {
		rec.Extraction = extraction
		ops, _ := Operations(rec, now)
		found := false
		for _, op := range ops {
			if op.Name == "export-private" {
				found = true
				if op.HumanAuthorized != human || op.Via != ViaReserved {
					t.Fatalf("%s export-private = %+v", extraction, op)
				}
			}
		}
		if !found {
			t.Fatalf("%s: export-private missing from %s", extraction, names(ops))
		}
	}
	for name, mutate := range map[string]func(*Record){
		"unknown algorithm": func(r *Record) { r.Algorithm = AlgorithmECP384 },
		"unknown store":     func(r *Record) { r.Store = StoreUnknown },
		"public-key kind":   func(r *Record) { r.Kind = KindPublicKey },
		"schema 1":          func(r *Record) { *r, _ = DecodeRecord([]byte("mac-keyvault/1 store=keychain")) },
	} {
		other := testRecord(tl("ops", 1))
		mutate(&other)
		ops, findings := Operations(other, now)
		if len(ops) != 0 || strings.Join(findings, ",") != CodeUnsupportedPrimitive || Exposure(other) != Unknown {
			t.Fatalf("%s: ops=%v findings=%v exposure=%s", name, ops, findings, Exposure(other))
		}
	}
	// The Secure Enclave row signs, verifies and exports its public half,
	// and nothing reserved: no ECDH, ECIES or private export is advertised.
	enclave := testRecord(tl("ops", 1))
	enclave.Store = StoreEnclave
	if ops, findings := Operations(enclave, now); names(ops) != "ecdsa-sha256-sign,ecdsa-sha256-verify,export-public" || len(findings) != 0 || Exposure(enclave) != ExposureNever {
		t.Fatalf("enclave: ops=%s findings=%v exposure=%s", names(ops), findings, Exposure(enclave))
	}
	if _, ok := LookupPrimitive(testRecord(tl("x", 1))); !ok || len(registry) != 2 {
		t.Fatalf("registry must hold exactly the ec-p256 keychain and enclave key rows, has %d", len(registry))
	}
}

// Translate maps -34018 to missing_entitlement and every other OSStatus to
// security, both operational failures with the status and its name; a
// non-status error passes through.
func TestTranslateStatus(t *testing.T) {
	var refusal *Refusal
	err := Translate("create", &StatusError{Op: "create", Status: errSecMissingEntitlement})
	if !errors.As(err, &refusal) || refusal.Code != CodeMissingEntitlement || !refusal.Failure || refusal.Status != -34018 {
		t.Fatalf("missing entitlement = %v", err)
	}
	err = Translate("list", &StatusError{Op: "list", Status: -25308})
	if !errors.As(err, &refusal) || refusal.Code != CodeSecurity || !refusal.Failure || refusal.Status != -25308 || !strings.Contains(refusal.Message, "errSecInteractionNotAllowed") || !strings.Contains(refusal.Hint, "list") {
		t.Fatalf("security = %v", err)
	}
	plain := errors.New("x")
	if Translate("op", plain) != plain {
		t.Fatal("non-status error rewritten")
	}
	if OSStatusName(-99999) != "OSStatus -99999" {
		t.Fatalf("unknown status name = %s", OSStatusName(-99999))
	}
}

// Fingerprint is base64url(SHA-256(SPKI)) without padding and empty for an
// unknown SPKI; EncodePEM wraps the DER as PUBLIC KEY; EncodeJWK renders the
// P-256 point and refuses a non-P-256 SPKI.
func TestFingerprintPEMAndJWK(t *testing.T) {
	point := append([]byte{0x04}, make([]byte, 64)...)
	point[32] = 1 // not a valid point, expected to be refused
	if _, err := spkiFromPoint(point); err == nil {
		t.Fatal("off-curve point accepted")
	}
	// Generator point of P-256.
	gx := "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296"
	gy := "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5"
	spki, err := spkiFromPoint(mustHex("04" + gx + gy))
	if err != nil {
		t.Fatal(err)
	}
	if len(spki) != 91 || spki[0] != 0x30 {
		t.Fatalf("spki = %x", spki)
	}
	key := Key{SPKI: spki}
	fp := key.Fingerprint()
	if len(fp) != 43 || strings.ContainsAny(fp, "+/=") {
		t.Fatalf("fingerprint = %q", fp)
	}
	if (Key{}).Fingerprint() != "" {
		t.Fatal("unknown SPKI produced a fingerprint")
	}
	pemText := string(EncodePEM(spki))
	if !strings.HasPrefix(pemText, "-----BEGIN PUBLIC KEY-----\n") || !strings.HasSuffix(pemText, "-----END PUBLIC KEY-----\n") {
		t.Fatalf("pem = %q", pemText)
	}
	jwk, err := EncodeJWK(spki)
	if err != nil {
		t.Fatal(err)
	}
	var parsed map[string]string
	if err := json.Unmarshal(jwk, &parsed); err != nil || parsed["kty"] != "EC" || parsed["crv"] != "P-256" || parsed["x"] != "axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY" || parsed["y"] != "T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU" {
		t.Fatalf("jwk = %s (%v)", jwk, err)
	}
	if _, err := EncodeJWK([]byte{0x30, 0x00}); err == nil {
		t.Fatal("garbage SPKI produced a JWK")
	}
}

func mustHex(s string) []byte {
	out := make([]byte, len(s)/2)
	for i := range out {
		var b byte
		for _, c := range s[2*i : 2*i+2] {
			b <<= 4
			switch {
			case c >= '0' && c <= '9':
				b |= byte(c - '0')
			case c >= 'a' && c <= 'f':
				b |= byte(c-'a') + 10
			}
		}
		out[i] = b
	}
	return out
}

// FileLock serialises two holders of the same path on separate descriptors
// (the cross-process shape) and refuses an empty path.
func TestFileLock(t *testing.T) {
	path := filepath.Join(t.TempDir(), "x.lock")
	release, err := FileLock{Path: path}.Lock()
	if err != nil {
		t.Fatal(err)
	}
	acquired := make(chan struct{})
	go func() {
		second, err := FileLock{Path: path}.Lock()
		if err == nil {
			second()
		}
		close(acquired)
	}()
	select {
	case <-acquired:
		t.Fatal("second holder acquired while the first still held the lock")
	case <-time.After(200 * time.Millisecond):
	}
	release()
	select {
	case <-acquired:
	case <-time.After(2 * time.Second):
		t.Fatal("second holder never acquired after release")
	}
	if _, err := (FileLock{}).Lock(); err == nil {
		t.Fatal("empty path accepted")
	}
}

// ValidateKind is the closed vocabulary every --kind goes through: the four
// model kinds pass, anything else (case, punctuation, empty, lookalike) is
// invalid_kind. It is the same gate ParseAddress applies.
func TestValidateKind(t *testing.T) {
	for _, kind := range kinds {
		if err := ValidateKind(kind); err != nil {
			t.Fatalf("%q refused: %v", kind, err)
		}
	}
	for _, kind := range []string{"", "Key", "keys", "key.", "public_key", "bogus", "*", "key,secret"} {
		if code := refusalCode(t, ValidateKind(kind)); code != CodeInvalidKind {
			t.Fatalf("%q admitted or wrong code %q", kind, code)
		}
		if _, err := ParseAddress("test/x", kind, 0); refusalCode(t, err) != CodeInvalidKind {
			t.Fatalf("ParseAddress admitted kind %q", kind)
		}
	}
}

// DecodeRecord keeps numeric meta as json.Number so that EncodeRecord of the
// decoded record reproduces the digits exactly (2^53+1 and 2^64+1 would be
// rounded through float64); a small integer, a fraction and a bool are the
// nearby positive controls, and a rev1 tag still carries an empty meta.
// Review rev8 F1, the persisted tag: a schema-2 record whose NESTED
// object repeats a member — format.public, origin.user, validity, meta,
// verbatim or escape-spelt, the forged value first and the valid one
// last, the order a struct decode collapses to the valid value — is a
// read failure naming the duplicate (DecodeRecord → DecodeSingleJSON →
// CheckDocument), never a readable record with the forged value erased
// before ValidateStored sees it; a top-level repeat is refused the same
// way. Controls: the same tag with a single escape-spelt nested member
// is readable under the decoded name, and one member name in two sibling
// objects is not a repeat.
func TestDecodeRecordRefusesNestedDuplicateMembers(t *testing.T) {
	head := `{"schema":2,"kind":"key","service":"test","purpose":"n","version":1,"algorithm":"ec-p256","store":"keychain","extraction":"none","usages":["sign"],"created":"2023-11-14T22:13:20Z",`
	tail := `,"origin":{"user":"u","host":"h","tool":"t","source":"generated"},"validity":{"not_before":null,"not_after":null},"meta":{"owner":"a"}}`
	forged := map[string]string{
		"format.public":          head + `"format":{"public":"wrong","public":"spki-der","signature":"ecdsa-der-low-s"}` + tail,
		"format.public escaped":  head + `"format":{"publ\u0069c":"wrong","public":"spki-der","signature":"ecdsa-der-low-s"}` + tail,
		"origin.user":            head + `"format":{"public":"spki-der","signature":"ecdsa-der-low-s"},"origin":{"user":"attacker","user":"u","host":"h","tool":"t","source":"generated"},"validity":{"not_before":null,"not_after":null},"meta":{"owner":"a"}}`,
		"validity.not_after":     head + `"format":{"public":"spki-der","signature":"ecdsa-der-low-s"},"origin":{"user":"u","host":"h","tool":"t","source":"generated"},"validity":{"not_before":null,"not_after":"2020-01-01T00:00:00Z","not_after":null},"meta":{"owner":"a"}}`,
		"meta.owner escaped":     head + `"format":{"public":"spki-der","signature":"ecdsa-der-low-s"},"origin":{"user":"u","host":"h","tool":"t","source":"generated"},"validity":{"not_before":null,"not_after":null},"meta":{"own\u0065r":"attacker","owner":"a"}}`,
		"top-level store":        head + `"store":"enclave","format":{"public":"spki-der","signature":"ecdsa-der-low-s"}` + tail,
		"unknown nested in meta": head + `"format":{"public":"spki-der","signature":"ecdsa-der-low-s"},"origin":{"user":"u","host":"h","tool":"t","source":"generated"},"validity":{"not_before":null,"not_after":null},"meta":{"x":{"a":1,"a":2},"owner":"a"}}`,
	}
	for name, tag := range forged {
		rec, problem := DecodeRecord([]byte(tag))
		if !strings.Contains(problem, "duplicate member") || rec.Schema != 0 || rec.Store != StoreUnknown {
			t.Errorf("%s: DecodeRecord = %+v (%q); a repeated nested member must be a read failure naming the duplicate", name, rec, problem)
		}
	}
	control := head + `"format":{"publ\u0069c":"spki-der","signature":"ecdsa-der-low-s"}` + tail
	if rec, problem := DecodeRecord([]byte(control)); problem != "" || rec.Format.Public != "spki-der" || rec.Origin.User != "u" {
		t.Fatalf("control: %+v (%q)", rec, problem)
	}
}

func TestDecodeRecordPreservesNumericMeta(t *testing.T) {
	tag := []byte(`{"schema":2,"kind":"key","service":"test","purpose":"n","version":1,"algorithm":"ec-p256","store":"keychain","extraction":"none","usages":["sign"],"format":{"public":"spki-der","signature":"ecdsa-der-low-s"},"meta":{"big":9007199254740993,"huge":18446744073709551617,"small":7,"frac":0.1,"flag":true}}`)
	rec, problem := DecodeRecord(tag)
	if problem != "" {
		t.Fatal(problem)
	}
	if rec.Meta["big"] != json.Number("9007199254740993") || rec.Meta["huge"] != json.Number("18446744073709551617") || rec.Meta["small"] != json.Number("7") || rec.Meta["frac"] != json.Number("0.1") || rec.Meta["flag"] != true {
		t.Fatalf("meta = %#v", rec.Meta)
	}
	encoded, err := EncodeRecord(rec)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"big":9007199254740993`, `"huge":18446744073709551617`, `"small":7`, `"frac":0.1`, `"flag":true`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("re-encoded record lacks %s: %s", want, encoded)
		}
	}
	if err := ValidateMeta(rec.Meta); err != nil {
		t.Fatalf("decoded numeric meta refused: %v", err)
	}
	if legacy, _ := DecodeRecord([]byte("mac-keyvault/1 store=keychain")); legacy.Schema != 1 || len(legacy.Meta) != 0 {
		t.Fatalf("legacy = %+v", legacy)
	}
}
