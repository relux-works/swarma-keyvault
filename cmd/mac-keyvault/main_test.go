package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/recordtest"
)

const testPrefix = keyvault.TestLabelPrefix

// tl is the test label of key/test/<purpose> version N.
func tl(purpose string, version int) string {
	return keyvault.Address{Kind: keyvault.KindKey, Service: keyvault.TestService, Purpose: purpose, Version: version}.Label()
}

// memStore is an in-memory Backend that records every call, so CLI tests can
// prove which labels reached the store and which refusals happened first.
type memStore struct {
	keys    map[string]keyvault.Item
	creates []keyvault.CreateOptions
	deletes []string
	updates []string
	lists   int
	createE error
	signs   []string
	signE   error
	// signHighS makes Sign return the high-S twin of every signature.
	signHighS bool
}

func newMemStore(labels ...string) *memStore {
	s := &memStore{keys: map[string]keyvault.Item{}}
	for i, label := range labels {
		s.keys[label] = memItem(label, byte(i))
	}
	return s
}

// memItem builds a schema-2 item whose record derives from a parseable label.
func memItem(label string, salt byte) keyvault.Item {
	addr, ok := keyvault.ParseLabel(label)
	if !ok {
		addr = keyvault.Address{Kind: keyvault.KindKey, Service: keyvault.Unknown, Purpose: keyvault.Unknown, Version: 1}
	}
	rec := keyvault.Record{Schema: 2, Kind: addr.Kind, Service: addr.Service, Purpose: addr.Purpose, Version: addr.Version, Algorithm: keyvault.AlgorithmECP256,
		Store: keyvault.StoreKeychain, Extraction: keyvault.ExtractionNone, Usages: []string{"sign", "verify"},
		Format:  keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS},
		Created: keyvault.NewTime(time.Date(2026, 9, 15, 8, int(salt), 0, 0, time.UTC)), Origin: keyvault.Origin{User: "t", Host: "h", Tool: "t", Source: keyvault.SourceGenerated}, Meta: map[string]any{}}
	tag, _ := keyvault.EncodeRecord(rec)
	return keyvault.Item{Label: label, Tag: tag, SPKI: generatorSPKI(salt)}
}

func (s *memStore) Create(opts keyvault.CreateOptions) (keyvault.Item, error) {
	s.creates = append(s.creates, opts)
	if s.createE != nil {
		return keyvault.Item{}, s.createE
	}
	item := keyvault.Item{Label: opts.Label, Tag: opts.Tag, SPKI: generatorSPKI(byte(len(s.creates) + 100))}
	s.keys[opts.Label] = item
	return item, nil
}

func (s *memStore) List() ([]keyvault.Item, error) {
	s.lists++
	out := make([]keyvault.Item, 0, len(s.keys))
	for _, item := range s.keys {
		out = append(out, item)
	}
	return out, nil
}

func (s *memStore) Delete(label string) error {
	s.deletes = append(s.deletes, label)
	if _, ok := s.keys[label]; !ok {
		return keyvault.ErrNotFound
	}
	delete(s.keys, label)
	return nil
}

func (s *memStore) UpdateTag(label string, tag []byte) error {
	s.updates = append(s.updates, label)
	item, ok := s.keys[label]
	if !ok {
		return keyvault.ErrNotFound
	}
	item.Tag = tag
	s.keys[label] = item
	return nil
}

func (s *memStore) touched() bool {
	return len(s.creates)+len(s.deletes)+len(s.updates)+len(s.signs)+s.lists != 0
}

func (s *memStore) record(t *testing.T, label string) keyvault.Record {
	t.Helper()
	item, ok := s.keys[label]
	if !ok {
		t.Fatalf("no item %s in store", label)
	}
	rec, problem := keyvault.DecodeRecord(item.Tag)
	if problem != "" {
		t.Fatalf("stored record of %s unreadable: %s", label, problem)
	}
	return rec
}

var (
	spkiCache   = map[byte][]byte{}
	signerCache = map[string]*ecdsa.PrivateKey{} // by SPKI bytes
	spkiCacheMu sync.Mutex
)

// generatorSPKI returns a real P-256 SPKI per salt so fingerprints differ
// per key and every representation (DER, PEM, JWK) parses; the private
// half is kept so memStore.Sign can produce real signatures under it.
func generatorSPKI(salt byte) []byte {
	spkiCacheMu.Lock()
	defer spkiCacheMu.Unlock()
	if spki, ok := spkiCache[salt]; ok {
		return spki
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic(err)
	}
	spkiCache[salt] = spki
	signerCache[string(spki)] = key
	return spki
}

// signerFor returns the private key behind a generatorSPKI SPKI.
func signerFor(spki []byte) *ecdsa.PrivateKey {
	spkiCacheMu.Lock()
	defer spkiCacheMu.Unlock()
	return signerCache[string(spki)]
}

// Sign records the call and signs with the private half behind the item's
// SPKI (crypto/ecdsa, DER out, the shape the bridge returns), low-S unless
// signHighS asks for the high-S twin so the CLI's normalisation is
// exercised; signE stands in for a Security.framework failure.
func (s *memStore) Sign(label string, digest []byte) ([]byte, error) {
	s.signs = append(s.signs, label)
	if s.signE != nil {
		return nil, s.signE
	}
	item, ok := s.keys[label]
	if !ok {
		return nil, keyvault.ErrNotFound
	}
	priv := signerFor(item.SPKI)
	if priv == nil {
		return nil, fmt.Errorf("memStore: no private key behind %s", label)
	}
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest)
	if err != nil {
		return nil, err
	}
	// crypto/ecdsa does not normalise, so the fake decides the half
	// deterministically: low-S by default, the high-S twin on request.
	sig, err := keyvault.ParseSignature(der, keyvault.FormatSignatureDERLowS)
	if err != nil {
		return nil, err
	}
	sig = sig.LowS()
	if s.signHighS {
		sig = keyvault.Signature{R: sig.R, S: new(big.Int).Sub(elliptic.P256().Params().N, sig.S)}
	}
	return sig.Encode(keyvault.FormatSignatureDERLowS)
}

func useStore(t *testing.T, store keyvault.Backend) {
	t.Helper()
	previousBackend, previousLock := newBackend, lockPath
	newBackend = func() keyvault.Backend { return store }
	lock := filepath.Join(t.TempDir(), "init.lock")
	lockPath = func() (string, error) { return lock, nil }
	t.Cleanup(func() { newBackend, lockPath = previousBackend, previousLock })
}

func runJSON(t *testing.T, args ...string) (int, response, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(append([]string{"--json"}, args...), &stdout, &stderr)
	var resp response
	if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
		t.Fatalf("stdout is not a JSON envelope (%v): %s / stderr: %s", err, stdout.String(), stderr.String())
	}
	if stderr.Len() != 0 {
		t.Fatalf("json mode wrote to stderr: %s", stderr.String())
	}
	// Error contract: every error carries code, message and hint.
	if resp.Error != nil && (resp.Error.Code == "" || resp.Error.Message == "" || resp.Error.Hint == "") {
		t.Fatalf("error envelope violates the contract: %s", stdout.String())
	}
	return code, resp, stdout.String()
}

func resultMap(t *testing.T, resp response) map[string]any {
	t.Helper()
	m, ok := resp.Result.(map[string]any)
	if !ok {
		t.Fatalf("result is %T, want object: %+v", resp.Result, resp.Result)
	}
	return m
}

func initArgs(purpose string, extra ...string) []string {
	return append([]string{"init", "--service", "test", "--purpose", purpose}, extra...)
}

// Every command answers --json with the {ok, command, result|error}
// envelope and the documented exit code; the same failures in text mode
// print "error: <code>: <message>" and "hint: <hint>" to stderr with the
// same exit code and nothing on stdout.
func TestRunJSONEnvelopeAndExitCodes(t *testing.T) {
	existing := tl("cli", 1)
	for name, tc := range map[string]struct {
		args    []string
		code    int
		ok      bool
		command string
		errCode string
	}{
		"init new":                     {args: initArgs("cli-new"), code: exitOK, ok: true, command: "init"},
		"init duplicate":               {args: initArgs("cli"), code: exitRefused, command: "init", errCode: keyvault.CodeDuplicate},
		"init invalid purpose":         {args: initArgs("Bad Purpose"), code: exitRefused, command: "init", errCode: keyvault.CodeInvalidPurpose},
		"list":                         {args: []string{"list"}, code: exitOK, ok: true, command: "list"},
		"describe existing":            {args: []string{"describe", "test/cli"}, code: exitOK, ok: true, command: "describe"},
		"describe version":             {args: []string{"describe", "test/cli", "--version", "1"}, code: exitOK, ok: true, command: "describe"},
		"describe missing version":     {args: []string{"describe", "test/cli", "--version", "4"}, code: exitFailure, command: "describe", errCode: "not_found"},
		"describe other kind":          {args: []string{"describe", "test/cli", "--kind", "secret"}, code: exitFailure, command: "describe", errCode: "not_found"},
		"describe missing":             {args: []string{"describe", "test/cli-missing"}, code: exitFailure, command: "describe", errCode: "not_found"},
		"pub existing":                 {args: []string{"pub", "test/cli"}, code: exitOK, ok: true, command: "pub"},
		"pub full label":               {args: []string{"pub", existing}, code: exitRefused, command: "pub", errCode: keyvault.CodeForeignLabel},
		"pub missing":                  {args: []string{"pub", "test/cli-missing"}, code: exitFailure, command: "pub", errCode: "not_found"},
		"rotate existing":              {args: []string{"rotate", "test/cli"}, code: exitOK, ok: true, command: "rotate"},
		"rotate missing":               {args: []string{"rotate", "test/cli-missing"}, code: exitFailure, command: "rotate", errCode: "not_found"},
		"delete unconfirmed":           {args: []string{"delete", "test/cli"}, code: exitRefused, command: "delete", errCode: keyvault.CodeConfirmationRequired},
		"delete unconfirmed flag late": {args: []string{"delete", "test/cli", "--confirm=false"}, code: exitRefused, command: "delete", errCode: keyvault.CodeConfirmationRequired},
		"delete unconfirmed versioned": {args: []string{"delete", "test/cli", "--version", "1"}, code: exitRefused, command: "delete", errCode: keyvault.CodeConfirmationRequired},
		"delete confirmed":             {args: []string{"delete", "test/cli", "--confirm"}, code: exitOK, ok: true, command: "delete"},
		"delete confirmed flag first":  {args: []string{"delete", "--confirm", "test/cli"}, code: exitOK, ok: true, command: "delete"},
		"delete missing":               {args: []string{"delete", "--confirm", "test/cli-missing"}, code: exitFailure, command: "delete", errCode: "not_found"},
		"meta get":                     {args: []string{"meta", "get", "test/cli"}, code: exitOK, ok: true, command: "meta get"},
		"meta get missing key":         {args: []string{"meta", "get", "test/cli", "owner"}, code: exitFailure, command: "meta get", errCode: "not_found"},
		"meta set":                     {args: []string{"meta", "set", "test/cli", "owner", "alexis"}, code: exitOK, ok: true, command: "meta set"},
		"meta set reserved":            {args: []string{"meta", "set", "test/cli", "schema", "3"}, code: exitRefused, command: "meta set", errCode: keyvault.CodeInvalidMeta},
		"meta unset missing":           {args: []string{"meta", "unset", "test/cli", "owner"}, code: exitFailure, command: "meta unset", errCode: "not_found"},
		"version":                      {args: []string{"version"}, code: exitOK, ok: true, command: "version"},
	} {
		t.Run(name, func(t *testing.T) {
			useStore(t, newMemStore(existing))
			code, resp, raw := runJSON(t, tc.args...)
			if code != tc.code || resp.OK != tc.ok || resp.Command != tc.command {
				t.Fatalf("code=%d ok=%v command=%s; want %d %v %s: %s", code, resp.OK, resp.Command, tc.code, tc.ok, tc.command, raw)
			}
			if tc.errCode != "" {
				if resp.Error == nil || resp.Error.Code != tc.errCode {
					t.Fatalf("error = %+v, want %s", resp.Error, tc.errCode)
				}
			} else if resp.Error != nil {
				t.Fatalf("unexpected error %+v", resp.Error)
			}
			// Same command in text mode: failures go to stderr only, in the
			// error-contract shape.
			var stdout, stderr bytes.Buffer
			useStore(t, newMemStore(existing))
			if textCode := run(tc.args, &stdout, &stderr); textCode != tc.code {
				t.Fatalf("text mode code = %d, want %d (stderr %s)", textCode, tc.code, stderr.String())
			}
			if tc.code != exitOK && (stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "error: "+tc.errCode+": ") || !strings.Contains(stderr.String(), "\nhint: ")) {
				t.Fatalf("text failure stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
		})
	}
}

// Every usage error — missing command, unknown command, missing or extra
// positionals, unknown or incompatible flags, bad --format, bad --meta,
// unreadable --meta-json, bad --not-after — yields a parseable error envelope
// with code usage on stdout, empty stderr and exit 2 in --json mode
// (whether --json comes first or last), exits 2 with stderr text and empty
// stdout in text mode, and never reaches the store (review F3).
func TestRunUsageErrorsAreJSONEnvelopesAndDoNotReachStore(t *testing.T) {
	missingFile := filepath.Join(t.TempDir(), "missing.json")
	for name, args := range map[string][]string{
		"no args":                nil,
		"unknown command":        {"frobnicate"},
		"init positional":        {"init", "a"},
		"init no service":        {"init", "--purpose", "a"},
		"init no purpose":        {"init", "--service", "a"},
		"init both stores":       initArgs("a", "--enclave", "--keychain"),
		"init unknown flag":      initArgs("a", "--biometry"),
		"init bad meta":          initArgs("a", "--meta", "novalue"),
		"init meta twice":        initArgs("a", "--meta", "k=1", "--meta", "k=2"),
		"init meta-json missing": initArgs("a", "--meta-json", missingFile),
		"init bad not-after":     initArgs("a", "--not-after", "tomorrow"),
		"init bad version flag":  initArgs("a", "--version", "1"),
		"list with arg":          {"list", "a"},
		"list unknown flag":      {"list", "--all"},
		"describe no address":    {"describe"},
		"describe two addresses": {"describe", "test/a", "test/b"},
		"pub bad format":         {"pub", "test/a", "--format", "x509"},
		"pub short format":       {"pub", "test/a", "--format", "der"},
		"describe bad version":   {"describe", "test/a", "--version", "two"},
		"pub missing address":    {"pub"},
		"delete no address":      {"delete", "--confirm"},
		"delete extra address":   {"delete", "test/a", "test/b", "--confirm"},
		"delete unknown flag":    {"delete", "test/a", "--force"},
		"rotate two addresses":   {"rotate", "test/a", "test/b"},
		"meta no sub":            {"meta"},
		"meta unknown sub":       {"meta", "list", "test/a"},
		"meta set no value":      {"meta", "set", "test/a", "k"},
		"meta unset no key":      {"meta", "unset", "test/a"},
		"meta set bad json":      {"meta", "set", "test/a", "k", "{", "--json-value"},
	} {
		t.Run(name, func(t *testing.T) { assertUsageRefusal(t, args) })
	}
}

// assertUsageRefusal drives run() with args in --json-first, --json-last and
// text placement against a store holding one own item and requires the
// usage contract in every placement: exit 2, store untouched (no List,
// Create, UpdateTag or Delete), a {ok:false, error:{code:"usage", message,
// hint:"mac-keyvault …"}} envelope on stdout with empty stderr in JSON
// mode, and "error: usage: …" + "hint: mac-keyvault …" on stderr with empty
// stdout in text mode.
func assertUsageRefusal(t *testing.T, args []string) {
	t.Helper()
	for _, placement := range []string{"json first", "json last", "text"} {
		store := newMemStore(tl("a", 1))
		useStore(t, store)
		var stdout, stderr bytes.Buffer
		var code int
		switch placement {
		case "json first":
			code = run(append([]string{"--json"}, args...), &stdout, &stderr)
		case "json last":
			code = run(append(append([]string(nil), args...), "--json"), &stdout, &stderr)
		default:
			code = run(args, &stdout, &stderr)
		}
		if code != exitUsage {
			t.Fatalf("%s: code = %d, want %d; stdout=%s stderr=%s", placement, code, exitUsage, stdout.String(), stderr.String())
		}
		if store.touched() {
			t.Fatalf("%s: usage error reached the store: creates=%v deletes=%v updates=%v lists=%d", placement, store.creates, store.deletes, store.updates, store.lists)
		}
		if placement == "text" {
			if stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "error: usage: ") || !strings.Contains(stderr.String(), "\nhint: mac-keyvault") {
				t.Fatalf("text usage error stdout=%q stderr=%q", stdout.String(), stderr.String())
			}
			continue
		}
		var resp response
		if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
			t.Fatalf("%s: stdout is not a JSON envelope (%v): %q", placement, err, stdout.String())
		}
		if resp.OK || resp.Error == nil || resp.Error.Code != "usage" || resp.Error.Message == "" || !strings.HasPrefix(resp.Error.Hint, "mac-keyvault") || stderr.Len() != 0 {
			t.Fatalf("%s: envelope = %+v stderr=%q", placement, resp, stderr.String())
		}
	}
}

// version and help are commands like any other: a stray positional or an
// unknown flag is a usage error with the envelope, exit 2 and zero store
// calls, not a successful version envelope that ignores the input (review
// F6, repeat of F3). Positive control: bare "version" and "help" still
// succeed with --json first, --json last and in text mode.
func TestRunVersionRejectsExtraInput(t *testing.T) {
	for name, args := range map[string][]string{
		"version positional":   {"version", "extra"},
		"version unknown flag": {"version", "--bogus"},
		"version flag value":   {"version", "--kind", "key"},
		"help positional":      {"help", "init"},
		"help unknown flag":    {"help", "--bogus"},
	} {
		t.Run(name, func(t *testing.T) { assertUsageRefusal(t, args) })
	}
	store := newMemStore()
	useStore(t, store)
	for _, args := range [][]string{{"--json", "version"}, {"version", "--json"}} {
		var stdout, stderr bytes.Buffer
		if code := run(args, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), `"ok": true`) || stderr.Len() != 0 {
			t.Fatalf("positive control %v: %d %q %q", args, code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"help"}, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), "Usage:") {
		t.Fatalf("positive control help: %d %q", code, stdout.String())
	}
	if store.touched() {
		t.Fatalf("version/help touched the store")
	}
}

// --meta-json must hold exactly one JSON object: a second document after
// the first, trailing tokens or trailing garbage, and a non-object top-level
// value are usage errors (envelope, exit 2, no store call) — the first
// object is never persisted on its own (review F6, repeat of F3). The same
// single-document rule applies to meta set --json-value. Positive controls:
// a single object (with surrounding whitespace and a trailing newline) is
// accepted and persisted; a single JSON number is a valid --json-value.
func TestRunMetaJSONRejectsTrailingDocument(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	for name, args := range map[string][]string{
		"second object":    initArgs("a", "--meta-json", write("two.json", `{"owner":"a"} {"ignored":true}`)),
		"trailing token":   initArgs("a", "--meta-json", write("token.json", `{"owner":"a"} 1`)),
		"trailing garbage": initArgs("a", "--meta-json", write("garbage.json", "{\"owner\":\"a\"}\n}")),
		"trailing bracket": initArgs("a", "--meta-json", write("bracket.json", `{"owner":"a"}]`)),
		"array top level":  initArgs("a", "--meta-json", write("array.json", `[{"owner":"a"}]`)),
		"empty file":       initArgs("a", "--meta-json", write("empty.json", "")),
		// a repeated member, top-level or nested, verbatim or escape-spelt
		// (rev8 F1: CheckDocument runs before the map decode that would
		// keep only the last value)
		"duplicate member":   initArgs("a", "--meta-json", write("dup.json", `{"owner":"x","owner":"a"}`)),
		"duplicate escaped":  initArgs("a", "--meta-json", write("dup-esc.json", `{"own\u0065r":"x","owner":"a"}`)),
		"duplicate nested":   initArgs("a", "--meta-json", write("dup-nested.json", `{"owner":"a","o":{"n":1,"n":2}}`)),
		"json-value dup":     {"meta", "set", "test/a", "n", `{"a":1,"a":2}`, "--json-value"},
		"json-value second":  {"meta", "set", "test/a", "n", "1 2", "--json-value"},
		"json-value garbage": {"meta", "set", "test/a", "n", "true x", "--json-value"},
	} {
		t.Run(name, func(t *testing.T) { assertUsageRefusal(t, args) })
	}
	store := newMemStore()
	useStore(t, store)
	if code, _, raw := runJSON(t, initArgs("single", "--meta-json", write("one.json", "  {\"owner\":\"a\", \"n\": 2}\n\n"))...); code != exitOK {
		t.Fatalf("positive control single object: %d %s", code, raw)
	}
	if rec := store.record(t, tl("single", 1)); rec.Meta["owner"] != "a" || rec.Meta["n"] != json.Number("2") {
		t.Fatalf("persisted meta = %+v", rec.Meta)
	}
	if code, _, raw := runJSON(t, "meta", "set", "test/single", "k", "3.5", "--json-value"); code != exitOK {
		t.Fatalf("positive control json-value: %d %s", code, raw)
	}
	if rec := store.record(t, tl("single", 1)); rec.Meta["k"] != json.Number("3.5") {
		t.Fatalf("persisted meta = %+v", rec.Meta)
	}
}

// The 80-character title bound counts characters, not bytes: an exactly
// 80-character title made of 2-byte Armenian letters (160 bytes) is
// admitted through init and persisted verbatim, while an 81-character one
// is refused as invalid_title with zero store calls (review F7).
func TestRunTitleCharacterBound(t *testing.T) {
	armenian := strings.Repeat("\u0561", 80) // U+0561 ARMENIAN SMALL LETTER AYB, 2 bytes each
	if len(armenian) != 160 {
		t.Fatalf("fixture is %d bytes, want 160", len(armenian))
	}
	store := newMemStore()
	useStore(t, store)
	if code, _, raw := runJSON(t, initArgs("titled", "--title", armenian)...); code != exitOK {
		t.Fatalf("80-character title refused: %d %s", code, raw)
	}
	if rec := store.record(t, tl("titled", 1)); rec.Title != armenian {
		t.Fatalf("persisted title = %q", rec.Title)
	}
	for name, title := range map[string]string{
		"81 armenian": armenian + "\u0561",
		"81 ascii":    strings.Repeat("x", 81),
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemStore()
			useStore(t, store)
			code, resp, raw := runJSON(t, initArgs("titled", "--title", title)...)
			if code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeInvalidTitle || !strings.Contains(resp.Error.Message, "81 characters") {
				t.Fatalf("code=%d resp=%s", code, raw)
			}
			if store.touched() {
				t.Fatalf("refused title reached the store")
			}
		})
	}
}

// Any input that is not a <service>/<purpose> address — a foreign label, a
// lookalike or sibling namespace, a bare name, the bare prefix, and even a
// full label inside the vault prefix — is refused as foreign_label at the
// run() entry with exit 3 before any store call, List included, for every
// addressing command (review F1, model §1). Positive control: the same
// commands with an own address reach the store.
func TestRunForeignLabelRefusedAtEntry(t *testing.T) {
	commands := map[string]func(addr string) []string{
		"describe":      func(a string) []string { return []string{"describe", a} },
		"describe kind": func(a string) []string { return []string{"describe", a, "--kind", "secret"} },
		"pub":           func(a string) []string { return []string{"pub", a} },
		"rotate":        func(a string) []string { return []string{"rotate", a} },
		"delete":        func(a string) []string { return []string{"delete", a, "--confirm"} },
		"delete v1":     func(a string) []string { return []string{"delete", a, "--confirm", "--version", "1"} },
		"meta get":      func(a string) []string { return []string{"meta", "get", a} },
		"meta set":      func(a string) []string { return []string{"meta", "set", a, "owner", "x"} },
		"meta unset":    func(a string) []string { return []string{"meta", "unset", a, "owner"} },
	}
	own := tl("cli-del", 1)
	for _, foreign := range []string{"com.apple.security.key", "works.relux.mac-keyvaultX.key", "works.relux.other.key", "signer", keyvault.LabelPrefix, "test.cli-del", own, ""} {
		for name, build := range commands {
			t.Run(name+" "+foreign, func(t *testing.T) {
				store := newMemStore(own)
				store.keys["com.apple.security.key"] = memItem(tl("x", 1), 9)
				useStore(t, store)
				code, resp, raw := runJSON(t, build(foreign)...)
				if code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeForeignLabel {
					t.Fatalf("code=%d resp=%s", code, raw)
				}
				if store.touched() {
					t.Fatalf("foreign input reached the store: creates=%v deletes=%v updates=%v lists=%d", store.creates, store.deletes, store.updates, store.lists)
				}
				if _, ok := store.keys["com.apple.security.key"]; !ok {
					t.Fatal("foreign key deleted")
				}
			})
		}
	}
	for name, build := range commands {
		store := newMemStore(own)
		useStore(t, store)
		code, _, raw := runJSON(t, build("test/cli-del")...)
		if store.lists == 0 {
			t.Fatalf("positive control %s: store not reached: code=%d %s", name, code, raw)
		}
	}
	// A bad part of an address is refused with its own code, still before the store.
	for input, want := range map[string]string{"Test/x": keyvault.CodeInvalidService, "test/x.y": keyvault.CodeInvalidPurpose, "a/b/c": keyvault.CodeInvalidPurpose, keyvault.LabelPrefix + "../x": keyvault.CodeInvalidService} {
		store := newMemStore()
		useStore(t, store)
		if code, resp, raw := runJSON(t, "delete", input, "--confirm"); code != exitRefused || resp.Error.Code != want || store.touched() {
			t.Fatalf("%s: %d %s", input, code, raw)
		}
	}
	store := newMemStore()
	useStore(t, store)
	if code, resp, raw := runJSON(t, "describe", "test/x", "--kind", "keypair"); code != exitRefused || resp.Error.Code != keyvault.CodeInvalidKind || store.touched() {
		t.Fatalf("bad kind: %d %s", code, raw)
	}
}

// init refuses every invalid record field with its own code, exit 3, and no
// store call at all: service, purpose, kind, algorithm, usages, formats
// (including an envelope format on a key), extraction (unknown, any
// extraction on the Enclave), --generate on a key, title length, reserved
// and mistyped meta from both --meta and --meta-json.
func TestRunInitValidatesRecordBeforeStore(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string) string {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	reservedJSON := write("reserved.json", `{"owner":"a","fingerprint":"x"}`)
	nestedJSON := write("nested.json", `{"owner":{"name":"a"}}`)
	for name, tc := range map[string]struct {
		args []string
		code string
	}{
		"service uppercase":      {[]string{"init", "--service", "Kvctl", "--purpose", "a"}, keyvault.CodeInvalidService},
		"service dot":            {[]string{"init", "--service", "kv.ctl", "--purpose", "a"}, keyvault.CodeInvalidService},
		"service too long":       {[]string{"init", "--service", strings.Repeat("s", 41), "--purpose", "a"}, keyvault.CodeInvalidService},
		"purpose underscore":     {initArgs("pki_root"), keyvault.CodeInvalidPurpose},
		"kind unknown":           {initArgs("a", "--kind", "keypair"), keyvault.CodeInvalidKind},
		"kind secret":            {initArgs("a", "--kind", "secret", "--algorithm", "aes-256-gcm"), keyvault.CodeUnsupportedKind},
		"algorithm unknown":      {initArgs("a", "--algorithm", "p256"), keyvault.CodeInvalidAlgorithm},
		"algorithm ed25519":      {initArgs("a", "--algorithm", "ed25519"), keyvault.CodeUnsupportedAlgorithm},
		"algorithm rsa reserved": {initArgs("a", "--algorithm", "rsa-3072"), keyvault.CodeUnsupportedAlgorithm},
		"usages unknown":         {initArgs("a", "--usages", "sign,export"), keyvault.CodeInvalidUsages},
		"usages empty":           {initArgs("a", "--usages", ","), keyvault.CodeInvalidUsages},
		"format public":          {initArgs("a", "--format-public", "x509-der"), keyvault.CodeInvalidFormat},
		"format signature":       {initArgs("a", "--format-signature", "pss"), keyvault.CodeInvalidFormat},
		"format envelope key":    {initArgs("a", "--format-envelope", "json"), keyvault.CodeInvalidFormat},
		"extraction unknown":     {initArgs("a", "--extraction", "always"), keyvault.CodeInvalidExtraction},
		"extraction human se":    {initArgs("a", "--extraction", "human", "--enclave"), keyvault.CodeInvalidExtraction},
		"generate for key":       {initArgs("a", "--generate", "token:32"), keyvault.CodeInvalidGenerate},
		"title too long":         {initArgs("a", "--title", strings.Repeat("x", 81)), keyvault.CodeInvalidTitle},
		"meta reserved flag":     {initArgs("a", "--meta", "label=x"), keyvault.CodeInvalidMeta},
		"meta reserved json":     {initArgs("a", "--meta-json", reservedJSON), keyvault.CodeInvalidMeta},
		"meta nested json":       {initArgs("a", "--meta-json", nestedJSON), keyvault.CodeInvalidMeta},
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemStore()
			useStore(t, store)
			code, resp, raw := runJSON(t, tc.args...)
			if code != exitRefused || resp.Error == nil || resp.Error.Code != tc.code {
				t.Fatalf("code=%d resp=%s; want %s", code, raw, tc.code)
			}
			if store.touched() {
				t.Fatalf("refused init reached the store: creates=%v lists=%d", store.creates, store.lists)
			}
		})
	}
}

// The record round-trips through the production commands: init persists
// every field (title, description, usages, formats, the literal extraction
// choice, string/number/bool meta from --meta and --meta-json, not_after,
// origin, null issuer, created) into the tag under the .v1 label; describe
// and list --json return it flat with label, fingerprint, exposure,
// operations and findings; rotate copies it into version 2 with a new label
// and fresh created; meta get/set/unset edit only meta of the newest
// generation.
func TestRunRecordRoundTrip(t *testing.T) {
	store := newMemStore()
	useStore(t, store)
	now = func() time.Time { return time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { now = time.Now })
	metaJSON := filepath.Join(t.TempDir(), "meta.json")
	if err := os.WriteFile(metaJSON, []byte(`{"ttl": 30, "pinned": true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	code, resp, raw := runJSON(t, initArgs("rt", "--title", "Round trip", "--description", "used by the round trip test", "--usages", "verify,sign,decrypt", "--extraction", "agent",
		"--format-public", "spki-pem", "--format-signature", "ecdsa-raw", "--meta", "owner=alexis", "--meta", "pki=example", "--meta-json", metaJSON, "--not-after", "2027-01-01T00:00:00Z")...)
	if code != exitOK {
		t.Fatalf("init: %s", raw)
	}
	label := tl("rt", 1)
	result := resultMap(t, resp)
	usages := fmt.Sprint(result["usages"])
	if result["label"] != label || result["schema"] != 2.0 || result["kind"] != "key" || result["service"] != "test" || result["purpose"] != "rt" || result["version"] != 1.0 ||
		result["title"] != "Round trip" || result["description"] != "used by the round trip test" || result["algorithm"] != "ec-p256" || result["store"] != "keychain" ||
		result["exposure"] != "never" || result["extraction"] != "agent" || usages != "[sign verify decrypt]" || result["fingerprint"] == "" || result["issuer"] != nil {
		t.Fatalf("init result = %v", result)
	}
	format := result["format"].(map[string]any)
	meta := result["meta"].(map[string]any)
	origin := result["origin"].(map[string]any)
	validity := result["validity"].(map[string]any)
	if format["public"] != "spki-pem" || format["signature"] != "ecdsa-raw" || format["envelope"] != nil || meta["owner"] != "alexis" || meta["pki"] != "example" || meta["ttl"] != 30.0 || meta["pinned"] != true ||
		origin["source"] != "generated" || origin["tool"] != "mac-keyvault/"+Version || origin["user"] == "" || validity["not_after"] != "2027-01-01T00:00:00Z" || validity["not_before"] != nil {
		t.Fatalf("init result = %v", result)
	}
	if _, err := time.Parse(time.RFC3339, result["created"].(string)); err != nil {
		t.Fatalf("created = %v", result["created"])
	}
	stored := store.record(t, label)
	if stored.Title != "Round trip" || stored.Meta["ttl"] != json.Number("30") || stored.Format.Public != "spki-pem" || stored.Validity.NotAfter == nil || stored.Extraction != "agent" {
		t.Fatalf("stored = %+v", stored)
	}

	_, resp, raw = runJSON(t, "describe", "test/rt")
	described := resultMap(t, resp)
	for _, field := range []string{"label", "fingerprint", "exposure", "operations", "findings", "schema", "service", "purpose", "meta", "origin", "issuer", "validity"} {
		if _, ok := described[field]; !ok {
			t.Fatalf("describe lacks %s: %s", field, raw)
		}
	}
	if described["title"] != "Round trip" || described["fingerprint"] != result["fingerprint"] || len(described["findings"].([]any)) != 0 {
		t.Fatalf("describe = %s", raw)
	}
	exportPrivate := false
	for _, op := range described["operations"].([]any) {
		if op.(map[string]any)["name"] == "export-private" {
			exportPrivate = op.(map[string]any)["human_authorized"] == nil
		}
	}
	if !exportPrivate {
		t.Fatalf("extraction agent must advertise export-private without human_authorized: %s", raw)
	}
	_, resp, raw = runJSON(t, "list", "--service", "test")
	items := resp.Result.([]any)
	if len(items) != 1 || items[0].(map[string]any)["description"] != "used by the round trip test" {
		t.Fatalf("list = %s", raw)
	}
	if _, resp, _ = runJSON(t, "list", "--service", "other"); len(resp.Result.([]any)) != 0 {
		t.Fatal("service filter ignored")
	}
	if _, resp, _ = runJSON(t, "list", "--kind", "secret"); len(resp.Result.([]any)) != 0 {
		t.Fatal("kind filter ignored")
	}

	code, resp, raw = runJSON(t, "rotate", "test/rt")
	if code != exitOK {
		t.Fatalf("rotate: %s", raw)
	}
	rotated := resultMap(t, resp)
	newView := rotated["new"].(map[string]any)
	if newView["label"] != tl("rt", 2) || newView["version"] != 2.0 || newView["title"] != "Round trip" || fmt.Sprint(newView["usages"]) != usages || newView["extraction"] != "agent" ||
		newView["meta"].(map[string]any)["ttl"] != 30.0 || newView["format"].(map[string]any)["signature"] != "ecdsa-raw" || newView["validity"].(map[string]any)["not_after"] != "2027-01-01T00:00:00Z" ||
		newView["fingerprint"] == result["fingerprint"] || rotated["old"].(map[string]any)["label"] != label {
		t.Fatalf("rotate = %s", raw)
	}
	if _, ok := store.keys[label]; !ok || len(store.deletes) != 0 {
		t.Fatal("rotate removed the old generation")
	}
	if _, resp, _ = runJSON(t, "describe", "test/rt"); resultMap(t, resp)["version"] != 2.0 {
		t.Fatal("describe does not resolve to the newest generation")
	}
	if _, resp, _ = runJSON(t, "describe", "test/rt", "--version", "1"); resultMap(t, resp)["version"] != 1.0 {
		t.Fatal("describe --version 1 does not resolve to version 1")
	}

	if code, _, raw = runJSON(t, "meta", "set", "test/rt", "ticket", "MI-7"); code != exitOK {
		t.Fatalf("meta set: %s", raw)
	}
	if code, _, raw = runJSON(t, "meta", "set", "test/rt", "weight", "2.5", "--json-value"); code != exitOK {
		t.Fatalf("meta set json: %s", raw)
	}
	_, resp, _ = runJSON(t, "meta", "get", "test/rt")
	got := resultMap(t, resp)["meta"].(map[string]any)
	if got["ticket"] != "MI-7" || got["weight"] != 2.5 || got["owner"] != "alexis" {
		t.Fatalf("meta = %v", got)
	}
	_, resp, _ = runJSON(t, "meta", "get", "test/rt", "ticket")
	if resultMap(t, resp)["value"] != "MI-7" {
		t.Fatalf("meta get key = %+v", resp.Result)
	}
	if code, _, raw = runJSON(t, "meta", "unset", "test/rt", "ticket"); code != exitOK {
		t.Fatalf("meta unset: %s", raw)
	}
	v2 := store.record(t, tl("rt", 2))
	if _, ok := v2.Meta["ticket"]; ok || v2.Meta["weight"] != json.Number("2.5") || v2.Title != "Round trip" || len(store.updates) != 3 {
		t.Fatalf("stored v2 = %+v updates=%v", v2, store.updates)
	}
	for _, updated := range store.updates {
		if updated != tl("rt", 2) {
			t.Fatalf("meta edited %s instead of the newest generation", updated)
		}
	}
	if v1 := store.record(t, label); len(v1.Meta) != 4 {
		t.Fatalf("v1 meta changed: %v", v1.Meta)
	}
	// meta set --version 1 edits that generation only.
	if code, _, raw = runJSON(t, "meta", "set", "test/rt", "old", "yes", "--version", "1"); code != exitOK {
		t.Fatalf("meta set v1: %s", raw)
	}
	if v1 := store.record(t, label); v1.Meta["old"] != "yes" || store.updates[3] != label {
		t.Fatalf("v1 meta = %v updates=%v", v1.Meta, store.updates)
	}
}

// describe derives operations from the primitive registry: the ec-p256
// keychain key lists export-public via pub, ecdsa-sha256-sign via sign and
// ecdsa-sha256-verify via verify (T2), the rest reserved, a record whose (kind, algorithm, store) has no row reports []
// with unsupported_primitive (plus the invariant finding) and exposure
// unknown, and a rev1 tag under a
// parseable label is schema 1 with service and purpose unknown, no
// operations and no silent upgrade; text list shows every column.
func TestRunDescribeOperationsAndLegacy(t *testing.T) {
	store := newMemStore(tl("ops", 1))
	other := memItem(tl("p384", 1), 3)
	rec, _ := keyvault.DecodeRecord(other.Tag)
	rec.Algorithm = keyvault.AlgorithmECP384
	other.Tag, _ = keyvault.EncodeRecord(rec)
	store.keys[other.Label] = other
	legacy := tl("legacy", 1)
	store.keys[legacy] = keyvault.Item{Label: legacy, Tag: []byte("mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z"), SPKI: generatorSPKI(5)}
	useStore(t, store)

	_, resp, raw := runJSON(t, "describe", "test/ops")
	view := resultMap(t, resp)
	ops := view["operations"].([]any)
	names := map[string]string{}
	for _, op := range ops {
		names[op.(map[string]any)["name"].(string)] = op.(map[string]any)["via"].(string)
	}
	if names["export-public"] != "pub" || names["ecdsa-sha256-sign"] != "sign" || names["ecdsa-sha256-verify"] != "verify" || names["ecdh-p256"] != "" || names["ecies-p256-decrypt"] != "" || names["export-private"] != "" || len(view["findings"].([]any)) != 0 || view["exposure"] != "never" {
		t.Fatalf("operations = %s", raw)
	}

	_, resp, raw = runJSON(t, "describe", "test/p384")
	view = resultMap(t, resp)
	// A reserved algorithm on a stored key has no registry row AND
	// violates the algorithm invariant; both facts are reported, neither
	// is a refusal on read.
	if len(view["operations"].([]any)) != 0 || fmt.Sprint(view["findings"]) != "[unsupported_primitive record_invalid:unsupported_algorithm]" || view["exposure"] != "unknown" {
		t.Fatalf("unknown row = %s", raw)
	}

	_, resp, raw = runJSON(t, "describe", "test/legacy")
	view = resultMap(t, resp)
	if view["schema"] != 1.0 || view["service"] != "unknown" || view["purpose"] != "unknown" || view["kind"] != "unknown" || view["store"] != "keychain" || view["created"] != "2026-09-15T08:00:00Z" || len(view["operations"].([]any)) != 0 || fmt.Sprint(view["findings"]) != "[unsupported_primitive]" {
		t.Fatalf("legacy = %s", raw)
	}
	if string(store.keys[legacy].Tag) != "mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z" || len(store.updates) != 0 {
		t.Fatal("legacy tag was upgraded")
	}
	// Text-mode list shows every column with unknown for what the tag lacks.
	var stdout, stderr bytes.Buffer
	if code := run([]string{"list"}, &stdout, &stderr); code != exitOK {
		t.Fatalf("list: %d %s", code, stderr.String())
	}
	lines := strings.Split(strings.TrimSpace(stdout.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], legacy+"\tunknown\tunknown\tkeychain\tunknown\tunknown\t2026-09-15T08:00:00Z\t") {
		t.Fatalf("list lines = %q", lines)
	}
	if fields := strings.Split(lines[1], "\t"); len(fields) != 9 || fields[1] != "key" || fields[2] != "ec-p256" || fields[4] != "none" || fields[5] != "sign,verify" {
		t.Fatalf("second line = %q", lines[1])
	}
}

// rotate refuses, with exit 3 metadata_unknown and no create, a key whose
// store or policy is unknown: a rev1 tag, an absent tag, an unreadable tag,
// a schema-2 record with store unknown. The keychain is never assumed
// (review F4). Positive control: a complete schema-2 record rotates.
func TestRunRotateRefusesUnknownMetadata(t *testing.T) {
	label := tl("origin", 1)
	unknownStore := memItem(label, 1)
	rec, _ := keyvault.DecodeRecord(unknownStore.Tag)
	rec.Store = keyvault.StoreUnknown
	unknownStore.Tag, _ = keyvault.EncodeRecord(rec)
	// A key record carrying a forged non-null issuer (review F8).
	forgedIssuer := memItem(label, 1)
	rec, _ = keyvault.DecodeRecord(forgedIssuer.Tag)
	rec.Issuer = &keyvault.Issuer{DN: "CN=forged", Fingerprint: "sha256:00"}
	forgedIssuer.Tag, _ = keyvault.EncodeRecord(rec)
	// A key record carrying a forged non-null not_before, null not_after
	// (review F13).
	forgedNotBefore := memItem(label, 1)
	rec, _ = keyvault.DecodeRecord(forgedNotBefore.Tag)
	notBefore := keyvault.NewTime(time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC))
	rec.Validity = keyvault.Validity{NotBefore: &notBefore}
	forgedNotBefore.Tag, _ = keyvault.EncodeRecord(rec)
	// A complete schema-2 record followed by a second JSON document, token
	// or garbage in the persisted tag is unreadable, never a readable record
	// whose policy rotate may reproduce (review F12, class of F6).
	valid := memItem(label, 1)
	rec, _ = keyvault.DecodeRecord(valid.Tag)
	rec.Store = keyvault.StoreEnclave
	shadowTag, _ := keyvault.EncodeRecord(rec)
	trailingDocument, trailingToken, trailingGarbage := valid, valid, valid
	trailingDocument.Tag = append(append(append([]byte{}, valid.Tag...), '\n'), shadowTag...)
	trailingToken.Tag = append(append([]byte{}, valid.Tag...), []byte(" 1")...)
	trailingGarbage.Tag = append(append([]byte{}, valid.Tag...), '}')
	for name, item := range map[string]keyvault.Item{
		"rev1 keychain":     {Label: label, Tag: []byte("mac-keyvault/1 store=keychain created=2026-09-15T08:00:00Z"), SPKI: generatorSPKI(1)},
		"trailing document": trailingDocument,
		"trailing token":    trailingToken,
		"trailing garbage":  trailingGarbage,
		"rev1 enclave":      {Label: label, Tag: []byte("mac-keyvault/1 store=enclave created=2026-09-15T08:00:00Z"), SPKI: generatorSPKI(1)},
		"absent tag":        {Label: label, SPKI: generatorSPKI(1)},
		"unreadable":        {Label: label, Tag: []byte("{oops"), SPKI: generatorSPKI(1)},
		"unknown store":     unknownStore,
		"forged issuer":     forgedIssuer,
		"forged not_before": forgedNotBefore,
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemStore()
			store.keys[label] = item
			useStore(t, store)
			code, resp, raw := runJSON(t, "rotate", "test/origin")
			if code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeMetadataUnknown {
				t.Fatalf("code=%d resp=%s", code, raw)
			}
			if name == "forged issuer" && !strings.Contains(resp.Error.Message, keyvault.CodeInvalidIssuer) {
				t.Fatalf("forged issuer refused for another reason: %s", raw)
			}
			if name == "forged not_before" && !strings.Contains(resp.Error.Message, keyvault.CodeInvalidValidity) {
				t.Fatalf("forged not_before refused for another reason: %s", raw)
			}
			if len(store.creates) != 0 || len(store.keys) != 1 || !bytes.Equal(store.keys[label].Tag, item.Tag) {
				t.Fatalf("rotate guessed a store or rewrote the old tag: creates=%+v tag=%q", store.creates, store.keys[label].Tag)
			}
			if strings.HasPrefix(name, "trailing") && !strings.Contains(resp.Error.Message, "unreadable record") {
				t.Fatalf("trailing data refused for another reason: %s", raw)
			}
		})
	}
	// Positive control: the same address with a complete schema-2 key record
	// (issuer null) rotates once and the new generation carries issuer null.
	store := newMemStore(label)
	useStore(t, store)
	if code, _, raw := runJSON(t, "rotate", "test/origin"); code != exitOK || len(store.creates) != 1 {
		t.Fatalf("positive control: %d %s", code, raw)
	}
	if rec := store.record(t, tl("origin", 2)); rec.Issuer != nil {
		t.Fatalf("rotated key carries issuer %+v", rec.Issuer)
	}
}

// Every forged field of a stored schema-2 key (the shared recordtest table,
// one field at a time, plus a label that disagrees with the record) is
// refused through the production entry point: rotate and meta set/unset
// exit 3 with metadata_unknown naming the row's code, zero Backend.Create
// and Backend.UpdateTag calls, the old tag byte-identical; describe still
// prints the item, with findings naming record_invalid:<code>. The positive
// controls (validity both null, only a future not_after) rotate once and
// describe with no finding (review F13, class of F8/F12; orchestrator rev6).
func TestRunForgedStoredRecordRefusedEverywhere(t *testing.T) {
	label := tl("forged", 1)
	forgeries := append(recordtest.Forgeries(), recordtest.Forgery{Name: "label mismatch", Field: "version", Code: keyvault.CodeMetadataUnknown, Mutate: recordtest.LabelMismatch})
	for _, forgery := range forgeries {
		t.Run(forgery.Name, func(t *testing.T) {
			item := memItem(label, 1)
			rec, problem := keyvault.DecodeRecord(item.Tag)
			if problem != "" {
				t.Fatal(problem)
			}
			rec.Meta["owner"] = "t"
			forgery.Mutate(&rec)
			item.Tag, _ = keyvault.EncodeRecord(rec)
			store := newMemStore()
			store.keys[label] = item
			useStore(t, store)

			code, resp, raw := runJSON(t, "rotate", "test/forged")
			if code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeMetadataUnknown || !strings.Contains(resp.Error.Message, forgery.Code) {
				t.Fatalf("rotate: code=%d resp=%s (want %s naming %s)", code, raw, keyvault.CodeMetadataUnknown, forgery.Code)
			}
			if code, resp, raw := runJSON(t, "meta", "set", "test/forged", "note", "x"); code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeMetadataUnknown {
				t.Fatalf("meta set: code=%d resp=%s", code, raw)
			}
			if code, resp, raw := runJSON(t, "meta", "unset", "test/forged", "owner"); code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeMetadataUnknown {
				t.Fatalf("meta unset: code=%d resp=%s", code, raw)
			}
			if len(store.creates) != 0 || len(store.updates) != 0 || len(store.keys) != 1 || !bytes.Equal(store.keys[label].Tag, item.Tag) {
				t.Fatalf("a gate touched the store: creates=%d updates=%d keys=%d", len(store.creates), len(store.updates), len(store.keys))
			}
			code, resp, raw = runJSON(t, "describe", "test/forged")
			if code != exitOK {
				t.Fatalf("describe: code=%d resp=%s", code, raw)
			}
			if want := keyvault.FindingRecordInvalid + ":" + forgery.Code; !strings.Contains(fmt.Sprint(resultMap(t, resp)["findings"]), want) {
				t.Fatalf("describe findings do not name %s: %s", want, raw)
			}
		})
	}
	for name, control := range recordtest.PositiveControls() {
		t.Run("control "+name, func(t *testing.T) {
			item := memItem(label, 1)
			rec, _ := keyvault.DecodeRecord(item.Tag)
			control(&rec)
			item.Tag, _ = keyvault.EncodeRecord(rec)
			store := newMemStore()
			store.keys[label] = item
			useStore(t, store)
			if code, resp, raw := runJSON(t, "describe", "test/forged"); code != exitOK || fmt.Sprint(resultMap(t, resp)["findings"]) != "[]" {
				t.Fatalf("control describe: %d %s", code, raw)
			}
			if code, _, raw := runJSON(t, "rotate", "test/forged"); code != exitOK || len(store.creates) != 1 {
				t.Fatalf("control rotate: %d %s", code, raw)
			}
			next := store.record(t, tl("forged", 2))
			if next.Validity.NotBefore != nil || (rec.Validity.NotAfter == nil) != (next.Validity.NotAfter == nil) {
				t.Fatalf("rotated validity %+v, stored %+v", next.Validity, rec.Validity)
			}
			if code, _, raw := runJSON(t, "meta", "set", "test/forged", "note", "x"); code != exitOK || len(store.updates) != 1 {
				t.Fatalf("control meta set: %d %s", code, raw)
			}
		})
	}
}

// A persisted schema-2 record carrying a JSON member the schema does not
// define — at the top level or inside a nested struct such as format — is an
// unreadable record, never a readable one with the member silently erased
// before ValidateStored (review F14): rotate and meta set/unset exit 3
// metadata_unknown naming an unreadable record, zero Backend.Create and
// Backend.UpdateTag calls, the old tag byte-identical; describe still prints
// the item with the record_unreadable finding. Positive controls: the same
// member name inside meta (an open map) stays readable, rotates once and
// describes with no finding, so the strictness is about the schema, not the
// spelling of the name.
func TestRunUnknownRecordFieldIsUnreadableEverywhere(t *testing.T) {
	label := tl("future", 1)
	inject := func(t *testing.T, mutate func(map[string]any)) keyvault.Item {
		t.Helper()
		item := memItem(label, 1)
		var doc map[string]any
		if err := json.Unmarshal(item.Tag, &doc); err != nil {
			t.Fatal(err)
		}
		mutate(doc)
		item.Tag, _ = json.Marshal(doc)
		return item
	}
	for name, mutate := range map[string]func(map[string]any){
		"unknown top-level": func(doc map[string]any) { doc["future_top_level_policy"] = "deny" },
		"unknown nested format": func(doc map[string]any) {
			doc["format"].(map[string]any)["future_format_policy"] = "deny"
		},
		"unknown nested origin": func(doc map[string]any) { doc["origin"].(map[string]any)["pid"] = 1 },
		"unknown nested validity": func(doc map[string]any) {
			doc["validity"].(map[string]any)["renew_after"] = "2027-01-01T00:00:00Z"
		},
	} {
		t.Run(name, func(t *testing.T) {
			item := inject(t, mutate)
			store := newMemStore()
			store.keys[label] = item
			useStore(t, store)

			code, resp, raw := runJSON(t, "rotate", "test/future")
			if code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeMetadataUnknown || !strings.Contains(resp.Error.Message, "unreadable record") {
				t.Fatalf("rotate: code=%d resp=%s", code, raw)
			}
			if code, resp, raw := runJSON(t, "meta", "set", "test/future", "note", "x"); code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeMetadataUnknown {
				t.Fatalf("meta set: code=%d resp=%s", code, raw)
			}
			if code, resp, raw := runJSON(t, "meta", "unset", "test/future", "note"); code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeMetadataUnknown {
				t.Fatalf("meta unset: code=%d resp=%s", code, raw)
			}
			if len(store.creates) != 0 || len(store.updates) != 0 || len(store.keys) != 1 || !bytes.Equal(store.keys[label].Tag, item.Tag) {
				t.Fatalf("a gate touched the store: creates=%d updates=%d keys=%d tag=%q", len(store.creates), len(store.updates), len(store.keys), store.keys[label].Tag)
			}
			code, resp, raw = runJSON(t, "describe", "test/future")
			if code != exitOK || !strings.Contains(fmt.Sprint(resultMap(t, resp)["findings"]), keyvault.FindingRecordUnreadable) {
				t.Fatalf("describe: code=%d findings lack %s: %s", code, keyvault.FindingRecordUnreadable, raw)
			}
		})
	}
	for name, mutate := range map[string]func(map[string]any){
		"meta carries the top-level name": func(doc map[string]any) {
			doc["meta"].(map[string]any)["future_top_level_policy"] = "deny"
		},
		"meta carries the nested name": func(doc map[string]any) {
			doc["meta"].(map[string]any)["future_format_policy"] = "deny"
		},
	} {
		t.Run("control "+name, func(t *testing.T) {
			item := inject(t, mutate)
			store := newMemStore()
			store.keys[label] = item
			useStore(t, store)
			if code, resp, raw := runJSON(t, "describe", "test/future"); code != exitOK || fmt.Sprint(resultMap(t, resp)["findings"]) != "[]" {
				t.Fatalf("control describe: %d %s", code, raw)
			}
			if code, _, raw := runJSON(t, "rotate", "test/future"); code != exitOK || len(store.creates) != 1 {
				t.Fatalf("control rotate: %d %s", code, raw)
			}
			if code, _, raw := runJSON(t, "meta", "set", "test/future", "note", "x"); code != exitOK || len(store.updates) != 1 {
				t.Fatalf("control meta set: %d %s", code, raw)
			}
		})
	}
}

// --enclave and --user-presence map a -34018 from the store to
// missing_entitlement: exit 1, os_status -34018, the provisioning-profile
// hint, and exactly one create attempt of the requested shape — no keychain
// fallback.
func TestRunInitMissingEntitlementIsExplicit(t *testing.T) {
	for name, tc := range map[string]struct {
		flag    string
		store   keyvault.StoreKind
		present bool
	}{
		"enclave":       {flag: "--enclave", store: keyvault.StoreEnclave},
		"user-presence": {flag: "--user-presence", store: keyvault.StoreKeychain, present: true},
	} {
		t.Run(name, func(t *testing.T) {
			store := newMemStore()
			store.createE = &keyvault.StatusError{Op: "create", Status: -34018}
			useStore(t, store)
			code, resp, raw := runJSON(t, initArgs("cli-se", tc.flag)...)
			if code != exitFailure || resp.Error == nil || resp.Error.Code != keyvault.CodeMissingEntitlement || resp.Error.Status != -34018 {
				t.Fatalf("code=%d resp=%s", code, raw)
			}
			if !strings.Contains(resp.Error.Hint, "provisioning profile") || !strings.Contains(resp.Error.Hint, "login keychain") {
				t.Fatalf("hint lacks the documented remedy: %s", resp.Error.Hint)
			}
			if len(store.creates) != 1 || store.creates[0].Store != tc.store || store.creates[0].UserPresence != tc.present {
				t.Fatalf("creates = %+v", store.creates)
			}
			if len(store.keys) != 0 {
				t.Fatalf("a key exists after the refusal: %v", store.keys)
			}
			var stdout, stderr bytes.Buffer
			if code := run(initArgs("cli-se", tc.flag), &stdout, &stderr); code != exitFailure || !strings.Contains(stderr.String(), "os_status: -34018 (errSecMissingEntitlement)") {
				t.Fatalf("text mode: %d %q", code, stderr.String())
			}
		})
	}
}

// pub writes SPKI DER, PEM or JWK depending on --format, the --out
// extension, or the record's format.public; all parse as the same P-256 key;
// files are 0600; JSON mode reports format, out and the encoded key.
func TestRunPubFormats(t *testing.T) {
	label := tl("cli-pub", 1)
	store := newMemStore(label)
	useStore(t, store)
	dir := t.TempDir()
	derPath, pemPath, jwkPath, forced := filepath.Join(dir, "spki.der"), filepath.Join(dir, "spki.pem"), filepath.Join(dir, "spki.jwk"), filepath.Join(dir, "spki.bin")

	var stdout, stderr bytes.Buffer
	for _, args := range [][]string{{"pub", "test/cli-pub", "--out", derPath}, {"pub", "test/cli-pub", "--out", pemPath}, {"pub", "test/cli-pub", "--out", jwkPath}} {
		if code := run(args, &stdout, &stderr); code != exitOK {
			t.Fatalf("%v: %d %s", args, code, stderr.String())
		}
	}
	code, resp, raw := runJSON(t, "pub", "test/cli-pub", "--out", forced, "--format", "spki-pem")
	if code != exitOK {
		t.Fatalf("forced pem: %s", raw)
	}
	result := resultMap(t, resp)
	if result["format"] != "spki-pem" || result["out"] != forced || result["fingerprint"] != (keyvault.Key{SPKI: store.keys[label].SPKI}).Fingerprint() {
		t.Fatalf("result = %v", result)
	}
	der, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(der, store.keys[label].SPKI) {
		t.Fatalf("der artifact differs from SPKI")
	}
	for _, path := range []string{pemPath, forced} {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		block, _ := pem.Decode(data)
		if block == nil || block.Type != "PUBLIC KEY" || !bytes.Equal(block.Bytes, der) {
			t.Fatalf("%s is not the SPKI PEM: %s", path, data)
		}
	}
	jwkData, _ := os.ReadFile(jwkPath)
	var jwk map[string]string
	if err := json.Unmarshal(jwkData, &jwk); err != nil || jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["x"] == "" {
		t.Fatalf("jwk = %s", jwkData)
	}
	for _, path := range []string{derPath, pemPath, jwkPath, forced} {
		if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s mode = %v", path, info.Mode())
		}
	}
	// stdout without --out follows the record default (spki-der) unless
	// --format says otherwise.
	stdout.Reset()
	if code := run([]string{"pub", "test/cli-pub"}, &stdout, &stderr); code != exitOK || !bytes.Equal(stdout.Bytes(), der) {
		t.Fatalf("stdout der: %d %x", code, stdout.Bytes())
	}
	stdout.Reset()
	if code := run([]string{"pub", "test/cli-pub", "--format", "spki-pem"}, &stdout, &stderr); code != exitOK || !strings.HasPrefix(stdout.String(), "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("stdout pem: %d %q", code, stdout.String())
	}
	item := store.keys[label]
	rec, _ := keyvault.DecodeRecord(item.Tag)
	rec.Format.Public = keyvault.FormatPublicJWK
	item.Tag, _ = keyvault.EncodeRecord(rec)
	store.keys[label] = item
	stdout.Reset()
	if code := run([]string{"pub", "test/cli-pub"}, &stdout, &stderr); code != exitOK || !strings.HasPrefix(stdout.String(), `{"crv":"P-256"`) {
		t.Fatalf("record default jwk: %d %q", code, stdout.String())
	}
	// JSON without --out embeds the encoded key.
	_, resp, _ = runJSON(t, "pub", "test/cli-pub", "--format", "spki-der")
	if encoded, _ := resultMap(t, resp)["der_base64"].(string); encoded != base64.StdEncoding.EncodeToString(der) {
		t.Fatalf("json der = %q", encoded)
	}
	_, resp, _ = runJSON(t, "pub", "test/cli-pub", "--format", "spki-pem")
	if pemText, _ := resultMap(t, resp)["pem"].(string); !strings.HasPrefix(pemText, "-----BEGIN PUBLIC KEY-----") {
		t.Fatalf("json pem = %q", pemText)
	}
	_, resp, _ = runJSON(t, "pub", "test/cli-pub")
	if got, _ := resultMap(t, resp)["jwk"].(map[string]any); got["kty"] != "EC" {
		t.Fatalf("json jwk = %v", got)
	}
}

// Unknown Security statuses surface as security with the OSStatus, its
// name in the message, and exit 1, never as a policy refusal.
func TestRunSecurityErrorIsExitOne(t *testing.T) {
	store := newMemStore()
	store.createE = &keyvault.StatusError{Op: "create", Status: -25293}
	useStore(t, store)
	code, resp, raw := runJSON(t, initArgs("cli-err")...)
	if code != exitFailure || resp.Error == nil || resp.Error.Code != keyvault.CodeSecurity || resp.Error.Status != -25293 || !strings.Contains(resp.Error.Message, "errSecAuthFailed") {
		t.Fatalf("code=%d %s", code, raw)
	}
}

func TestVersionAndHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"version"}, &stdout, &stderr); code != exitOK || !strings.HasPrefix(stdout.String(), "mac-keyvault ") {
		t.Fatalf("%d %q", code, stdout.String())
	}
	stdout.Reset()
	if code := run([]string{"help"}, &stdout, &stderr); code != exitOK || !strings.Contains(stdout.String(), keyvault.LabelPrefix) {
		t.Fatalf("%d %q", code, stdout.String())
	}
}

// guardedBackend fails any Create/Delete/UpdateTag outside the test prefix
// before it reaches the real keychain and remembers labels for cleanup.
type guardedBackend struct {
	t       *testing.T
	inner   keyvault.Backend
	touched []string
}

func (g *guardedBackend) guard(label string) error {
	if !keyvault.IsTestLabel(label) {
		g.t.Errorf("test guard: %q is outside the test namespace %s", label, testPrefix)
		return fmt.Errorf("test guard refused %q", label)
	}
	g.touched = append(g.touched, label)
	return nil
}

func (g *guardedBackend) Create(opts keyvault.CreateOptions) (keyvault.Item, error) {
	if err := g.guard(opts.Label); err != nil {
		return keyvault.Item{}, err
	}
	return g.inner.Create(opts)
}

func (g *guardedBackend) List() ([]keyvault.Item, error) { return g.inner.List() }

func (g *guardedBackend) Delete(label string) error {
	if err := g.guard(label); err != nil {
		return err
	}
	return g.inner.Delete(label)
}

func (g *guardedBackend) UpdateTag(label string, tag []byte) error {
	if err := g.guard(label); err != nil {
		return err
	}
	return g.inner.UpdateTag(label, tag)
}

func (g *guardedBackend) Sign(label string, digest []byte) ([]byte, error) {
	if err := g.guard(label); err != nil {
		return nil, err
	}
	return g.inner.Sign(label, digest)
}

// End-to-end against the login keychain on this Mac through the production
// SecurityStore: init with a full record, the duplicate refusal, the
// explicit --enclave refusal with -34018, list, describe, pub, meta set/get,
// rotate, delete unconfirmed, delete both generations, delete twice. All
// labels are test prefixed (service test) and removed in cleanup.
func TestRunAgainstLoginKeychain(t *testing.T) {
	guard := &guardedBackend{t: t, inner: newTestSecurityStore(t)}
	useStore(t, guard)
	t.Cleanup(func() {
		for _, label := range guard.touched {
			if err := guard.inner.Delete(label); err != nil && !errors.Is(err, keyvault.ErrNotFound) {
				t.Errorf("cleanup %s: %v", label, err)
			}
		}
	})
	purpose := fmt.Sprintf("cli-e2e-%d", os.Getpid())
	addr := "test/" + purpose
	label := tl(purpose, 1)

	code, resp, raw := runJSON(t, initArgs(purpose, "--title", "e2e", "--meta", "owner=e2e")...)
	if code != exitOK {
		t.Fatalf("init: %s", raw)
	}
	fingerprint := resultMap(t, resp)["fingerprint"].(string)

	if code, resp, raw = runJSON(t, initArgs(purpose)...); code != exitRefused || resp.Error.Code != keyvault.CodeDuplicate {
		t.Fatalf("duplicate: %s", raw)
	}
	if code, resp, raw = runJSON(t, initArgs(purpose+"-se", "--enclave")...); code != exitFailure || resp.Error.Code != keyvault.CodeMissingEntitlement || resp.Error.Status != -34018 {
		t.Fatalf("enclave: %s", raw)
	}
	if err := guard.inner.Delete(tl(purpose+"-se", 1)); !errors.Is(err, keyvault.ErrNotFound) {
		t.Fatalf("enclave refusal left a keychain key behind: %v", err)
	}

	_, resp, raw = runJSON(t, "list", "--service", "test")
	found := false
	for _, item := range resp.Result.([]any) {
		view := item.(map[string]any)
		if view["label"] == label {
			found = view["store"] == "keychain" && view["fingerprint"] == fingerprint && view["created"] != nil && view["title"] == "e2e" && view["schema"] == 2.0
		}
	}
	if !found {
		t.Fatalf("list lacks the created key with its record: %s", raw)
	}
	_, resp, raw = runJSON(t, "describe", addr)
	if view := resultMap(t, resp); view["meta"].(map[string]any)["owner"] != "e2e" || len(view["operations"].([]any)) == 0 {
		t.Fatalf("describe: %s", raw)
	}

	derPath := filepath.Join(t.TempDir(), "spki.der")
	if code, _, raw = runJSON(t, "pub", addr, "--out", derPath); code != exitOK {
		t.Fatalf("pub: %s", raw)
	}
	der, err := os.ReadFile(derPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := x509.ParsePKIXPublicKey(der); err != nil {
		t.Fatalf("pub wrote an unparsable SPKI: %v", err)
	}

	if code, _, raw = runJSON(t, "meta", "set", addr, "ticket", "MI-7"); code != exitOK {
		t.Fatalf("meta set: %s", raw)
	}
	if _, resp, raw = runJSON(t, "meta", "get", addr, "ticket"); resultMap(t, resp)["value"] != "MI-7" {
		t.Fatalf("meta get after real update: %s", raw)
	}

	if code, resp, raw = runJSON(t, "rotate", addr); code != exitOK {
		t.Fatalf("rotate: %s", raw)
	}
	rotated := resultMap(t, resp)["new"].(map[string]any)
	if rotated["label"] != tl(purpose, 2) || rotated["meta"].(map[string]any)["ticket"] != "MI-7" {
		t.Fatalf("rotate: %s", raw)
	}
	if code, _, raw = runJSON(t, "pub", addr, "--version", "1"); code != exitOK {
		t.Fatalf("old key gone after rotate: %s", raw)
	}

	if code, resp, raw = runJSON(t, "delete", addr); code != exitRefused || resp.Error.Code != keyvault.CodeConfirmationRequired {
		t.Fatalf("delete unconfirmed: %s", raw)
	}
	if code, resp, raw = runJSON(t, "delete", addr, "--confirm", "--version", "2"); code != exitOK || resultMap(t, resp)["label"] != tl(purpose, 2) {
		t.Fatalf("delete v2: %s", raw)
	}
	if code, resp, raw = runJSON(t, "delete", addr, "--confirm"); code != exitOK || resultMap(t, resp)["label"] != label {
		t.Fatalf("delete v1: %s", raw)
	}
	if code, resp, raw = runJSON(t, "delete", addr, "--confirm"); code != exitFailure || resp.Error.Code != "not_found" {
		t.Fatalf("delete twice: %s", raw)
	}
	for _, touched := range guard.touched {
		if !keyvault.IsTestLabel(touched) {
			t.Fatalf("non-test label touched: %s", touched)
		}
	}
}

// jsonTrueSpellings is every spelling of a true json flag the command
// parser (flag.Bool via strconv.ParseBool) accepts: bare, and =1/t/T/TRUE/
// true/True with one or two dashes.
func jsonTrueSpellings() []string {
	spellings := []string{"--json", "-json"}
	for _, value := range []string{"1", "t", "T", "TRUE", "true", "True"} {
		spellings = append(spellings, "--json="+value, "-json="+value)
	}
	return spellings
}

// JSON-mode detection admits exactly the spellings the command parser
// admits (review F9, repeat of F6/F3): with every true spelling, placed
// before or after the command, a usage error is a parseable
// {ok:false, error:{code:"usage"}} envelope on stdout, exit 2, empty
// stderr and zero store calls; the same spelling on a valid command is a
// {ok:true} envelope (positive control). False spellings (=0/f/false/F/
// FALSE/False) and non-json tokens (--jsonx, --json=maybe, --json=) never
// select the envelope, and a later --json=false overrides an earlier --json
// exactly as the command parser resolves repeated flags.
func TestRunJSONSpellingsRouteUsageErrors(t *testing.T) {
	for _, spelling := range jsonTrueSpellings() {
		for placement, args := range map[string][]string{
			"first": {spelling, "version", "extra"},
			"after": {"version", spelling, "extra"},
			"last":  {"version", "extra", spelling},
		} {
			t.Run(spelling+" "+placement, func(t *testing.T) {
				store := newMemStore(tl("a", 1))
				useStore(t, store)
				var stdout, stderr bytes.Buffer
				code := run(args, &stdout, &stderr)
				var resp response
				if err := json.Unmarshal(stdout.Bytes(), &resp); err != nil {
					t.Fatalf("stdout is not a JSON envelope (%v): stdout=%q stderr=%q", err, stdout.String(), stderr.String())
				}
				if code != exitUsage || resp.OK || resp.Error == nil || resp.Error.Code != "usage" || resp.Error.Hint != usageLines["version"] || stderr.Len() != 0 || store.touched() {
					t.Fatalf("code=%d resp=%+v stderr=%q touched=%v", code, resp, stderr.String(), store.touched())
				}
			})
		}
		t.Run(spelling+" positive", func(t *testing.T) {
			for _, args := range [][]string{{spelling, "version"}, {"version", spelling}} {
				var stdout, stderr bytes.Buffer
				var resp response
				if code := run(args, &stdout, &stderr); code != exitOK || json.Unmarshal(stdout.Bytes(), &resp) != nil || !resp.OK || resp.Command != "version" || stderr.Len() != 0 {
					t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
				}
			}
		})
	}
	// "--" ends flag parsing in both the detector and the command parser:
	// a --json before it counts, the same token after it is a positional.
	t.Run("json before terminator", func(t *testing.T) {
		store := newMemStore()
		useStore(t, store)
		var stdout, stderr bytes.Buffer
		var resp response
		if code := run([]string{"--json", "version", "--", "extra"}, &stdout, &stderr); code != exitUsage || json.Unmarshal(stdout.Bytes(), &resp) != nil || resp.Error == nil || resp.Error.Code != "usage" || stderr.Len() != 0 {
			t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
		}
	})
	// Negative controls: text mode stays text mode.
	for name, args := range map[string][]string{
		"false":            {"--json=false", "version", "extra"},
		"zero":             {"version", "--json=0", "extra"},
		"F":                {"version", "extra", "-json=F"},
		"FALSE":            {"--json=FALSE", "version", "extra"},
		"False":            {"-json=False", "version", "extra"},
		"f":                {"--json=f", "version", "extra"},
		"later false wins": {"--json", "version", "extra", "--json=false"},
		"lookalike flag":   {"--jsonx", "version"},
		"non-bool value":   {"version", "--json=maybe"},
		"empty value":      {"version", "--json="},
		"terminator":       {"version", "--", "--json"},
		"terminator first": {"--", "--json", "version"},
	} {
		t.Run("text "+name, func(t *testing.T) {
			store := newMemStore()
			useStore(t, store)
			var stdout, stderr bytes.Buffer
			code := run(args, &stdout, &stderr)
			if code != exitUsage || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "error: usage: ") || store.touched() {
				t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
		})
	}
}

// list --kind goes through the closed kind vocabulary before the manager
// exists (review F10): an unknown kind is invalid_kind, exit 3, and
// Backend.List is never called, in JSON and text mode. Positive controls:
// every kind in the vocabulary reaches the store once and filters by label
// (key returns the own items, secret returns []); --service is validated
// the same way.
func TestRunListRejectsInvalidKindBeforeBackend(t *testing.T) {
	for _, kind := range []string{"bogus", "keypair", "Key", "key.", "", "*"} {
		if kind == "" {
			continue // empty means "no filter" and is a positive control below
		}
		t.Run("json "+kind, func(t *testing.T) {
			store := newMemStore(tl("a", 1))
			useStore(t, store)
			code, resp, raw := runJSON(t, "list", "--kind", kind)
			if code != exitRefused || resp.Error == nil || resp.Error.Code != keyvault.CodeInvalidKind || store.lists != 0 || store.touched() {
				t.Fatalf("kind %q admitted: code=%d %s lists=%d", kind, code, raw, store.lists)
			}
		})
		t.Run("text "+kind, func(t *testing.T) {
			store := newMemStore(tl("a", 1))
			useStore(t, store)
			var stdout, stderr bytes.Buffer
			code := run([]string{"list", "--kind", kind}, &stdout, &stderr)
			if code != exitRefused || stdout.Len() != 0 || !strings.HasPrefix(stderr.String(), "error: "+keyvault.CodeInvalidKind+": ") || store.lists != 0 {
				t.Fatalf("kind %q admitted: code=%d stdout=%q stderr=%q lists=%d", kind, code, stdout.String(), stderr.String(), store.lists)
			}
		})
	}
	for kind, want := range map[string]int{"key": 2, "public-key": 0, "certificate": 0, "secret": 0, "": 2} {
		store := newMemStore(tl("a", 1), tl("b", 1))
		useStore(t, store)
		args := []string{"list"}
		if kind != "" {
			args = append(args, "--kind", kind)
		}
		code, resp, raw := runJSON(t, args...)
		got, _ := resp.Result.([]any)
		if code != exitOK || store.lists != 1 || len(got) != want {
			t.Fatalf("positive control kind %q: code=%d lists=%d result=%s", kind, code, store.lists, raw)
		}
	}
	store := newMemStore(tl("a", 1))
	useStore(t, store)
	if code, resp, raw := runJSON(t, "list", "--service", "Bad"); code != exitRefused || resp.Error.Code != keyvault.CodeInvalidService || store.lists != 0 {
		t.Fatalf("service filter: code=%d %s lists=%d", code, raw, store.lists)
	}
}

// Numeric meta round-trips digit-exact through init --meta-json, the stored
// schema-2 tag, describe, list, meta set --json-value, meta get and rotate
// (review F11): 9007199254740993 (2^53+1, not representable in float64) and
// 18446744073709551617 (2^64+1, beyond every machine integer) appear
// verbatim in the raw tag and the raw envelopes; a small integer and a
// fraction are the nearby positive controls; the text-mode meta get prints
// the digits as typed.
func TestRunMetaNumberRoundTrips(t *testing.T) {
	const big, huge = "9007199254740993", "18446744073709551617"
	metaFile := filepath.Join(t.TempDir(), "meta.json")
	if err := os.WriteFile(metaFile, []byte(`{"big": `+big+`, "small": 7, "frac": 0.1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	store := newMemStore()
	useStore(t, store)
	code, _, raw := runJSON(t, initArgs("num", "--meta-json", metaFile)...)
	if code != exitOK {
		t.Fatalf("init: %s", raw)
	}
	tagV1 := string(store.keys[tl("num", 1)].Tag)
	for _, want := range []string{`"big":` + big, `"small":7`, `"frac":0.1`} {
		if !strings.Contains(tagV1, want) {
			t.Fatalf("stored tag lacks %s: %s", want, tagV1)
		}
	}
	rec := store.record(t, tl("num", 1))
	if rec.Meta["big"] != json.Number(big) || rec.Meta["small"] != json.Number("7") || rec.Meta["frac"] != json.Number("0.1") {
		t.Fatalf("decoded meta = %#v", rec.Meta)
	}
	if !strings.Contains(raw, `"big": `+big) {
		t.Fatalf("init envelope rounded the number: %s", raw)
	}
	for _, args := range [][]string{{"describe", "test/num"}, {"list"}, {"meta", "get", "test/num"}} {
		if _, _, raw := runJSON(t, args...); !strings.Contains(raw, `"big": `+big) || !strings.Contains(raw, `"small": 7`) || !strings.Contains(raw, `"frac": 0.1`) {
			t.Fatalf("%v envelope rounded the number: %s", args, raw)
		}
	}
	if code, _, raw := runJSON(t, "meta", "set", "test/num", "huge", huge, "--json-value"); code != exitOK || !strings.Contains(raw, `"huge": `+huge) {
		t.Fatalf("meta set: %d %s", code, raw)
	}
	tagV1 = string(store.keys[tl("num", 1)].Tag)
	if !strings.Contains(tagV1, `"huge":`+huge) || !strings.Contains(tagV1, `"big":`+big) {
		t.Fatalf("stored tag after meta set: %s", tagV1)
	}
	if _, _, raw := runJSON(t, "meta", "get", "test/num", "huge"); !strings.Contains(raw, `"value": `+huge) {
		t.Fatalf("meta get value: %s", raw)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"meta", "get", "test/num", "big"}, &stdout, &stderr); code != exitOK || stdout.String() != big+"\n" {
		t.Fatalf("text meta get: %d %q %q", code, stdout.String(), stderr.String())
	}
	if code, _, raw := runJSON(t, "rotate", "test/num"); code != exitOK || !strings.Contains(raw, `"big": `+big) || !strings.Contains(raw, `"huge": `+huge) {
		t.Fatalf("rotate: %d %s", code, raw)
	}
	tagV2 := string(store.keys[tl("num", 2)].Tag)
	for _, want := range []string{`"big":` + big, `"huge":` + huge, `"small":7`, `"frac":0.1`} {
		if !strings.Contains(tagV2, want) {
			t.Fatalf("rotated tag lacks %s: %s", want, tagV2)
		}
	}
	if tagV1 != string(store.keys[tl("num", 1)].Tag) {
		t.Fatalf("rotate rewrote the old generation: %s", store.keys[tl("num", 1)].Tag)
	}
}
