package keyvault

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault/signerclient"
	"github.com/relux-works/swarma-keyvault/internal/keyvault/signertest"
)

var updateGolden = flag.Bool("update", false, "rewrite the signer-v1 golden responses from the current server output")

const goldenDir = signertest.Dir

// goldenMaterial is testdata/signer-v1/fixture-key.json: one P-256 SPKI,
// one digest and one low-S DER signature over it under that key, so the
// canned backend's answer is fixed and every response line is
// reproducible byte for byte.
type goldenMaterial struct {
	SPKI   []byte
	Digest []byte
	DER    []byte
}

func loadGoldenMaterial(t *testing.T) goldenMaterial {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(goldenDir, "fixture-key.json"))
	if err != nil {
		t.Fatal(err)
	}
	var raw struct {
		SPKI   string `json:"spki_der_base64"`
		Digest string `json:"digest_hex"`
		DER    string `json:"signature_der_hex"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatal(err)
	}
	spki, err := base64.StdEncoding.DecodeString(raw.SPKI)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := hex.DecodeString(raw.Digest)
	if err != nil {
		t.Fatal(err)
	}
	der, err := hex.DecodeString(raw.DER)
	if err != nil {
		t.Fatal(err)
	}
	// Premise: the canned signature verifies under the canned key, so a
	// fixture that says verified:true is a real verdict.
	sig, err := ParseSignature(der, FormatSignatureDERLowS)
	if err != nil || !sig.IsLowS() {
		t.Fatalf("fixture signature: %v low-S=%v", err, sig.IsLowS())
	}
	if ok, err := VerifyDigest(spki, digest, sig); err != nil || !ok {
		t.Fatalf("fixture signature does not verify: %v %v", ok, err)
	}
	return goldenMaterial{SPKI: spki, Digest: digest, DER: der}
}

// cannedStore signs exactly one digest with one canned signature; any
// other digest is a backend failure, so a fixture cannot sign something
// the material does not cover.
type cannedStore struct {
	*fakeStore
	material goldenMaterial
	// corruptDER, when set, is what Sign returns instead of the canned
	// signature: a well-formed low-S DER that does not verify under the
	// canned key, standing in for a damaged keychain item or bridge.
	corruptDER []byte
	// listE and signE, when set, are what List and Sign return: a
	// StatusError stands in for a Security.framework status, a plain
	// error for a backend failure outside the status space.
	listE, signE error
}

func (s *cannedStore) List() ([]Item, error) {
	if s.listE != nil {
		s.mu.Lock()
		s.lists++
		s.mu.Unlock()
		return nil, s.listE
	}
	return s.fakeStore.List()
}

func (s *cannedStore) Sign(label string, digest []byte) ([]byte, error) {
	s.mu.Lock()
	s.signs = append(s.signs, label)
	s.mu.Unlock()
	if _, ok := s.keys[label]; !ok {
		return nil, ErrNotFound
	}
	if s.signE != nil {
		return nil, s.signE
	}
	if !bytes.Equal(digest, s.material.Digest) {
		return nil, fmt.Errorf("cannedStore: digest %x is not the golden digest", digest)
	}
	if s.corruptDER != nil {
		return s.corruptDER, nil
	}
	return s.material.DER, nil
}

// corruptDER is r=1, s=1 in strict DER: parses, is low-S, and verifies
// under no P-256 key for the golden digest.
var corruptDER = []byte{0x30, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01}

func goldenClock() time.Time { return time.Date(2026, 9, 15, 10, 0, 0, 0, time.UTC) }

// goldenSessions builds the store and address of each fixture session:
// signer (usages sign,verify), verify-only (usages verify), expired
// (not_after in the past), unreadable (a tag that is not a record →
// metadata_unknown), no-row (store enclave, no registry row →
// unsupported_primitive), no-spki (public half unreadable → security on
// pub and verify), corrupt (the backend signs with a signature that does
// not verify under the key → security on sign), bad-spki (a public half
// that is not a P-256 SPKI → invalid_public_key on verify, security on
// sign), entitlement (the backend answers sign with OSStatus -34018 →
// missing_entitlement) and backend-failure (the backend answers sign with
// an error outside the OSStatus space → failure) share the canned SPKI;
// missing has no item, hello-security, hello-entitlement and
// hello-failure have a backend whose listing fails (security with
// os_status, missing_entitlement, failure in the hello).
func goldenSessions(t *testing.T, material goldenMaterial) map[string]*SignerServer {
	t.Helper()
	// Every valid key record has a registry row since the enclave row, so
	// the no-row session takes that row away for the test.
	withoutRegistryRow(t, PrimitiveKey{Kind: KindKey, Algorithm: AlgorithmECP256, Store: StoreEnclave})
	sessions := map[string]*SignerServer{}
	build := func(name string, adjust func(*Record, *Item, *cannedStore)) {
		label := tl(name, 1)
		store := &cannedStore{fakeStore: newFakeStore(), material: material}
		if adjust != nil {
			rec := testRecord(label)
			rec.Title = "golden " + name
			rec.Description = "signer contract v1 golden fixture"
			rec.Meta = map[string]any{"owner": "golden"}
			item := Item{Label: label, SPKI: material.SPKI}
			adjust(&rec, &item, store)
			if item.Tag == nil {
				tag, err := EncodeRecord(rec)
				if err != nil {
					t.Fatal(err)
				}
				item.Tag = tag
			}
			store.keys[label] = item
		}
		m := NewManager(store, NoLock{}, testOrigin)
		m.SetClock(goldenClock)
		sessions[name] = &SignerServer{Manager: m, Address: Address{Kind: KindKey, Service: TestService, Purpose: name}, ToolVersion: "test"}
	}
	build("signer", func(*Record, *Item, *cannedStore) {})
	build("verify-only", func(rec *Record, _ *Item, _ *cannedStore) { rec.Usages = []string{"verify"} })
	build("expired", func(rec *Record, _ *Item, _ *cannedStore) {
		notAfter := NewTime(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
		rec.Validity.NotAfter = &notAfter
	})
	build("unreadable", func(_ *Record, item *Item, _ *cannedStore) { item.Tag = []byte("not a mac-keyvault record") })
	build("no-row", func(rec *Record, _ *Item, _ *cannedStore) { rec.Store = StoreEnclave })
	build("no-spki", func(_ *Record, item *Item, _ *cannedStore) { item.SPKI = nil })
	build("corrupt", func(_ *Record, _ *Item, store *cannedStore) { store.corruptDER = corruptDER })
	build("bad-spki", func(_ *Record, item *Item, _ *cannedStore) { item.SPKI = []byte("not a subject public key info") })
	build("entitlement", func(_ *Record, _ *Item, store *cannedStore) {
		store.signE = &StatusError{Op: "SecKeyCreateSignature", Status: errSecMissingEntitlement}
	})
	build("backend-failure", func(_ *Record, _ *Item, store *cannedStore) {
		store.signE = errors.New("bridge: helper exited before answering")
	})
	build("missing", nil)
	build("hello-security", nil)
	sessions["hello-security"].Manager.backend.(*cannedStore).listE = &StatusError{Op: "SecItemCopyMatching", Status: -25308}
	build("hello-entitlement", nil)
	sessions["hello-entitlement"].Manager.backend.(*cannedStore).listE = &StatusError{Op: "SecItemCopyMatching", Status: errSecMissingEntitlement}
	build("hello-failure", nil)
	sessions["hello-failure"].Manager.backend.(*cannedStore).listE = errors.New("bridge: helper exited before answering")
	return sessions
}

// startupFailures are the sessions whose hello is ok=false: Serve must
// return an error the CLI maps to the code the hello carries.
var startupFailures = map[string]string{"missing": CodeNotFound, "hello-security": CodeSecurity, "hello-entitlement": CodeMissingEntitlement, "hello-failure": CodeFailure}

// loadGoldenFixtures loads the corpus and returns the server-driven
// sessions; the startup session belongs to the CLI package
// (TestRunSignerServeStartupGolden), which drives run() for it.
func loadGoldenFixtures(t *testing.T) (server map[string][]signertest.Fixture, startup []signertest.Fixture) {
	t.Helper()
	fixtures, err := signertest.Load(goldenDir)
	if err != nil {
		t.Fatal(err)
	}
	startup = fixtures[signertest.StartupSession]
	delete(fixtures, signertest.StartupSession)
	return fixtures, startup
}

// The signer-v1 wire is pinned byte for byte: for every server fixture
// session the request lines are sent in file order through one
// SignerServer.Serve call over a canned backend and a fixed clock, and
// each response line — hello first — must equal the fixture's response
// exactly (bytes, including key order). The signer session interleaves
// error responses (bad_request incl. zero-valued members an op does not
// take, missing_id, unknown_op, invalid_digest, invalid_signature,
// high_s_refused, signature_invalid) with later successful requests, and
// every other served session ends with a successful request after its
// refusals, so a green run also proves no error ended the stream; the
// startup-failure sessions (missing, hello-security, hello-entitlement,
// hello-failure) prove a failed hello is one line with ok=false and a
// returned error of that code. Run with -update to regenerate the
// response fields from the current server; review the diff, never the
// run. The startup session is driven by the CLI package.
func TestSignerServeGoldenWire(t *testing.T) {
	material := loadGoldenMaterial(t)
	sessions := goldenSessions(t, material)
	fixtures, _ := loadGoldenFixtures(t)
	if len(fixtures) != len(sessions) {
		t.Fatalf("fixture sessions %v, server sessions %d", keysOf(fixtures), len(sessions))
	}
	for name, server := range sessions {
		t.Run(name, func(t *testing.T) {
			list := fixtures[name]
			if len(list) == 0 || !list[0].IsHello() {
				t.Fatalf("session %s must start with a hello fixture (no request)", name)
			}
			var in bytes.Buffer
			for _, f := range list[1:] {
				if f.IsHello() {
					t.Fatalf("%s: only the first fixture of a session may lack a request", f.Path)
				}
				line, err := f.RequestLine()
				if err != nil {
					t.Fatal(err)
				}
				in.Write(line)
				in.WriteByte('\n')
			}
			var out bytes.Buffer
			err := server.Serve(&in, &out)
			if code, failing := startupFailures[name]; failing {
				if err == nil || ClassifyError(err).Code != code {
					t.Fatalf("%s session: Serve returned %v, want a %s error", name, err, code)
				}
			} else if err != nil {
				t.Fatalf("Serve: %v", err)
			}
			lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
			if len(lines) != len(list) {
				t.Fatalf("server wrote %d lines for %d fixtures:\n%s", len(lines), len(list), out.String())
			}
			for i, f := range list {
				if *updateGolden {
					if err := signertest.Save(f, lines[i]); err != nil {
						t.Fatal(err)
					}
					continue
				}
				if f.Response == nil {
					t.Fatalf("%s: no response recorded; run with -update", f.Path)
				}
				if lines[i] != *f.Response {
					t.Errorf("%s (%s):\n got: %s\nwant: %s", f.Path, f.Note, lines[i], *f.Response)
				}
			}
		})
	}
}

// The declared stream error set is the registry (signerclient.ErrorContract
// rows with Stream), not a hand-written list, and the golden corpus is
// enumerated against it in both directions: every declared code has at
// least one byte-exact golden negative — driven through production by
// TestSignerServeGoldenWire (server sessions) or by the CLI package's
// TestRunSignerServeStartupGolden (startup session) — and no fixture
// carries a code the registry does not declare for the stream. The
// measured ratio is logged (21 of 21 as of rev3, review rev2 F1). A
// registry row flipped to Stream:false while a fixture still carries the
// code, a Stream row without a fixture, or a fixture with an undeclared
// code each fail here.
func TestSignerGoldenCoversStreamErrorCodes(t *testing.T) {
	declared := map[string]bool{}
	for _, code := range signerclient.StreamErrorCodes() {
		if declared[code] {
			t.Fatalf("StreamErrorCodes lists %s twice", code)
		}
		declared[code] = true
	}
	fixtures, err := signertest.Load(goldenDir)
	if err != nil {
		t.Fatal(err)
	}
	startup, server, err := signertest.ErrorCodes(fixtures)
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string][]string{}
	for _, part := range []map[string][]string{startup, server} {
		for code, files := range part {
			covered[code] = append(covered[code], files...)
		}
	}
	var missing, undeclared []string
	for code := range declared {
		if len(covered[code]) == 0 {
			missing = append(missing, code)
		}
	}
	for code := range covered {
		if !declared[code] {
			undeclared = append(undeclared, code)
		}
	}
	sort.Strings(missing)
	sort.Strings(undeclared)
	t.Logf("golden negatives cover %d of %d declared stream error codes (%d carried by the CLI-driven startup session: %v)", len(declared)-len(missing), len(declared), len(startup), keysOfCodes(startup))
	if len(missing) != 0 {
		t.Errorf("declared stream codes without a byte-exact golden negative: %v", missing)
	}
	if len(undeclared) != 0 {
		t.Errorf("golden responses carry codes the registry does not declare for the stream: %v", undeclared)
	}
}

// The codes the server sessions of the corpus carry are exactly the
// codes production emits when those sessions are served — the golden
// wire test proves the bytes; this test proves the enumeration is not
// circular: every server-emitted error line in every corpus session is
// re-served here and its code is checked against the registry's Stream
// set directly, so a code production emits that the registry does not
// declare fails regardless of what the fixture file says.
func TestSignerServedErrorCodesAreDeclared(t *testing.T) {
	material := loadGoldenMaterial(t)
	sessions := goldenSessions(t, material)
	fixtures, _ := loadGoldenFixtures(t)
	seen := map[string]int{}
	for name, server := range sessions {
		var in bytes.Buffer
		for _, f := range fixtures[name][1:] {
			line, err := f.RequestLine()
			if err != nil {
				t.Fatal(err)
			}
			in.Write(line)
			in.WriteByte('\n')
		}
		var out bytes.Buffer
		_ = server.Serve(&in, &out)
		for _, line := range strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n") {
			var resp signerclient.Response
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				t.Fatalf("%s: %v: %s", name, err, line)
			}
			if resp.Error == nil {
				continue
			}
			seen[resp.Error.Code]++
			if !signerclient.IsStreamCode(resp.Error.Code) {
				t.Errorf("%s: production emitted %q, which ErrorContract does not declare for the stream: %s", name, resp.Error.Code, line)
			}
		}
	}
	if len(seen) == 0 {
		t.Fatal("no error line was served; the corpus sessions carry no negatives")
	}
	t.Logf("%d distinct codes emitted by the served sessions: %v", len(seen), keysOfCounts(seen))
}

func keysOfCodes(m map[string][]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysOfCounts(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func keysOf(m map[string][]signertest.Fixture) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// serveLines runs one session over the given input and returns the
// response lines after the hello.
func serveLines(t *testing.T, server *SignerServer, input string) (hello signerclient.Response, responses []signerclient.Response, err error) {
	t.Helper()
	var out bytes.Buffer
	err = server.Serve(strings.NewReader(input), &out)
	lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
	for i, line := range lines {
		var resp signerclient.Response
		if decodeErr := json.Unmarshal([]byte(line), &resp); decodeErr != nil {
			t.Fatalf("line %d is not a response: %v: %s", i, decodeErr, line)
		}
		if resp.Error != nil && (resp.Error.Code == "" || resp.Error.Message == "" || resp.Error.Hint == "") {
			t.Fatalf("line %d violates the error contract: %s", i, line)
		}
		if i == 0 {
			hello = resp
		} else {
			responses = append(responses, resp)
		}
	}
	return hello, responses, err
}

// Serve ends with nil on EOF whether or not the last line has a newline,
// skips blank and whitespace-only lines without a response, and the
// hello carries contract 1 with the resolved label and fingerprint.
func TestSignerServeEOFAndBlankLines(t *testing.T) {
	material := loadGoldenMaterial(t)
	server := goldenSessions(t, material)["signer"]
	hello, responses, err := serveLines(t, server, "\n   \n{\"id\":1,\"op\":\"pub\"}\n\n{\"id\":2,\"op\":\"pub\"}")
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if hello.Contract != signerclient.Contract || !hello.OK {
		t.Fatalf("hello: %+v", hello)
	}
	var h signerclient.Hello
	if err := json.Unmarshal(hello.Result, &h); err != nil || h.Label != tl("signer", 1) || h.Fingerprint != (Key{SPKI: material.SPKI}).Fingerprint() || len(h.Ops) != 4 {
		t.Fatalf("hello result: %v %+v", err, h)
	}
	if len(responses) != 2 || string(responses[0].ID) != "1" || string(responses[1].ID) != "2" || !responses[0].OK || !responses[1].OK {
		t.Fatalf("responses: %+v", responses)
	}
}

// The request gates answer before any store call: a malformed line, an
// unknown member, a missing id, an unknown op, a mis-sized or non-hex
// digest, a malformed signature and a high-S signature each produce their
// error response with zero Sign and zero List calls beyond the hello's
// one listing; the positive control (a valid sign) then reaches Sign
// exactly once, so the store really is reachable in this session.
func TestSignerServeGatesBeforeStore(t *testing.T) {
	material := loadGoldenMaterial(t)
	server := goldenSessions(t, material)["signer"]
	store := server.Manager.backend.(*cannedStore)
	digest := hex.EncodeToString(material.Digest)
	highS := "304502200f04c66e3ea5b1834951596367d99a939f60459e5c1b47e5d0f1a1ae13e7904a022100e5d7cb4270847d84783350fc089c6935d699d8c342041381bc00a2fe1ea43eff"
	gated := []struct{ line, code string }{
		{`{"id":1,"op":"sign"`, signerclient.CodeBadRequest},
		{`{"id":2,"op":"sign","digest":"` + digest + `","extra":true}`, signerclient.CodeBadRequest},
		{`{"op":"sign","digest":"` + digest + `"}`, signerclient.CodeMissingID},
		{`{"id":4,"op":"rotate"}`, signerclient.CodeUnknownOp},
		{`{"id":5,"op":"sign","digest":"abcd"}`, CodeInvalidDigest},
		{`{"id":6,"op":"sign","digest":"xyz"}`, signerclient.CodeBadRequest},
		{`{"id":7,"op":"verify","digest":"` + digest + `","signature":"3000"}`, CodeInvalidSignature},
		{`{"id":8,"op":"verify","digest":"` + digest + `","signature":"` + highS + `"}`, CodeHighSRefused},
		{`{"id":9,"op":"sign","digest":"` + digest + `","format":"pkcs1"}`, signerclient.CodeBadRequest},
	}
	var input strings.Builder
	for _, g := range gated {
		input.WriteString(g.line + "\n")
	}
	input.WriteString(`{"id":10,"op":"sign","digest":"` + digest + `"}` + "\n")
	_, responses, err := serveLines(t, server, input.String())
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(responses) != len(gated)+1 {
		t.Fatalf("%d responses for %d requests", len(responses), len(gated)+1)
	}
	for i, g := range gated {
		if responses[i].OK || responses[i].Error == nil || responses[i].Error.Code != g.code {
			t.Errorf("%s: got %+v, want %s", g.line, responses[i], g.code)
		}
	}
	if !responses[len(gated)].OK {
		t.Fatalf("positive control failed: %+v", responses[len(gated)])
	}
	_, _, _, lists := store.calls()
	if len(store.signs) != 1 || lists != 2 { // hello listing + the control's listing
		t.Fatalf("store saw %d signs and %d lists; the gates leaked a store call", len(store.signs), lists)
	}
}

// Member gating is on presence, not value (review rev2 F2): a member an
// op does not take is bad_request even when its JSON value is the zero
// value of its type — explicit false for allow_high_s on describe, pub
// and sign, "" for signature/digest/format where the op does not take
// them — with zero Sign calls and no listing beyond the hello's, and the
// stream stays usable. Nearby controls: verify takes allow_high_s and
// accepts an explicit false, pub takes format and accepts an explicit
// "" (decoded as the default), and a plain sign after the refusals
// reaches the backend exactly once. A server that decodes into the typed
// struct first (where false and absent are the same) admits every
// negative row and fails here.
func TestSignerServeRefusesInapplicableZeroValueMembers(t *testing.T) {
	material := loadGoldenMaterial(t)
	server := goldenSessions(t, material)["signer"]
	store := server.Manager.backend.(*cannedStore)
	digest := hex.EncodeToString(material.Digest)
	sig := hex.EncodeToString(material.DER)
	negatives := []struct{ line, member string }{
		{`{"id":1,"op":"describe","allow_high_s":false}`, "allow_high_s"},
		{`{"id":2,"op":"pub","allow_high_s":false}`, "allow_high_s"},
		{`{"id":3,"op":"sign","digest":"` + digest + `","allow_high_s":false}`, "allow_high_s"},
		{`{"id":4,"op":"describe","digest":""}`, "digest"},
		{`{"id":5,"op":"describe","format":""}`, "format"},
		{`{"id":6,"op":"pub","signature":""}`, "signature"},
		{`{"id":7,"op":"pub","digest":""}`, "digest"},
		{`{"id":8,"op":"sign","digest":"` + digest + `","signature":""}`, "signature"},
		{`{"id":9,"op":"describe","allow_high_s":true}`, "allow_high_s"},
		{`{"id":10,"op":"sign","digest":"` + digest + `","signature":"` + sig + `"}`, "signature"},
	}
	var input strings.Builder
	for _, n := range negatives {
		input.WriteString(n.line + "\n")
	}
	controls := []string{
		`{"id":11,"op":"verify","digest":"` + digest + `","signature":"` + sig + `","allow_high_s":false}`,
		`{"id":12,"op":"pub","format":""}`,
		`{"id":13,"op":"sign","digest":"` + digest + `"}`,
	}
	for _, c := range controls {
		input.WriteString(c + "\n")
	}
	_, responses, err := serveLines(t, server, input.String())
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(responses) != len(negatives)+len(controls) {
		t.Fatalf("%d responses for %d requests", len(responses), len(negatives)+len(controls))
	}
	for i, n := range negatives {
		resp := responses[i]
		if resp.OK || resp.Error == nil || resp.Error.Code != signerclient.CodeBadRequest || !strings.Contains(resp.Error.Message, n.member) {
			t.Errorf("%s: got %+v, want bad_request naming %s", n.line, resp, n.member)
		}
		if string(resp.ID) != fmt.Sprint(i+1) {
			t.Errorf("%s: answered under id %s", n.line, resp.ID)
		}
	}
	for i := range controls {
		if resp := responses[len(negatives)+i]; !resp.OK {
			t.Errorf("control %s failed: %+v", controls[i], resp)
		}
	}
	_, _, _, lists := store.calls()
	if len(store.signs) != 1 || lists != 4 { // hello + one listing per control (verify, pub, sign)
		t.Fatalf("store saw %d signs and %d lists; a refused member reached the backend", len(store.signs), lists)
	}
}

// Review rev6 F1 regression, server side, through SignerServer.Serve (the
// production loop of `signer serve`): a request line that repeats a
// member — verbatim or spelt with a JSON escape (dig\u0065st), the
// contradictory value first and a valid one last, the order a map decode
// collapses to the valid value — is bad_request under id null naming the
// duplicate, with zero Sign calls and no listing beyond the hello's, and
// the stream stays usable. A repeated id is refused the same way (no id
// is trusted). Nearby controls: a single escape-spelt member is the
// member it decodes to (a sign whose digest is spelt dig\u0065st
// reaches the backend once), and a plain sign afterwards reaches it once
// more. A server that reads the line into a map or struct before this
// gate admits every negative row and fails here. Rev8 F1 rows repeat a
// member BELOW the top level (inside an object member, at depth 2,
// inside an array of objects — first and later element — verbatim and
// escape-spelt): the gate is the recursive CheckDocument walk, and a
// walk limited to depth 0 or one that skips array elements answers
// missing_id / bad_request(unknown member) instead of naming the
// duplicate.
func TestSignerServeRefusesDuplicateMembers(t *testing.T) {
	material := loadGoldenMaterial(t)
	server := goldenSessions(t, material)["signer"]
	store := server.Manager.backend.(*cannedStore)
	digest := hex.EncodeToString(material.Digest)
	negatives := []struct{ line, member string }{
		{`{"id":1,"op":"sign","digest":"00","digest":"` + digest + `"}`, "digest"},
		{`{"id":2,"op":"sign","dig\u0065st":"00","digest":"` + digest + `"}`, "digest"},
		{`{"id":3,"op":"describe","op":"sign","digest":"` + digest + `"}`, "op"},
		{`{"id":4,"\u006fp":"describe","op":"sign","digest":"` + digest + `"}`, "op"},
		{`{"id":99,"id":5,"op":"describe"}`, "id"},
		{`{"\u0069d":99,"id":6,"op":"describe"}`, "id"},
		{`{"id":7,"op":"verify","digest":"` + digest + `","signature":"00","signature":"` + hex.EncodeToString(material.DER) + `"}`, "signature"},
		// rev8 F1 (repeat-of rev6 F1): the repeat BELOW the top level —
		// inside an object member, at depth 2, inside an array of
		// objects (first and later element), verbatim and escape-spelt.
		// A request has no legitimate nested object, so the walk is the
		// only thing that names the duplicate; a per-object gate answers
		// missing_id or bad_request(unknown member) instead and fails
		// the message assertion below.
		{`{"id":{"a":1,"a":2},"op":"describe"}`, "a"},
		{`{"id":{"a":1,"\u0061":2},"op":"describe"}`, "a"},
		{`{"id":10,"op":"describe","x":{"y":{"z":1,"z":2}}}`, "z"},
		{`{"id":11,"op":"describe","x":[{"z":1,"z":2}]}`, "z"},
		{`{"id":12,"op":"describe","x":[{"z":1},{"z":1,"\u007a":2}]}`, "z"},
		{`{"id":13,"op":"sign","digest":"` + digest + `","x":[[{"z":1,"z":2}]]}`, "z"},
	}
	controls := []string{
		`{"id":8,"op":"sign","dig\u0065st":"` + digest + `"}`,
		`{"id":9,"op":"sign","digest":"` + digest + `"}`,
	}
	// nested-shape controls: one name in sibling objects and at two
	// depths is not a repeat, so the line is judged on its own merits —
	// an object id is missing_id, an unknown member is bad_request that
	// does NOT name a duplicate; neither is the walk's refusal.
	nestedControls := []struct{ line, code string }{
		{`{"id":{"a":1,"b":{"a":2}},"op":"describe"}`, signerclient.CodeMissingID},
		{`{"id":14,"op":"describe","x":[{"z":1},{"z":2}]}`, signerclient.CodeBadRequest},
	}
	var input strings.Builder
	for _, n := range negatives {
		input.WriteString(n.line + "\n")
	}
	for _, c := range controls {
		input.WriteString(c + "\n")
	}
	for _, c := range nestedControls {
		input.WriteString(c.line + "\n")
	}
	_, responses, err := serveLines(t, server, input.String())
	if err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if len(responses) != len(negatives)+len(controls)+len(nestedControls) {
		t.Fatalf("%d responses for %d requests", len(responses), len(negatives)+len(controls)+len(nestedControls))
	}
	for i, c := range nestedControls {
		resp := responses[len(negatives)+len(controls)+i]
		if resp.OK || resp.Error == nil || resp.Error.Code != c.code || strings.Contains(resp.Error.Message, "duplicate member") {
			t.Errorf("nested control %s: got %+v, want %s not naming a duplicate", c.line, resp, c.code)
		}
	}
	for i, n := range negatives {
		resp := responses[i]
		if resp.OK || resp.Error == nil || resp.Error.Code != signerclient.CodeBadRequest || !strings.Contains(resp.Error.Message, "duplicate member "+strconv.Quote(n.member)) {
			t.Errorf("%s: got %+v, want bad_request naming duplicate member %s", n.line, resp, n.member)
		}
		if string(resp.ID) != "null" {
			t.Errorf("%s: answered under id %s, want null", n.line, resp.ID)
		}
	}
	for i := range controls {
		if resp := responses[len(negatives)+i]; !resp.OK || string(resp.ID) != fmt.Sprint(8+i) {
			t.Errorf("control %s failed: %+v", controls[i], resp)
		}
	}
	_, _, _, lists := store.calls()
	if len(store.signs) != len(controls) || lists != 1+len(controls) {
		t.Fatalf("store saw %d signs and %d lists; a duplicate-member request reached the backend", len(store.signs), lists)
	}
}

// syncBuffer is a writer the serving goroutine fills while the test reads
// the lines written so far.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	text := strings.TrimSuffix(s.b.String(), "\n")
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

func waitForLines(t *testing.T, out *syncBuffer, n int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for len(out.lines()) < n {
		if time.Now().After(deadline) {
			t.Fatalf("waited for %d lines, have %v", n, out.lines())
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// A key missing at start is one hello line with ok=false, not_found and
// a returned ErrNotFound with no further lines; a key that disappears
// after the hello yields not_found for sign and for verify while the
// stream continues, and a later request on the re-added key succeeds.
func TestSignerServeNotFoundMidStream(t *testing.T) {
	material := loadGoldenMaterial(t)
	server := goldenSessions(t, material)["signer"]
	store := server.Manager.backend.(*cannedStore)
	label := tl("signer", 1)
	item := store.keys[label]
	digest := hex.EncodeToString(material.Digest)

	delete(store.keys, label)
	hello, responses, err := serveLines(t, server, `{"id":1,"op":"sign","digest":"`+digest+`"}`+"\n")
	if !errors.Is(err, ErrNotFound) || hello.OK || hello.Error == nil || hello.Error.Code != "not_found" || hello.Contract != signerclient.Contract || len(responses) != 0 {
		t.Fatalf("startup with a missing key: err=%v hello=%+v responses=%d", err, hello, len(responses))
	}
	store.keys[label] = item

	pr, pw := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- server.Serve(pr, out) }()
	waitForLines(t, out, 1) // the hello listed the key
	store.mu.Lock()
	delete(store.keys, label)
	store.mu.Unlock()
	fmt.Fprintf(pw, `{"id":1,"op":"sign","digest":"%s"}`+"\n", digest)
	fmt.Fprintf(pw, `{"id":2,"op":"verify","digest":"%s","signature":"%s"}`+"\n", digest, hex.EncodeToString(material.DER))
	waitForLines(t, out, 3)
	store.mu.Lock()
	store.keys[label] = item
	store.mu.Unlock()
	fmt.Fprintf(pw, `{"id":3,"op":"sign","digest":"%s"}`+"\n", digest)
	pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	lines := out.lines()
	if len(lines) != 4 {
		t.Fatalf("lines: %v", lines)
	}
	for i, want := range []string{"", "not_found", "not_found", ""} {
		var resp signerclient.Response
		if err := json.Unmarshal([]byte(lines[i]), &resp); err != nil {
			t.Fatal(err)
		}
		if want == "" && !resp.OK || want != "" && (resp.OK || resp.Error == nil || resp.Error.Code != want) {
			t.Errorf("line %d: %s", i, lines[i])
		}
	}
}

// The generation the hello names is bound for the whole stream (review
// rev1 F1): with version 0 requested, a rotate performed after the hello
// leaves describe, pub and sign answering with the v1 label and
// fingerprint the hello attested, and the store's Sign is called with the
// v1 label — never v2. Controls: a session started after the rotate with
// version 0 binds v2 (newest at its hello, announced as version 2), and a
// session started with version 1 binds v1 again. Guards
// SignerServer.Serve → pinGeneration and the s.bound address every
// handler passes to the Manager; the built-binary variant is
// TestClientAgainstBuiltBinaryAndLoginKeychain.
func TestSignerServePinsGenerationAcrossRotate(t *testing.T) {
	material := loadGoldenMaterial(t)
	server := goldenSessions(t, material)["signer"]
	store := server.Manager.backend.(*cannedStore)
	addr := server.Address
	v1 := tl("signer", 1)
	digest := hex.EncodeToString(material.Digest)

	pr, pw := io.Pipe()
	out := &syncBuffer{}
	done := make(chan error, 1)
	go func() { done <- server.Serve(pr, out) }()
	waitForLines(t, out, 1)
	rotated, err := server.Manager.Rotate(addr)
	if err != nil || rotated.New.Label != tl("signer", 2) {
		t.Fatalf("rotate: %v %+v", err, rotated)
	}
	fmt.Fprintf(pw, `{"id":1,"op":"describe"}`+"\n")
	fmt.Fprintf(pw, `{"id":2,"op":"pub"}`+"\n")
	fmt.Fprintf(pw, `{"id":3,"op":"sign","digest":"%s"}`+"\n", digest)
	fmt.Fprintf(pw, `{"id":4,"op":"verify","digest":"%s","signature":"%s"}`+"\n", digest, hex.EncodeToString(material.DER))
	pw.Close()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}
	lines := out.lines()
	if len(lines) != 5 {
		t.Fatalf("lines: %v", lines)
	}
	var hello signerclient.Response
	var h signerclient.Hello
	if err := json.Unmarshal([]byte(lines[0]), &hello); err != nil || json.Unmarshal(hello.Result, &h) != nil {
		t.Fatal(err)
	}
	if h.Version != 1 || h.Label != v1 || h.Fingerprint != (Key{SPKI: material.SPKI}).Fingerprint() {
		t.Fatalf("hello: %+v", h)
	}
	for i, line := range lines[1:] {
		var resp signerclient.Response
		if err := json.Unmarshal([]byte(line), &resp); err != nil {
			t.Fatal(err)
		}
		var result struct {
			Label       string `json:"label"`
			Fingerprint string `json:"fingerprint"`
		}
		if !resp.OK || json.Unmarshal(resp.Result, &result) != nil {
			t.Fatalf("response %d: %s", i+1, line)
		}
		if result.Label != v1 || result.Fingerprint != h.Fingerprint {
			t.Errorf("response %d answered with %s %s after the rotate; the hello attested %s %s", i+1, result.Label, result.Fingerprint, v1, h.Fingerprint)
		}
	}
	store.mu.Lock()
	signs := append([]string(nil), store.signs...)
	store.mu.Unlock()
	if len(signs) != 1 || signs[0] != v1 {
		t.Fatalf("store signed with %v, want [%s]", signs, v1)
	}

	// Controls: a new unpinned session binds the newest generation, and a
	// version-1 session binds v1 again.
	newest := &SignerServer{Manager: server.Manager, Address: addr, ToolVersion: "test"}
	newestHello, _, err := serveLines(t, newest, "")
	if err != nil || json.Unmarshal(newestHello.Result, &h) != nil || h.Version != 2 || h.Label != tl("signer", 2) {
		t.Fatalf("session after rotate: %v %+v", err, h)
	}
	pinnedAddr := addr
	pinnedAddr.Version = 1
	pinned := &SignerServer{Manager: server.Manager, Address: pinnedAddr, ToolVersion: "test"}
	pinnedHello, _, err := serveLines(t, pinned, "")
	if err != nil || json.Unmarshal(pinnedHello.Result, &h) != nil || h.Version != 1 || h.Label != v1 {
		t.Fatalf("version-1 session after rotate: %v %+v", err, h)
	}
}

// withoutRegistryRow removes one registry row until the test ends. The
// package's tests do not run in parallel, so the shared table is safe to
// change for one test.
func withoutRegistryRow(t *testing.T, key PrimitiveKey) {
	t.Helper()
	row, ok := registry[key]
	delete(registry, key)
	t.Cleanup(func() {
		if ok {
			registry[key] = row
		}
	})
}
