package kek

import (
	"bufio"
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
	"github.com/relux-works/swarma-keyvault/internal/sockettest"
	"github.com/relux-works/swarma-keyvault/pkg/kekclient"
)

// memBackend is an in-memory keyvault backend whose keys are Go P-256 keys.
// Decrypt opens the ECIES variant independently of kekclient and answers
// errSecParam (-50) for an envelope that does not open, as
// Security.framework does.
type memBackend struct {
	mu   sync.Mutex
	keys map[string]*memKey
}

type memKey struct {
	tag  []byte
	priv *ecdh.PrivateKey
	spki []byte
}

func newMemBackend() *memBackend { return &memBackend{keys: map[string]*memKey{}} }

func (b *memBackend) Create(opts keyvault.CreateOptions) (keyvault.Item, error) {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return keyvault.Item{}, err
	}
	spki, _ := x509.MarshalPKIXPublicKey(&k.PublicKey)
	priv, _ := k.ECDH()
	b.mu.Lock()
	defer b.mu.Unlock()
	b.keys[opts.Label] = &memKey{tag: opts.Tag, priv: priv, spki: spki}
	return keyvault.Item{Label: opts.Label, Tag: opts.Tag, SPKI: spki}, nil
}

func (b *memBackend) List() ([]keyvault.Item, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	var items []keyvault.Item
	for label, k := range b.keys {
		items = append(items, keyvault.Item{Label: label, Tag: k.tag, SPKI: k.spki})
	}
	return items, nil
}

func (b *memBackend) Delete(label string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if _, ok := b.keys[label]; !ok {
		return keyvault.ErrNotFound
	}
	delete(b.keys, label)
	return nil
}

func (b *memBackend) UpdateTag(label string, tag []byte) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	k, ok := b.keys[label]
	if !ok {
		return keyvault.ErrNotFound
	}
	k.tag = tag
	return nil
}

func (b *memBackend) Sign(string, []byte) ([]byte, error) { return nil, errors.New("not used") }

func (b *memBackend) Decrypt(label string, sealed []byte) ([]byte, error) {
	b.mu.Lock()
	k, ok := b.keys[label]
	b.mu.Unlock()
	if !ok {
		return nil, keyvault.ErrNotFound
	}
	plain, err := eciesOpen(k.priv, sealed)
	if err != nil {
		return nil, &keyvault.StatusError{Op: "decrypt", Status: -50}
	}
	return plain, nil
}

func eciesOpen(priv *ecdh.PrivateKey, sealed []byte) ([]byte, error) {
	if len(sealed) < 65+16 {
		return nil, errors.New("short")
	}
	eph, err := ecdh.P256().NewPublicKey(sealed[:65])
	if err != nil {
		return nil, err
	}
	z, err := priv.ECDH(eph)
	if err != nil {
		return nil, err
	}
	var derived []byte
	for c := uint32(1); len(derived) < 32; c++ {
		h := sha256.New()
		h.Write(z)
		binary.Write(h, binary.BigEndian, c)
		h.Write(sealed[:65])
		derived = h.Sum(derived)
	}
	block, _ := aes.NewCipher(derived[:16])
	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	return gcm.Open(nil, derived[16:32], sealed[65:], nil)
}

// fakeInspector answers fixed identities: one for every peer, and one per
// file path.
type fakeInspector struct {
	peer        CodeIdentity
	peerErr     error
	files       map[string]CodeIdentity
	nextPeer    *CodeIdentity
	nextPeerErr error
	peerCalls   int
}

func (f *fakeInspector) Peer(*net.UnixConn) (CodeIdentity, error) {
	f.peerCalls++
	if f.peerCalls > 1 && f.nextPeer != nil {
		return *f.nextPeer, f.nextPeerErr
	}
	return f.peer, f.peerErr
}

func (f *fakeInspector) File(path string) (CodeIdentity, error) {
	id, ok := f.files[path]
	if !ok {
		return CodeIdentity{}, os.ErrNotExist
	}
	return id, nil
}

const (
	proxyHash   = "1111111111111111111111111111111111111111"
	newHash     = "2222222222222222222222222222222222222222"
	otherHash   = "3333333333333333333333333333333333333333"
	installPath = "/Users/someone/.local/bin/network-proxy"
	address     = "network-proxy/store-kek"
)

func hardened(cdhash string) CodeIdentity {
	return CodeIdentity{Valid: true, CDHash: cdhash, Runtime: true, LibraryValidation: true}
}

var testKEK = bytes.Repeat([]byte{0xc3}, kekclient.KEKLen)

// fixture is a vault with one store-kek key, an envelope bound to proxyHash,
// and an audit log in a private directory.
type fixture struct {
	t        *testing.T
	backend  *memBackend
	manager  *keyvault.Manager
	key      keyvault.Key
	envelope []byte
	audit    *Audit
	inspect  *fakeInspector
	now      time.Time
}

func newFixture(t *testing.T, mutate func(*keyvault.InitSpec)) *fixture {
	t.Helper()
	f := &fixture{t: t, backend: newMemBackend(), now: time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)}
	f.manager = keyvault.NewManager(f.backend, nil, keyvault.Origin{Tool: "mac-keyvault-kek/test", User: "tester", Host: "testhost"})
	f.manager.SetClock(func() time.Time { return f.now })
	spec := keyvault.InitSpec{Service: "network-proxy", Purpose: "store-kek", Kind: keyvault.KindKey, Title: "store kek", Algorithm: keyvault.AlgorithmECP256, Store: keyvault.StoreKeychain, Extraction: keyvault.ExtractionNone, Usages: []string{"decrypt"}, Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS}}
	if mutate != nil {
		mutate(&spec)
	}
	key, err := f.manager.Init(spec)
	if err != nil {
		t.Fatal(err)
	}
	f.key = key
	f.envelope = f.wrap(proxyHash, testKEK)
	dir := privateTemp(t)
	f.audit = &Audit{Path: filepath.Join(dir, "audit", "audit.jsonl")}
	f.inspect = &fakeInspector{peer: hardened(proxyHash), files: map[string]CodeIdentity{installPath: hardened(newHash)}}
	return f
}

func (f *fixture) wrap(cdhash string, kek []byte) []byte {
	f.t.Helper()
	req, _ := kekclient.RequirementForCDHash(cdhash)
	sealed, err := kekclient.Wrap(kekclient.WrapSpec{SPKI: f.key.SPKI, Fingerprint: f.key.Fingerprint(), Address: address, Generation: f.key.Record.Version, Requirement: req, InstallPath: installPath}, kek)
	if err != nil {
		f.t.Fatal(err)
	}
	return sealed
}

func privateTemp(t *testing.T) string {
	t.Helper()
	dir := sockettest.Dir(t, "kk")
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// call serves op once and sends line as the request; it returns the decoded
// answer and the raw answer bytes.
func (f *fixture) call(op string, line []byte) (kekclient.Response, []byte) {
	f.t.Helper()
	dir := privateTemp(f.t)
	sock := filepath.Join(dir, "s")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: sock, Net: "unix"})
	if err != nil {
		f.t.Fatal(err)
	}
	defer l.Close()
	s := &Server{Vault: f.manager, Inspector: f.inspect, Audit: f.audit, Op: op, Address: address, Timeout: 5 * time.Second, Now: func() time.Time { return f.now }}
	f.inspect.peerCalls = 0
	done := make(chan error, 1)
	go func() { done <- s.Serve(l) }()
	conn, err := net.Dial("unix", sock)
	if err != nil {
		f.t.Fatal(err)
	}
	defer conn.Close()
	conn.Write(append(line, '\n'))
	raw, err := bufio.NewReader(conn).ReadBytes('\n')
	if err != nil {
		f.t.Fatalf("no answer: %v", err)
	}
	<-done
	var resp kekclient.Response
	if err := json.Unmarshal(raw, &resp); err != nil {
		f.t.Fatalf("answer %q: %v", raw, err)
	}
	return resp, raw
}

func request(op string, envelope []byte) []byte {
	b, _ := json.Marshal(kekclient.Request{Contract: kekclient.Contract, Op: op, Address: address, Envelope: envelope})
	return b
}

func (f *fixture) unwrap() (kekclient.Response, []byte) {
	return f.call(kekclient.OpUnwrap, request(kekclient.OpUnwrap, f.envelope))
}

func requireRefused(t *testing.T, resp kekclient.Response, raw []byte, code string) {
	t.Helper()
	if resp.OK || resp.Result != nil || resp.Error == nil || resp.Error.Code != code {
		t.Fatalf("want refusal %s, got %s", code, raw)
	}
	requireNoKEK(t, raw)
}

func requireNoKEK(t *testing.T, data []byte) {
	t.Helper()
	if bytes.Contains(data, testKEK) || bytes.Contains(data, []byte(base64.StdEncoding.EncodeToString(testKEK))) {
		t.Fatalf("the KEK appears in %q", data)
	}
}

// The bound, hardened caller gets the KEK and the key's identity; every
// answer is logged without the KEK, and the chain verifies.
func TestUnwrapAnswersTheBoundCaller(t *testing.T) {
	f := newFixture(t, nil)
	resp, _ := f.unwrap()
	if !resp.OK || resp.Result == nil || !bytes.Equal(resp.Result.KEK, testKEK) || resp.Result.Generation != 1 || resp.Result.Fingerprint != f.key.Fingerprint() || resp.Result.Address != address {
		t.Fatalf("answer = %+v %+v", resp, resp.Error)
	}
	n, head, err := f.audit.Verify()
	if err != nil || n != 1 || len(head) != 64 {
		t.Fatalf("audit: %d entries, %v", n, err)
	}
	log, _ := os.ReadFile(f.audit.Path)
	requireNoKEK(t, log)
	if !strings.Contains(string(log), `"caller":"`+proxyHash+`"`) || !strings.Contains(string(log), `"verdict":"answered"`) {
		t.Fatalf("audit line: %s", log)
	}
}

// Callers that are not the bound code, or whose code could be injected into
// (no hardened runtime, no library validation, get-task-allow, an invalid
// signature, an unidentifiable peer), are refused as caller_refused with no
// KEK; the bound hardened caller is answered (positive control above and in
// the first case).
func TestUnwrapRefusesOtherOrInjectableCallers(t *testing.T) {
	cases := map[string]func(*fakeInspector){
		"control":             nil,
		"other code":          func(i *fakeInspector) { i.peer = hardened(otherHash) },
		"no hardened runtime": func(i *fakeInspector) { i.peer.Runtime = false },
		"no library valid.":   func(i *fakeInspector) { i.peer.LibraryValidation = false },
		"get-task-allow":      func(i *fakeInspector) { i.peer.GetTaskAllow = true },
		"invalid signature":   func(i *fakeInspector) { i.peer.Valid = false },
		"unknown cdhash":      func(i *fakeInspector) { i.peer.CDHash = "" },
		"unidentifiable":      func(i *fakeInspector) { i.peer, i.peerErr = CodeIdentity{}, errors.New("no audit token") },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			if mutate == nil {
				if resp, raw := f.unwrap(); !resp.OK || !bytes.Equal(resp.Result.KEK, testKEK) {
					t.Fatalf("control refused: %s", raw)
				}
				return
			}
			mutate(f.inspect)
			resp, raw := f.unwrap()
			requireRefused(t, resp, raw, kekclient.CodeCallerRefused)
			log, _ := os.ReadFile(f.audit.Path)
			requireNoKEK(t, log)
			if !strings.Contains(string(log), `"code":"caller_refused"`) {
				t.Fatalf("refusal not logged: %s", log)
			}
		})
	}
}

// Envelopes that were changed, sealed to another key, or whose sealed
// payload disagrees with the clear header are refused as envelope_invalid
// with no KEK; the genuine envelope opens (control).
func TestUnwrapRefusesTamperedOrForeignEnvelopes(t *testing.T) {
	f := newFixture(t, nil)
	if resp, raw := f.unwrap(); !resp.OK {
		t.Fatalf("control: %s", raw)
	}
	env, _ := kekclient.ParseEnvelope(f.envelope)
	reseal := func(change func(*kekclient.Envelope)) []byte {
		e := env
		e.ECIES = bytes.Clone(env.ECIES)
		change(&e)
		b, _ := json.Marshal(e)
		return b
	}
	other := newFixture(t, nil)
	foreignSealed, _ := kekclient.ParseEnvelope(other.envelope)
	// A payload sealed to the right key whose own header names another
	// generation than the clear header.
	mismatch := func() []byte {
		req, _ := kekclient.RequirementForCDHash(proxyHash)
		p, _ := json.Marshal(kekclient.Payload{Version: 1, Address: address, Generation: 2, Fingerprint: f.key.Fingerprint(), Requirement: req, InstallPath: installPath, KCV: env.KCV, KEK: testKEK})
		sealed := sealTo(t, f.key.SPKI, p)
		return reseal(func(e *kekclient.Envelope) { e.ECIES = sealed })
	}()
	// Sealed to this key, but header and payload both name another key:
	// only the broker's own fingerprint check refuses it.
	consistentOther := func() []byte {
		req, _ := kekclient.RequirementForCDHash(proxyHash)
		p, _ := json.Marshal(kekclient.Payload{Version: 1, Address: address, Generation: 1, Fingerprint: other.key.Fingerprint(), Requirement: req, InstallPath: installPath, KCV: env.KCV, KEK: testKEK})
		return reseal(func(e *kekclient.Envelope) {
			e.Fingerprint, e.ECIES = other.key.Fingerprint(), sealTo(t, f.key.SPKI, p)
		})
	}()
	cases := map[string][]byte{
		"names another key":     consistentOther,
		"ciphertext byte":       reseal(func(e *kekclient.Envelope) { e.ECIES[70] ^= 1 }),
		"tag byte":              reseal(func(e *kekclient.Envelope) { e.ECIES[len(e.ECIES)-1] ^= 1 }),
		"ephemeral point":       reseal(func(e *kekclient.Envelope) { e.ECIES[10] ^= 1 }),
		"truncated":             reseal(func(e *kekclient.Envelope) { e.ECIES = e.ECIES[:40] }),
		"sealed to another key": reseal(func(e *kekclient.Envelope) { e.ECIES = foreignSealed.ECIES }),
		"other fingerprint":     reseal(func(e *kekclient.Envelope) { e.Fingerprint = other.key.Fingerprint() }),
		"payload header":        mismatch,
	}
	for name, envelope := range cases {
		t.Run(name, func(t *testing.T) {
			resp, raw := f.call(kekclient.OpUnwrap, request(kekclient.OpUnwrap, envelope))
			requireRefused(t, resp, raw, kekclient.CodeEnvelopeInvalid)
		})
	}
}

// sealTo seals arbitrary plaintext to spki with the contract's ECIES, for
// payloads Wrap would refuse to build.
func sealTo(t *testing.T, spki, plain []byte) []byte {
	t.Helper()
	parsed, _ := x509.ParsePKIXPublicKey(spki)
	point, _ := parsed.(*ecdsa.PublicKey).ECDH()
	eph, _ := ecdh.P256().GenerateKey(rand.Reader)
	z, _ := eph.ECDH(point)
	var derived []byte
	for c := uint32(1); len(derived) < 32; c++ {
		h := sha256.New()
		h.Write(z)
		binary.Write(h, binary.BigEndian, c)
		h.Write(eph.PublicKey().Bytes())
		derived = h.Sum(derived)
	}
	block, _ := aes.NewCipher(derived[:16])
	gcm, _ := cipher.NewGCMWithNonceSize(block, 16)
	return gcm.Seal(bytes.Clone(eph.PublicKey().Bytes()), derived[16:32], plain, nil)
}

// The key's state gates unwrap through keyvault's own policy: a missing
// generation is not_found, an elapsed not_after is expired, a key without
// the decrypt usage is usage_refused. A valid key opens (control).
func TestUnwrapRefusesMissingExpiredOrUnusableKeys(t *testing.T) {
	t.Run("control", func(t *testing.T) {
		if resp, raw := newFixture(t, nil).unwrap(); !resp.OK {
			t.Fatalf("control: %s", raw)
		}
	})
	t.Run("deleted key", func(t *testing.T) {
		f := newFixture(t, nil)
		f.backend.Delete(f.key.Label)
		resp, raw := f.unwrap()
		requireRefused(t, resp, raw, kekclient.CodeNotFound)
	})
	t.Run("expired", func(t *testing.T) {
		end := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
		f := newFixture(t, func(s *keyvault.InitSpec) { s.NotAfter = &end })
		if resp, raw := f.unwrap(); !resp.OK {
			t.Fatalf("before not_after: %s", raw)
		}
		f.now = end.Add(time.Second)
		resp, raw := f.unwrap()
		requireRefused(t, resp, raw, kekclient.CodeExpired)
	})
	t.Run("no decrypt usage", func(t *testing.T) {
		f := newFixture(t, func(s *keyvault.InitSpec) { s.Usages = []string{"sign", "verify"} })
		resp, raw := f.unwrap()
		requireRefused(t, resp, raw, kekclient.CodeUsageRefused)
	})
}

// Requests outside what this process serves are refused as bad_request
// before the vault is asked: another operation or address, another
// contract, unknown members, no envelope.
func TestUnwrapRefusesMalformedRequests(t *testing.T) {
	f := newFixture(t, nil)
	other, _ := json.Marshal(kekclient.Request{Contract: kekclient.Contract, Op: kekclient.OpUnwrap, Address: "network-proxy/other", Envelope: f.envelope})
	cases := map[string][]byte{
		"rebind on unwrap": request(kekclient.OpRebind, f.envelope),
		"other address":    other,
		"other contract":   bytes.Replace(request(kekclient.OpUnwrap, f.envelope), []byte(`"kek-1"`), []byte(`"kek-2"`), 1),
		"unknown member":   bytes.Replace(request(kekclient.OpUnwrap, f.envelope), []byte(`{"contract"`), []byte(`{"debug":true,"contract"`), 1),
		"no envelope":      request(kekclient.OpUnwrap, nil),
		"not json":         []byte("unwrap please"),
		"repeated op":      bytes.Replace(request(kekclient.OpUnwrap, f.envelope), []byte(`{"contract"`), []byte(`{"op":"rebind","contract"`), 1),
		"case alias":       bytes.Replace(request(kekclient.OpUnwrap, f.envelope), []byte(`"op"`), []byte(`"OP"`), 1),
		"second document":  append(request(kekclient.OpUnwrap, f.envelope), []byte(` {"op":"rebind"}`)...),
		"trailing brace":   append(request(kekclient.OpUnwrap, f.envelope), '}'),
		"null envelope":    bytes.Replace(request(kekclient.OpUnwrap, f.envelope), []byte(`"envelope":{`), []byte(`"envelope":null,"x":{`), 1),
	}
	for name, line := range cases {
		t.Run(name, func(t *testing.T) {
			resp, raw := f.call(kekclient.OpUnwrap, line)
			requireRefused(t, resp, raw, kekclient.CodeBadRequest)
		})
	}
}

// Nothing is answered unless the audit log takes the entry first: with the
// log's directory open to others, the bound caller gets security and no KEK.
func TestUnwrapAnswersNothingWithoutTheAuditLog(t *testing.T) {
	f := newFixture(t, nil)
	dir := filepath.Dir(f.audit.Path)
	os.MkdirAll(dir, 0o700)
	os.Chmod(dir, 0o755)
	resp, raw := f.unwrap()
	requireRefused(t, resp, raw, kekclient.CodeSecurity)
	os.Chmod(dir, 0o700)
	if resp, raw := f.unwrap(); !resp.OK {
		t.Fatalf("control after repair: %s", raw)
	}
}

// Rebind by the bound caller returns a new envelope for the same key that
// opens only for the code now installed at the envelope's install path; the
// old binding is refused afterwards, and no answer carries the KEK.
func TestRebindMovesTheBindingToTheInstalledCode(t *testing.T) {
	f := newFixture(t, nil)
	resp, raw := f.call(kekclient.OpRebind, request(kekclient.OpRebind, f.envelope))
	if !resp.OK || resp.Result == nil || resp.Result.KEK != nil || len(resp.Result.Envelope) == 0 {
		t.Fatalf("rebind: %s", raw)
	}
	requireNoKEK(t, raw)
	f.envelope = resp.Result.Envelope
	if resp, raw := f.unwrap(); resp.OK {
		t.Fatalf("old code still answered: %s", raw)
	}
	f.inspect.peer = hardened(newHash)
	if resp, raw := f.unwrap(); !resp.OK || !bytes.Equal(resp.Result.KEK, testKEK) {
		t.Fatalf("new code: %s", raw)
	}
	log, _ := os.ReadFile(f.audit.Path)
	requireNoKEK(t, log)
	if !strings.Contains(string(log), `"requirement":"cdhash H\"`+newHash+`\""`) {
		t.Fatalf("rebind not logged with its new binding: %s", log)
	}
}

// Rebind is refused when the caller is not the bound code, when the
// installed code is missing, injectable or unsigned, and when it is the
// code already bound; the envelope the caller holds stays valid.
func TestRebindRefusals(t *testing.T) {
	cases := map[string]struct {
		mutate func(*fakeInspector)
		code   string
	}{
		"caller not bound":        {func(i *fakeInspector) { i.peer = hardened(otherHash) }, kekclient.CodeCallerRefused},
		"nothing installed":       {func(i *fakeInspector) { delete(i.files, installPath) }, kekclient.CodeRebindRefused},
		"installed no runtime":    {func(i *fakeInspector) { id := hardened(newHash); id.Runtime = false; i.files[installPath] = id }, kekclient.CodeRebindRefused},
		"installed get-task":      {func(i *fakeInspector) { id := hardened(newHash); id.GetTaskAllow = true; i.files[installPath] = id }, kekclient.CodeRebindRefused},
		"installed invalid":       {func(i *fakeInspector) { id := hardened(newHash); id.Valid = false; i.files[installPath] = id }, kekclient.CodeRebindRefused},
		"installed already bound": {func(i *fakeInspector) { i.files[installPath] = hardened(proxyHash) }, kekclient.CodeRebindRefused},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFixture(t, nil)
			tc.mutate(f.inspect)
			resp, raw := f.call(kekclient.OpRebind, request(kekclient.OpRebind, f.envelope))
			requireRefused(t, resp, raw, tc.code)
			f.inspect.peer = hardened(proxyHash)
			if resp, raw := f.unwrap(); !resp.OK {
				t.Fatalf("the held envelope stopped working: %s", raw)
			}
		})
	}
}

// Nothing is answered unless the entry was synced: a failing sync gives the
// bound caller security and no KEK, and a working one answers (control).
func TestUnwrapAnswersNothingWhenTheAuditSyncFails(t *testing.T) {
	f := newFixture(t, nil)
	saved := syncFile
	t.Cleanup(func() { syncFile = saved })
	synced := 0
	syncFile = func(*os.File) error { synced++; return errors.New("disk said no") }
	resp, raw := f.unwrap()
	requireRefused(t, resp, raw, kekclient.CodeSecurity)
	if synced != 1 {
		t.Fatalf("sync ran %d times", synced)
	}
	syncFile = func(*os.File) error { synced++; return nil }
	if resp, raw := f.unwrap(); !resp.OK || synced != 2 {
		t.Fatalf("control: synced=%d %s", synced, raw)
	}
}

// The default sync hook really syncs the file it is given: it succeeds on
// an open file and reports the error of a closed one (os.ErrClosed), which a
// hook that skipped the sync would not. With the injected-failure test above
// this covers both the default durability call and its refusal path.
func TestDefaultSyncFileSyncs(t *testing.T) {
	f, err := os.CreateTemp(privateTemp(t), "sync")
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("entry\n")
	if err := syncFile(f); err != nil {
		t.Fatalf("sync of an open file: %v", err)
	}
	f.Close()
	if err := syncFile(f); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("sync of a closed file: %v", err)
	}
}

// Verify applies Append's framing: a log whose last entry lacks its newline,
// or ends in a truncated entry, does not verify, although its JSON may be
// complete; a log that is not a private regular file does not verify either.
// The intact log verifies (control).
func TestAuditVerifyRequiresAppendFraming(t *testing.T) {
	f := newFixture(t, nil)
	f.unwrap()
	f.unwrap()
	data, _ := os.ReadFile(f.audit.Path)
	if _, _, err := f.audit.Verify(); err != nil {
		t.Fatalf("control: %v", err)
	}
	cases := map[string][]byte{
		"no final newline": bytes.TrimSuffix(data, []byte("\n")),
		"truncated entry":  data[:len(data)-20],
		"empty line":       append(bytes.Clone(data), '\n'),
	}
	for name, edited := range cases {
		os.WriteFile(f.audit.Path, edited, 0o600)
		if n, head, err := f.audit.Verify(); err == nil {
			t.Fatalf("%s: verified %d entries, head %s", name, n, head)
		}
	}
	os.WriteFile(f.audit.Path, data, 0o600)
	os.Chmod(f.audit.Path, 0o644)
	if _, _, err := f.audit.Verify(); err == nil {
		t.Fatal("a group-readable log verified")
	}
}

// The audit chain detects a removed or edited line; an intact log verifies.
func TestAuditChainDetectsEdits(t *testing.T) {
	f := newFixture(t, nil)
	for i := 0; i < 3; i++ {
		f.unwrap()
	}
	n, head, err := f.audit.Verify()
	if err != nil || n != 3 || head == genesis {
		t.Fatalf("control: %d %s %v", n, head, err)
	}
	data, _ := os.ReadFile(f.audit.Path)
	lines := bytes.SplitAfter(data, []byte("\n"))
	edits := map[string][]byte{
		"middle line removed": bytes.Join([][]byte{lines[0], lines[2]}, nil),
		"verdict edited":      bytes.Replace(data, []byte(`"answered"`), []byte(`"refused"`), 1),
	}
	for name, edited := range edits {
		os.WriteFile(f.audit.Path, edited, 0o600)
		if _, _, err := f.audit.Verify(); err == nil {
			t.Fatalf("%s: chain still verifies", name)
		}
	}
}

// Character counts describe the literal TMPDIR input; Unix sockets budget UTF-8
// bytes. Both cases have at least 70 characters and exercise binding, a real fixture
// server exchange, and cleanup through the same privateTemp used by its callers.
func TestPrivateTempWithLongTMPDIR(t *testing.T) {
	setup := filepath.Join(t.TempDir(), strings.Repeat("x", 58))
	if err := os.Mkdir(setup, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("TMPDIR", setup)
	parent := sockettest.Dir(t, "kk-env")
	for _, tc := range []struct {
		name  string
		chars int
		pad   string
	}{
		{"ascii100", 100, "x"},
		{"utf8-70-characters", 70, "é"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := filepath.Join(parent, strings.Repeat(tc.pad, tc.chars-utf8.RuneCountInString(parent)-1))
			if err := os.Mkdir(input, 0700); err != nil {
				t.Fatal(err)
			}
			if utf8.RuneCountInString(input) != tc.chars {
				t.Fatal("incorrect TMPDIR character count")
			}
			t.Setenv("TMPDIR", input)
			var dir string
			t.Run("socket-and-exchange", func(t *testing.T) {
				dir = privateTemp(t)
				path := filepath.Join(dir, "s")
				t.Logf("TMPDIR: %d bytes/%d characters; socket: %d bytes/%d characters", len(input), utf8.RuneCountInString(input), len(path), utf8.RuneCountInString(path))
				ln, err := net.Listen("unix", path)
				if err != nil {
					t.Fatalf("fixture socket bind: %v", err)
				}
				if err := ln.Close(); err != nil {
					t.Fatal(err)
				}
				if len(path) > sockettest.MaxPath {
					t.Fatalf("socket exceeds portable byte budget: %d", len(path))
				}
				if filepath.Dir(dir) != sockettest.Base(input) {
					t.Fatal("privateTemp did not use existing sockettest base")
				}
				f := newFixture(t, nil)
				if resp, _ := f.unwrap(); !resp.OK || resp.Result == nil || !bytes.Equal(resp.Result.KEK, testKEK) {
					t.Fatal("fixture server exchange refused")
				}
				if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
					t.Fatalf("socket cleanup: entries=%v error=%v", entries, err)
				}
			})
			if _, err := os.Lstat(dir); !errors.Is(err, os.ErrNotExist) {
				t.Errorf("fixture directory survived cleanup: %v", err)
			}
		})
	}
}
