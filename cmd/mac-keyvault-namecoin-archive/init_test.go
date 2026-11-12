//go:build darwin && cgo && keyvault_abi_tests

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinlocalgate"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
)

func initializationArchiveFixture(t *testing.T) (*initializationRegistry, []byte, []byte, string) {
	t.Helper()
	read := func(p string) []byte {
		b, e := os.ReadFile(filepath.Join("..", "..", "internal", "namecoinpsbt", "testdata", p))
		if e != nil {
			t.Fatal(e)
		}
		return b
	}
	config := read("native-selection/all-four-before-release-reservation.json")
	pin := read("all-four-before-release/account-pin.json")
	if _, e := namecoinpsbt.DecodeNativeSelection(config); e != nil {
		t.Fatal(e)
	}
	home, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.MkdirAll(filepath.Join(home, "Library", "Application Support"), 0700); e != nil {
		t.Fatal(e)
	}
	r := &initializationRegistry{open: func(c namecoinpsbt.NativeSelection, p []byte) (initializationSession, error) {
		session, e := namecoinpsbt.OpenInitializationABIFixture(c, p, home)
		if e != nil {
			return nil, e
		}
		return session, nil
	}}
	old := initializationHandles
	initializationHandles = r
	t.Cleanup(func() {
		r.entries.Range(func(k, v any) bool {
			if _, ok := v.(*initializationEntry); ok {
				_ = r.close(k.(uint64))
			}
			return true
		})
		initializationHandles = old
	})
	return r, pin, config, home
}

func requireInitializationGateBusy(t *testing.T) {
	t.Helper()
	g, e := namecoinlocalgate.Acquire()
	if g != nil {
		_ = g.Close()
	}
	if g != nil || !errors.Is(e, namecoinlocalgate.ErrAccountBusy) {
		t.Fatal("real initialization gate was released early")
	}
}
func requireInitializationGateFree(t *testing.T) {
	t.Helper()
	g, e := namecoinlocalgate.Acquire()
	if e != nil || g == nil {
		t.Fatal("real initialization gate remains held")
	}
	if g.Close() != nil {
		t.Fatal("fixture gate close failed")
	}
}
func requireNoInitializationPublicState(t *testing.T, home string) {
	t.Helper()
	if _, e := os.Lstat(filepath.Join(home, "Library", "Application Support", "mac-keyvault")); !os.IsNotExist(e) {
		t.Fatal("public initialization state unexpectedly created")
	}
}

// Actual initialization exports, real kernel gate/public create-only journal and C
// callbacks complete a published-account fixture. The explicit build tag selects
// only a disposable public home; no Keychain, Touch ID or production home write.
func TestInitializationExportsPositiveAndGateLifetime(t *testing.T) {
	_, pin, cfg, home := initializationArchiveFixture(t)
	h, code := initializationFixtureOpen(pin, cfg)
	if code != 0 || h == 0 {
		t.Fatalf("open status%d", code)
	}
	requireNoInitializationPublicState(t, home)
	if code := initializationFixtureCheckAbsent(h); code != 0 {
		t.Fatalf("public query status%d", code)
	}
	requireInitializationGateBusy(t)
	material := publishedInitializationAccount(t)
	defer clear(material)
	before := bytes.Clone(material)
	defer clear(before)
	f := newInitializationCFixture(0)
	defer f.close()
	if code := initializationFixtureComplete(h, material, f); code != 0 {
		t.Fatalf("complete status%d", code)
	}
	if !bytes.Equal(material, before) {
		t.Fatal("caller account buffer modified")
	}
	a, c, l, n := f.stats()
	if a != 2 || c != 1 || l != 2 || n == 0 {
		t.Fatalf("callback counts absent%d create%d load%d", a, c, l)
	}
	if _, e := os.Stat(filepath.Join(home, "Library", "Application Support", "mac-keyvault")); e != nil {
		t.Fatal("public journal missing")
	}
	requireInitializationGateBusy(t)
	if code := initializationFixtureComplete(h, material, f); code != 19 {
		t.Fatalf("duplicate status%d", code)
	}
	// Native owner contract: clear its private buffer before the explicit Close.
	clear(material)
	if code := initializationFixtureClose(h); code != 0 {
		t.Fatalf("close status%d", code)
	}
	if code := initializationFixtureClose(h); code != 0 {
		t.Fatalf("repeated close status%d", code)
	}
	requireInitializationGateFree(t)
}

// Wrong account and malformed/missing callback inputs consume only this explicit
// attempt, produce the intended refusal and make no public/native create. The
// nearby positive test exercises the same actual exported path successfully.
func TestInitializationExportsPreCreateRefusals(t *testing.T) {
	cases := []struct {
		name         string
		fault, code  int
		mutate       int
		nilCallbacks bool
	}{
		{name: "wrong-scalar", code: 5, mutate: 1}, {name: "wrong-chain", code: 5, mutate: 33},
		{name: "short-material", code: 1, mutate: -1}, {name: "no-callbacks", code: 1, nilCallbacks: true},
		{name: "missing-absence", fault: 101, code: 1}, {name: "missing-create", fault: 102, code: 1}, {name: "missing-load", fault: 103, code: 1},
		{name: "native-already-present", fault: 1, code: 20},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, pin, cfg, home := initializationArchiveFixture(t)
			h, code := initializationFixtureOpen(pin, cfg)
			if code != 0 {
				t.Fatal("positive open failed")
			}
			material := publishedInitializationAccount(t)
			defer clear(material)
			if tc.mutate > 0 {
				material[tc.mutate-1] ^= 1
			}
			if tc.mutate < 0 {
				material = material[:63]
			}
			f := newInitializationCFixture(tc.fault)
			defer f.close()
			arg := f
			if tc.nilCallbacks {
				arg = nil
			}
			if code := initializationFixtureComplete(h, material, arg); code != int32(tc.code) {
				t.Fatalf("status%d want%d", code, tc.code)
			}
			_, creates, _, _ := f.stats()
			if creates != 0 {
				t.Fatal("refusal called native create")
			}
			requireNoInitializationPublicState(t, home)
			requireInitializationGateBusy(t)
			if code := initializationFixtureComplete(h, material, f); code != 19 {
				t.Fatal("refused attempt retried")
			}
			clear(material)
			if initializationFixtureClose(h) != 0 {
				t.Fatal("close failed")
			}
			requireInitializationGateFree(t)
		})
	}
}

// Any callback failure after public-create attempt is UNKNOWN, never a clean
// refusal or retry. Public files are preserved and the same gate stays held.
func TestInitializationExportsPostCreateUnknown(t *testing.T) {
	for _, fault := range []int{2, 3, 4, 5, 6, 7} {
		t.Run(string(rune('a'+fault)), func(t *testing.T) {
			_, pin, cfg, home := initializationArchiveFixture(t)
			h, code := initializationFixtureOpen(pin, cfg)
			if code != 0 {
				t.Fatal("open failed")
			}
			material := publishedInitializationAccount(t)
			defer clear(material)
			f := newInitializationCFixture(fault)
			defer f.close()
			if code := initializationFixtureComplete(h, material, f); code != 19 {
				t.Fatalf("status%d", code)
			}
			if _, e := os.Stat(filepath.Join(home, "Library", "Application Support", "mac-keyvault")); e != nil {
				t.Fatal("unknown state was cleaned or not created")
			}
			requireInitializationGateBusy(t)
			a, c, l, n := f.stats()
			if initializationFixtureComplete(h, material, f) != 19 {
				t.Fatal("unknown retried")
			}
			aa, cc, ll, nn := f.stats()
			if a != aa || c != cc || l != ll || n != nn {
				t.Fatal("duplicate changed callback state")
			}
			clear(material)
			if initializationFixtureClose(h) != 0 {
				t.Fatal("close failed")
			}
			requireInitializationGateFree(t)
		})
	}
}

type initializationPanicSession struct {
	real       initializationSession
	captured   []byte
	closePanic bool
	closes     int
}

func (s *initializationPanicSession) CheckPublicAbsent() error { return s.real.CheckPublicAbsent() }
func (s *initializationPanicSession) CompleteReviewed(b []byte, _ namecoinpsbt.ProtectedInitializer) error {
	s.captured = b
	b[0] ^= 1
	panic("bounded fixture")
}
func (s *initializationPanicSession) Close() error {
	s.closes++
	e := s.real.Close()
	if s.closePanic {
		panic("bounded fixture")
	}
	return e
}

// Actual exported recover boundaries retain the real gate after Complete panic
// until synthetic native cleanup then Close. Go-owned copy clears while caller
// bytes remain unchanged. This does not claim universal library/OS zeroization.
func TestInitializationExportsRecoverAndBorrowOrdering(t *testing.T) {
	r, pin, cfg, home := initializationArchiveFixture(t)
	original := r.open
	var wrapped *initializationPanicSession
	r.open = func(c namecoinpsbt.NativeSelection, p []byte) (initializationSession, error) {
		s, e := original(c, p)
		if e != nil {
			return nil, e
		}
		wrapped = &initializationPanicSession{real: s}
		return wrapped, nil
	}
	h, code := initializationFixtureOpen(pin, cfg)
	if code != 0 {
		t.Fatal("open failed")
	}
	material := publishedInitializationAccount(t)
	defer clear(material)
	before := bytes.Clone(material)
	defer clear(before)
	f := newInitializationCFixture(0)
	defer f.close()
	if code := initializationFixtureComplete(h, material, f); code != 19 {
		t.Fatalf("panic status%d", code)
	}
	if !bytes.Equal(material, before) {
		t.Fatal("destructive consumer modified caller")
	}
	if len(wrapped.captured) != 64 || !bytes.Equal(wrapped.captured, make([]byte, 64)) {
		t.Fatal("Go private copy retained after panic")
	}
	requireNoInitializationPublicState(t, home)
	requireInitializationGateBusy(t)
	if wrapped.closes != 0 {
		t.Fatal("panic automatically closed under native borrow")
	}
	if initializationFixtureComplete(h, material, f) != 19 {
		t.Fatal("panicked operation retried")
	}
	clear(material)
	if initializationFixtureClose(h) != 0 {
		t.Fatal("explicit close failed")
	}
	requireInitializationGateFree(t)
	if wrapped.closes != 1 {
		t.Fatal("close count")
	}
}

// Open partial ownership is released; Close panic is retained UNKNOWN and never
// retries that release. No private account borrow exists in either control.
func TestInitializationExportsOpenAndClosePanics(t *testing.T) {
	t.Run("open-panic", func(t *testing.T) {
		r, pin, cfg, _ := initializationArchiveFixture(t)
		r.open = func(namecoinpsbt.NativeSelection, []byte) (initializationSession, error) { panic("bounded") }
		h, c := initializationFixtureOpen(pin, cfg)
		if h != 0 || c != 19 {
			t.Fatal("open panic escaped")
		}
		requireInitializationGateFree(t)
	})
	t.Run("partial-open-refusal", func(t *testing.T) {
		r, pin, cfg, home := initializationArchiveFixture(t)
		open := r.open
		r.open = func(c namecoinpsbt.NativeSelection, p []byte) (initializationSession, error) {
			s, e := open(c, p)
			if e != nil {
				return nil, e
			}
			return s, errors.New("bounded")
		}
		h, c := initializationFixtureOpen(pin, cfg)
		if h != 0 || c != 19 {
			t.Fatal("partial open refusal")
		}
		requireNoInitializationPublicState(t, home)
		requireInitializationGateFree(t)
	})
	t.Run("close-panic", func(t *testing.T) {
		r, pin, cfg, _ := initializationArchiveFixture(t)
		open := r.open
		var s *initializationPanicSession
		r.open = func(c namecoinpsbt.NativeSelection, p []byte) (initializationSession, error) {
			actual, e := open(c, p)
			if e != nil {
				return nil, e
			}
			s = &initializationPanicSession{real: actual, closePanic: true}
			return s, nil
		}
		h, c := initializationFixtureOpen(pin, cfg)
		if c != 0 {
			t.Fatal("open failed")
		}
		if initializationFixtureClose(h) != 19 || initializationFixtureClose(h) != 19 || s.closes != 1 {
			t.Fatal("unknown close retried or became success")
		}
		requireInitializationGateFree(t)
	})
}

// Canonical public positives precede intended invalid input/domain refusals.
// Unknown handles cannot consume a real different-domain operation.
func TestInitializationExportsPublicAdmissionAndDomains(t *testing.T) {
	_, pin, cfg, home := initializationArchiveFixture(t)
	for _, tc := range []struct {
		name string
		p, c []byte
		want int32
	}{
		{"empty-profile", pin, nil, 18}, {"malformed-profile", pin, []byte("{}"), 18}, {"empty-pin", nil, cfg, 5},
		{"wrong-pin", []byte("{}"), cfg, 5}, {"oversize-pin", make([]byte, 32769), cfg, 5}, {"oversize-profile", pin, make([]byte, (4<<20)+1), 18},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h, c := initializationFixtureOpen(tc.p, tc.c)
			if h != 0 || c != tc.want {
				t.Fatalf("status%d want%d", c, tc.want)
			}
			requireNoInitializationPublicState(t, home)
			requireInitializationGateFree(t)
		})
	}
	for _, h := range []uint64{0, rootHandleBit | 1, 999999999} {
		if initializationFixtureClose(h) != 1 || initializationFixtureComplete(h, nil, nil) != 1 {
			t.Fatal("wrong domain accepted")
		}
	}
	cfgDecoded, e := namecoinpsbt.DecodeNativeSelection(cfg)
	if e != nil {
		t.Fatal(e)
	}
	cfgDecoded.Schema = "unsupported/2"
	bad, _ := json.Marshal(cfgDecoded)
	if h, c := initializationFixtureOpen(pin, bad); h != 0 || c != 18 {
		t.Fatal("unknown profile version accepted")
	}
}

// The shared allocator never overlaps root IDs or renews a low-domain ID after
// exhaustion. The count is restored only in this serial, isolated test fixture.
func TestInitializationSharedHandleAllocatorBoundary(t *testing.T) {
	old := nextNativeID.Load()
	defer nextNativeID.Store(old)
	nextNativeID.Store(rootHandleBit - 2)
	if allocateNativeHandle() != rootHandleBit-1 {
		t.Fatal("last low-domain handle refused")
	}
	if allocateNativeHandle() != 0 || allocateNativeHandle() != 0 || nextNativeID.Load() != rootHandleBit-1 {
		t.Fatal("allocator entered root domain or renewed")
	}
}

// Published BIP32 vector1 and fixed hardened account path, never owner material.
func publishedInitializationAccount(t *testing.T) []byte {
	t.Helper()
	seed, err := hex.DecodeString("000102030405060708090a0b0c0d0e0f")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	mac := hmac.New(sha512.New, []byte("Bitcoin seed"))
	_, _ = mac.Write(seed)
	material := mac.Sum(nil)
	defer clear(material)
	var scalar btcec.ModNScalar
	defer scalar.Zero()
	if scalar.SetByteSlice(material[:32]) || scalar.IsZero() {
		t.Fatal("published master invalid")
	}
	var chain [32]byte
	defer clear(chain[:])
	copy(chain[:], material[32:])
	for _, index := range []uint32{0x80000054, 0x80000007, 0x80000000} {
		var data [37]byte
		scalar.PutBytesUnchecked(data[1:33])
		binary.BigEndian.PutUint32(data[33:], index)
		mac := hmac.New(sha512.New, chain[:])
		_, _ = mac.Write(data[:])
		clear(data[:])
		sum := mac.Sum(nil)
		var delta btcec.ModNScalar
		if delta.SetByteSlice(sum[:32]) {
			clear(sum)
			t.Fatal("published child invalid")
		}
		scalar.Add(&delta)
		delta.Zero()
		copy(chain[:], sum[32:])
		clear(sum)
	}
	out := make([]byte, 64)
	scalar.PutBytesUnchecked(out[:32])
	copy(out[32:], chain[:])
	return out
}

// Real Go/C entry + disposable public home: every existing selected object
// refuses before private material/callbacks; removing it cannot revive this
// handle. The real gate remains until Close. No native Keychain or biometric UI.
func TestInitializationPublicAbsenceExportLatches(t *testing.T) {
	for _, mode := range []string{"directory", "file", "symlink", "panic", "unknown", "closed"} {
		t.Run(mode, func(t *testing.T) {
			r, pin, cfg, home := initializationArchiveFixture(t)
			h, c := initializationFixtureOpen(pin, cfg)
			if c != 0 {
				t.Fatal(c)
			}
			requireInitializationGateBusy(t)
			if mode == "unknown" {
				if initializationFixtureCheckAbsent(h+1000000) != 1 {
					t.Fatal("unknown handle")
				}
				if initializationFixtureCheckAbsent(h) != 0 {
					t.Fatal("unknown touched live handle")
				}
				return
			}
			if mode == "closed" {
				if initializationFixtureClose(h) != 0 || initializationFixtureCheckAbsent(h) != 1 {
					t.Fatal("closed query")
				}
				return
			}
			if mode == "panic" {
				entry := r.entry(h)
				entry.session = &initializationAbsencePanicSession{entry.session}
				if initializationFixtureCheckAbsent(h) != 19 || initializationFixtureCheckAbsent(h) != 19 {
					t.Fatal("panic not latched")
				}
			} else {
				parsed, e := namecoinpsbt.DecodeNativeSelection(cfg)
				if e != nil {
					t.Fatal(e)
				}
				locator, e := namecoinjournal.Locator(parsed.Sidecar.Binding)
				if e != nil {
					t.Fatal(e)
				}
				parent := filepath.Join(home, "Library", "Application Support", "mac-keyvault", "namecoin-journal", "v1")
				if e := os.MkdirAll(parent, 0700); e != nil {
					t.Fatal(e)
				}
				target := filepath.Join(parent, locator)
				switch mode {
				case "directory":
					if e := os.Mkdir(target, 0700); e != nil {
						t.Fatal(e)
					}
				case "file":
					if e := os.WriteFile(target, []byte("collision"), 0600); e != nil {
						t.Fatal(e)
					}
				case "symlink":
					if e := os.Symlink(parent, target); e != nil {
						t.Fatal(e)
					}
				}
				if initializationFixtureCheckAbsent(h) != 20 {
					t.Fatal("existing object did not map journal_unavailable")
				}
				if e := os.Remove(target); e != nil {
					t.Fatal(e)
				}
				if initializationFixtureCheckAbsent(h) != 19 {
					t.Fatal("failed query revived")
				}
			}
			requireInitializationGateBusy(t)
			f := newInitializationCFixture(0)
			defer f.close()
			if initializationFixtureComplete(h, nil, f) != 19 {
				t.Fatal("query failure reached Complete")
			}
			absences, creates, loads, size := f.stats()
			if absences != 0 || creates != 0 || loads != 0 || size != 0 {
				t.Fatal("query failure invoked protected callbacks")
			}
			if initializationFixtureClose(h) != 0 {
				t.Fatal("explicit close")
			}
			requireInitializationGateFree(t)
		})
	}
}

type initializationAbsencePanicSession struct{ initializationSession }

func (*initializationAbsencePanicSession) CheckPublicAbsent() error {
	panic("bounded public query fixture")
}

// Automatic initial Open refuses an existing selected locator with zero handle,
// no native callback, no overwrite and no retained-gate leak.
func TestInitializationPublicAbsenceOpenRefusesExisting(t *testing.T) {
	_, pin, cfg, home := initializationArchiveFixture(t)
	parsed, e := namecoinpsbt.DecodeNativeSelection(cfg)
	if e != nil {
		t.Fatal(e)
	}
	locator, e := namecoinjournal.Locator(parsed.Sidecar.Binding)
	if e != nil {
		t.Fatal(e)
	}
	target := filepath.Join(home, "Library", "Application Support", "mac-keyvault", "namecoin-journal", "v1", locator)
	if e := os.MkdirAll(target, 0700); e != nil {
		t.Fatal(e)
	}
	if h, c := initializationFixtureOpen(pin, cfg); h != 0 || c != 20 {
		t.Fatalf("existing initial state handle%d code%d", h, c)
	}
	requireInitializationGateFree(t)
	if st, e := os.Lstat(target); e != nil || !st.IsDir() {
		t.Fatal("existing state changed")
	}
}
