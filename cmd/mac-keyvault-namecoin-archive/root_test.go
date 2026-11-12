//go:build darwin && cgo && keyvault_abi_tests

package main

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"encoding/json"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/keyvault"
)

type rootPublicFixture struct {
	prepareFn func() (keyvault.RootGrantsPreparationPublic, error)
	sealFn    func([]byte, []byte) (keyvault.RootGrantsPrivateSealed, error)
	closeFn   func()
	closes    atomic.Int32
}

func (f *rootPublicFixture) Prepare() (keyvault.RootGrantsPreparationPublic, error) {
	if f.prepareFn != nil {
		return f.prepareFn()
	}
	return keyvault.RootGrantsPreparationPublic{}, nil
}
func (f *rootPublicFixture) Seal(p, b []byte) (keyvault.RootGrantsPrivateSealed, error) {
	if f.sealFn != nil {
		return f.sealFn(p, b)
	}
	return keyvault.RootGrantsPrivateSealed{Record: json.RawMessage(`{"public":"record"}`), Envelope: json.RawMessage(`{"public":"envelope"}`)}, nil
}
func (f *rootPublicFixture) Close() {
	f.closes.Add(1)
	if f.closeFn != nil {
		f.closeFn()
	}
}

func rootRegistryFixture(t *testing.T) *rootRegistry {
	t.Helper()
	previous := rootHandles
	r := &rootRegistry{open: keyvault.OpenRootGrantsPrivate}
	rootHandles = r
	t.Cleanup(func() {
		r.entries.Range(func(k, _ any) bool {
			r.abort(k.(uint64))
			return true
		})
		rootHandles = previous
	})
	return r
}
func rootPublicRequestFixture(t *testing.T, version string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/root-request-" + version + ".json")
	if err != nil {
		t.Fatal("public request fixture unavailable")
	}
	return raw
}
func rootInstallFixture(t *testing.T, r *rootRegistry, ctx context.Context, f *rootPublicFixture) uint64 {
	t.Helper()
	ctx, cancel := context.WithCancel(ctx)
	h := rootHandleBit | 63
	r.entries.Store(h, &rootEntry{ctx: ctx, cancel: cancel, session: f})
	t.Cleanup(cancel)
	return h
}
func rootFixtureWrapPoint() []byte {
	c := elliptic.P256()
	return elliptic.Marshal(c, c.Params().Gx, c.Params().Gy)
}

// Canonical retained v1/v2 PUBLIC requests traverse the actual vault factory
// through the exported wrapper. Invalid representations/versions and exhausted
// handle capacity refuse with zero output handle. No Prepare/tty is called.
func TestRootCOpenActualPublicFactory(t *testing.T) {
	for _, version := range []string{"v1", "v2"} {
		t.Run(version, func(t *testing.T) {
			r := rootRegistryFixture(t)
			raw := rootPublicRequestFixture(t, version)
			original := bytes.Clone(raw)
			before := time.Now()
			h, code := rootFixtureOpen(raw)
			if code != 0 || h&rootHandleBit == 0 {
				t.Fatalf("public factory status %d", code)
			}
			if !bytes.Equal(raw, original) {
				t.Fatal("open modified borrowed public input")
			}
			s := r.entry(h)
			deadline, ok := s.ctx.Deadline()
			if !ok || deadline.Before(before.Add(rootAttemptLimit)) || deadline.After(time.Now().Add(rootAttemptLimit)) {
				t.Fatal("open did not establish the original bounded deadline")
			}
			if s.phase != rootNew || s.public != nil || s.sealed != nil {
				t.Fatal("public open performed private preparation")
			}
			if rootFixtureClose(h) != 0 || rootFixtureClose(h) != 0 || rootFixturePrepare(h) != 10 {
				t.Fatal("close/reuse contract")
			}
		})
	}
	for _, tc := range []struct {
		name string
		raw  []byte
		code int32
	}{
		{"empty", nil, 1}, {"malformed", []byte("{"), 1},
		{"unknown-key", append([]byte(`{"extra":true,`), rootPublicRequestFixture(t, "v1")[1:]...), 1},
		{"wrong-version", bytes.ReplaceAll(rootPublicRequestFixture(t, "v1"), []byte("keyvault-root-grants-private/1"), []byte("keyvault-root-grants-private/9")), 18},
		{"oversize", bytes.Repeat([]byte{' '}, rootRequestLimit+1), 17},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := rootRegistryFixture(t)
			h, code := rootFixtureOpen(tc.raw)
			if code != tc.code || h != 0 || r.next.Load() != 0 {
				t.Fatalf("factory refusal status %d, handle %d", code, h)
			}
		})
	}
	t.Run("finite-handles", func(t *testing.T) {
		r := rootRegistryFixture(t)
		r.next.Store(rootHandleLimit)
		if h, code := rootFixtureOpen(rootPublicRequestFixture(t, "v1")); code != 17 || h != 0 {
			t.Fatal("bounded tombstone limit refused incorrectly")
		}
	})
}

// Actual C-typed wrappers enforce phase/query/capacity/no-partial-write rules
// around an explicitly synthetic PUBLIC-only facade. This is ABI plumbing;
// the fake record/view does not establish mnemonic, crypto or native validity.
func TestRootCBufferAndPhaseControls(t *testing.T) {
	r := rootRegistryFixture(t)
	f := &rootPublicFixture{sealFn: func(point, blob []byte) (keyvault.RootGrantsPrivateSealed, error) {
		// A destructive consumer of OWNED Go copies must not alter the
		// caller's borrowed public buffers at the actual export boundary.
		clear(point)
		clear(blob)
		return keyvault.RootGrantsPrivateSealed{Record: json.RawMessage(`{"public":"record"}`), Envelope: json.RawMessage(`{"public":"envelope"}`)}, nil
	}}
	ctx, stop := context.WithTimeout(context.Background(), rootAttemptLimit)
	defer stop()
	h := rootInstallFixture(t, r, ctx, f)
	buf := bytes.Repeat([]byte{0xa5}, 8192)
	if n, code := rootFixtureCopy(h, false, nil, 0, false); code != 10 || n != 0 {
		t.Fatal("public output before preparation")
	}
	if code := rootFixturePrepare(h); code != 0 {
		t.Fatal("synthetic valid prepare refused")
	}
	deadline, deadlineOK := r.entry(h).ctx.Deadline()
	n, code := rootFixtureCopy(h, false, nil, 0, false)
	if code != 0 || n == 0 || n > len(buf) {
		t.Fatal("size query refused")
	}
	if needed, status := rootFixtureCopy(h, false, buf[:n-1], n-1, false); status != 1 || needed != n || !bytes.Equal(buf, bytes.Repeat([]byte{0xa5}, len(buf))) {
		t.Fatal("short capacity partially wrote or lost required length")
	}
	if written, status := rootFixtureCopy(h, false, buf, len(buf), false); status != 0 || written != n || !json.Valid(buf[:n]) || !bytes.Equal(buf[n:], bytes.Repeat([]byte{0xa5}, len(buf)-n)) {
		t.Fatal("exact public copy boundary")
	}
	owned := bytes.Clone(buf[:n])
	if repeated, status := rootFixtureCopy(h, false, nil, 0, false); status != 0 || repeated != n {
		t.Fatal("pure repeat query refused")
	}
	after, afterOK := r.entry(h).ctx.Deadline()
	if deadlineOK != afterOK || !after.Equal(deadline) || !bytes.Equal(r.entry(h).public, owned) {
		t.Fatal("copy changed original deadline or owned output")
	}
	for _, tc := range []struct {
		capacity int
		omit     bool
		code     int32
	}{{1, false, 1}, {0, true, 1}, {rootResponseLimit + 1, false, 17}} {
		if _, status := rootFixtureCopy(h, false, nil, tc.capacity, tc.omit); status != tc.code {
			t.Fatal("invalid output arguments admitted")
		}
	}
	point, blob := rootFixtureWrapPoint(), []byte("PUBLIC device blob")
	pointBefore, blobBefore := bytes.Clone(point), bytes.Clone(blob)
	if status := rootFixtureSeal(h, point, blob); status != 0 {
		t.Fatal("synthetic seal refused")
	}
	if !bytes.Equal(point, pointBefore) || !bytes.Equal(blob, blobBefore) {
		t.Fatal("seal modified borrowed public input")
	}
	if _, status := rootFixtureCopy(h, false, nil, 0, false); status != 10 {
		t.Fatal("old-phase output remained available")
	}
	n, code = rootFixtureCopy(h, true, nil, 0, false)
	if code != 0 || n == 0 {
		t.Fatal("sealed size query")
	}
	if written, status := rootFixtureCopy(h, true, buf, len(buf), false); status != 0 || written != n || string(buf[:n]) != `{"record":{"public":"record"},"envelope":{"public":"envelope"}}` {
		t.Fatal("sealed canonical result copy")
	}
	if rootFixtureSeal(h, rootFixtureWrapPoint(), []byte("PUBLIC device blob")) != 10 || f.closes.Load() != 1 || r.entry(h).sealed != nil {
		t.Fatal("duplicate seal retained a usable completion")
	}
}

// A real canceled/deadline context invalidates synthetic owned output, and
// Close cancels BEFORE waiting for an active operation's mutex. No tty is used;
// the facade's injected-clock tests cover actual 900s engine/input propagation.
func TestRootCCancelDeadlineAndConcurrentClose(t *testing.T) {
	t.Run("close-unblocks-operation", func(t *testing.T) {
		r := rootRegistryFixture(t)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		entered := make(chan struct{})
		var entry *rootEntry
		f := &rootPublicFixture{prepareFn: func() (keyvault.RootGrantsPreparationPublic, error) {
			close(entered)
			<-entry.ctx.Done()
			return keyvault.RootGrantsPreparationPublic{}, entry.ctx.Err()
		}}
		h := rootInstallFixture(t, r, ctx, f)
		entry = r.entry(h)
		prepared := make(chan int32, 1)
		go func() { prepared <- rootFixturePrepare(h) }()
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("synthetic operation did not enter")
		}
		closed := make(chan int32, 1)
		go func() { closed <- rootFixtureClose(h) }()
		select {
		case status := <-closed:
			if status != 0 {
				t.Fatal("close refused")
			}
		case <-time.After(time.Second):
			cancel()
			t.Fatal("close waited before canceling")
		}
		if status := <-prepared; status != 14 || f.closes.Load() != 1 || r.entry(h).session != nil {
			t.Fatal("canceled operation retained ownership")
		}
	})
	for _, expire := range []bool{false, true} {
		t.Run(map[bool]string{false: "cancel", true: "deadline"}[expire], func(t *testing.T) {
			r := rootRegistryFixture(t)
			ctx, stop := context.WithCancel(context.Background())
			want := int32(14)
			if expire {
				stop()
				ctx, stop = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				want = 15
			}
			defer stop()
			f := &rootPublicFixture{}
			h := rootInstallFixture(t, r, ctx, f)
			s := r.entry(h)
			s.phase, s.public = rootPrepared, []byte("PUBLIC preparation")
			stop()
			if n, status := rootFixtureCopy(h, false, nil, 0, false); status != want || n != 0 || s.public != nil || s.session != nil || f.closes.Load() != 1 {
				t.Fatal("expired/canceled copy retained state")
			}
		})
	}
}

// Known recoverable Go panics reach EACH actual export boundary. Factory and
// synthetic lifecycle faults clear handles/owned buffers; corrupt map types
// exercise both copy exports. This excludes native/C invalid-pointer traps.
func TestRootCAllExportPanicBoundaries(t *testing.T) {
	t.Run("open", func(t *testing.T) {
		r := rootRegistryFixture(t)
		r.open = func(context.Context, []byte) (*keyvault.RootGrantsPrivateSession, error) {
			panic("PUBLIC factory fault")
		}
		if h, status := rootFixtureOpen(rootPublicRequestFixture(t, "v1")); status != 16 || h != 0 || r.next.Load() != 0 {
			t.Fatal("open panic crossed boundary or returned a handle")
		}
	})
	for _, name := range []string{"prepare", "seal", "close", "public", "sealed"} {
		t.Run(name, func(t *testing.T) {
			r := rootRegistryFixture(t)
			f := &rootPublicFixture{}
			h := rootInstallFixture(t, r, context.Background(), f)
			s := r.entry(h)
			s.public, s.sealed = []byte("PUBLIC before panic"), []byte("PUBLIC sealed before panic")
			switch name {
			case "prepare":
				f.prepareFn = func() (keyvault.RootGrantsPreparationPublic, error) { panic("PUBLIC prepare fault") }
			case "seal":
				s.phase = rootPrepared
				f.sealFn = func([]byte, []byte) (keyvault.RootGrantsPrivateSealed, error) { panic("PUBLIC seal fault") }
			case "close":
				f.closeFn = func() { panic("PUBLIC close fault") }
			default:
				r.entries.Store(h, struct{}{})
				// A replaced map value cannot reveal the discarded fixture's
				// ownership. Restore it for explicit fixture cleanup only; this
				// control claims fixed panic status, not inaccessible-state erasure.
				defer func() { r.entries.Store(h, s); r.abort(h) }()
			}
			status := int32(-1)
			switch name {
			case "prepare":
				status = rootFixturePrepare(h)
			case "seal":
				status = rootFixtureSeal(h, rootFixtureWrapPoint(), []byte("PUBLIC blob"))
			case "close":
				status = rootFixtureClose(h)
			default:
				var written int
				written, status = rootFixtureCopy(h, name == "sealed", nil, 0, false)
				if written != 0 {
					t.Fatal("panic returned stale output length")
				}
			}
			if status != 16 {
				t.Fatal("panic did not return fixed protocol error")
			}
			if name != "public" && name != "sealed" && (s.session != nil || s.public != nil || s.sealed != nil || f.closes.Load() != 1) {
				t.Fatal("panic retained reachable session/output")
			}
		})
	}
}

// All known ROOT refusals retain their accepted numeric meaning; unknown raw
// errors stay protocol16. A live Namecoin namespace is never a root session.
// Malformed wrap arguments close the synthetic root before calling Seal.
func TestRootCClosedMappingNamespaceAndMalformedWrap(t *testing.T) {
	// Literal ABI1 order is independent of the production lookup table.
	wantCodes := []string{"", "invalid_arguments", "terminal_required", "invalid_word_number", "invalid_word_count", "invalid_mnemonic", "invalid_checksum", "invalid_derivation", "retained_record_mismatch", "public_pin_mismatch", "operation_unavailable", "wrapping_policy_refused", "invalid_envelope", "binding_mismatch", "canceled", "timeout", "private_protocol_error", "limit_exceeded", "unsupported_version", "unsupported_operation", "input_canceled"}
	if rootCode(nil) != 0 {
		t.Fatal("success code changed")
	}
	for want, code := range wantCodes[1:] {
		if got := rootCode(&keyvault.Refusal{Code: "recovery_" + code}); got != int32(want+1) {
			t.Fatal("known root error changed")
		}
	}
	if rootCode(&keyvault.Refusal{Code: "recovery_checksum_or_pin_mismatch"}) != 6 {
		t.Fatal("legacy checksum parser alias changed")
	}
	if rootCode(errors.New("PUBLIC diagnostic sentinel")) != 16 || rootCode((*keyvault.Refusal)(nil)) != 16 || rootCode(&keyvault.Refusal{Code: "recovery_unknown"}) != 16 || rootCode(context.Canceled) != 14 || rootCode(context.DeadlineExceeded) != 15 {
		t.Fatal("closed error mapping widened")
	}
	r := rootRegistryFixture(t)
	const namecoin = uint64(63)
	nativeEntries.Store(namecoin, &nativeEntry{review: []byte("PUBLIC namecoin")})
	defer nativeEntries.Delete(namecoin)
	if rootFixturePrepare(namecoin) != 1 || rootFixtureClose(namecoin) != 1 {
		t.Fatal("Namecoin handle reinterpreted")
	}
	if _, status := rootFixtureCopy(namecoin, false, nil, 0, false); status != 1 {
		t.Fatal("Namecoin output leaked through root namespace")
	}
	f := &rootPublicFixture{sealFn: func([]byte, []byte) (keyvault.RootGrantsPrivateSealed, error) {
		t.Fatal("malformed wrap reached facade")
		return keyvault.RootGrantsPrivateSealed{}, nil
	}}
	h := rootInstallFixture(t, r, context.Background(), f)
	r.entry(h).phase = rootPrepared
	if rootFixtureSeal(h, rootFixtureWrapPoint()[:64], []byte("PUBLIC blob")) != 1 || f.closes.Load() != 1 || r.entry(h).session != nil {
		t.Fatal("malformed wrap did not invalidate")
	}
}
