package grants

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

type a2aFakeProvider struct {
	calls   atomic.Int64
	result  []byte
	err     error
	enter   chan struct{}
	release chan struct{}
}

func (p *a2aFakeProvider) create(_ context.Context, _ *a2aCheckedCreate) ([]byte, error) {
	n := p.calls.Add(1)
	if n == 1 && p.enter != nil {
		close(p.enter)
		<-p.release
	}
	return bytes.Clone(p.result), p.err
}
func a2aReceiptFixture(t *testing.T) []byte {
	return requestTestBytes(t, map[string]any{"id": 42, "node_id": "R_fixture", "full_name": LocalOrganization + "/" + A2ARepository, "private": true})
}
func a2aMediatorFixture(t *testing.T) (*a2aFixture, *A2AMediator, *a2aFakeProvider, A2AEvent) {
	t.Helper()
	f := a2aFixtureForTest(t)
	r, e := f.receiver(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	state := A2AStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("inert-fixture-epoch"))}
	if err := InitializeA2AState(state, r); err != nil {
		t.Fatal("fixture state init", err)
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	m := NewA2AMediator(r, state, path)
	m.now = func() time.Time { return f.now }
	p := &a2aFakeProvider{result: a2aReceiptFixture(t)}
	m.provider = p
	return f, m, p, e
}
func a2aJournalBytes(t *testing.T, m *A2AMediator) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(m.state.Directory, "a2a.journal"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// A valid request gets one durable fake CREATE. A new nonce on that same grant
// cannot replenish its allowance, and rejected replay does not rewrite state.
func TestA2ADurableOneUse(t *testing.T) {
	f, m, p, e := a2aMediatorFixture(t)
	out, err := m.Execute(context.Background(), e)
	if err != nil || out == nil || out.State != "succeeded" || out.RepositoryID != "42" || p.calls.Load() != 1 {
		t.Fatal("first use", out, err, p.calls.Load())
	}
	before := a2aJournalBytes(t, m)
	for _, nonce := range []string{strings.Repeat("cd", 32), f.request["nonce"].(string)} {
		f.request["nonce"] = nonce
		if _, err := m.Execute(context.Background(), f.event(t)); !errors.Is(err, ErrA2AUseHeld) {
			t.Fatal("consumed use accepted", err, "provider calls", p.calls.Load())
		}
	}
	if p.calls.Load() != 1 || !bytes.Equal(before, a2aJournalBytes(t, m)) {
		t.Fatal("replay duplicate call or state rewrite")
	}
}

// Registry replacement does not reset grant consumption. A genuinely new
// certificate has a new allowance, but cannot reuse the old signed nonce;
// the adjacent fresh-nonce control succeeds under that new certificate.
func TestA2ADurableNonceAndRegistryRefresh(t *testing.T) {
	f, m, p, e := a2aMediatorFixture(t)
	if _, err := m.Execute(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	f.grantsRegistry["revoked"] = []any{"unrelated-grant"}
	r, err := NewA2AReceiver(a2aCurrentConfig(t, f))
	if err != nil {
		t.Fatal(err)
	}
	f.request["grant_registry_sha256"] = a2aHash(requestTestBytes(t, f.grantsRegistry))
	f.request["nonce"] = strings.Repeat("cd", 32)
	m.receiver = r
	if _, err := m.Execute(context.Background(), f.event(t)); !errors.Is(err, ErrA2AUseHeld) {
		t.Fatal("registry reset allowance", err)
	}
	f.certificate["certificate_id"] = "a2a-grant-B"
	r, e = f.receiver(t)
	m.receiver = r
	f.request["nonce"] = strings.Repeat("ab", 32)
	if _, err := m.Execute(context.Background(), f.event(t)); !errors.Is(err, ErrA2ANonceHeld) {
		t.Fatal("new certificate replayed nonce", err)
	}
	f.request["nonce"] = strings.Repeat("ef", 32)
	if _, err := m.Execute(context.Background(), f.event(t)); err != nil || p.calls.Load() != 2 {
		t.Fatal("fresh grant/nonce control", err, p.calls.Load())
	}
}

// Changing exact signed certificate bytes under its existing identity refuses
// as a collision even with a new registry pin and a valid owner signature.
func TestA2ADurableCertificateCollision(t *testing.T) {
	f, m, p, e := a2aMediatorFixture(t)
	if _, err := m.Execute(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	f.certificate["expires_at"] = "2026-11-04T14:29:00Z"
	r, e := f.receiver(t)
	m.receiver = r
	before := a2aJournalBytes(t, m)
	if _, err := m.Execute(context.Background(), e); !errors.Is(err, ErrA2ACertificateCollision) {
		t.Fatal("certificate collision accepted", err)
	}
	if p.calls.Load() != 1 || !bytes.Equal(before, a2aJournalBytes(t, m)) {
		t.Fatal("collision had effects")
	}
}

// Validation and unusable provider metadata fail before state access. Expiry
// after acquiring a lock still refuses without a reservation or fake call.
func TestA2ADurablePreReservationRefusals(t *testing.T) {
	for _, mode := range []string{"sender", "missing-provider", "expiry-at-lock", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f, m, p, e := a2aMediatorFixture(t)
			before := a2aJournalBytes(t, m)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			want := error(ErrA2ANoGrant)
			switch mode {
			case "sender":
				e.SenderMXID = "@other:example.invalid"
				m.open = func(context.Context, A2AStateConfig, *A2AReceiver) (*a2aState, error) {
					t.Fatal("invalid request opened state")
					return nil, ErrA2AState
				}
			case "missing-provider":
				m.providerPath = filepath.Join(m.state.Directory, "missing")
				want = ErrLocalProviderUnavailable
				m.open = func(context.Context, A2AStateConfig, *A2AReceiver) (*a2aState, error) {
					t.Fatal("missing provider opened state")
					return nil, ErrA2AState
				}
			case "expiry-at-lock":
				want = ErrA2ATerm
				original := m.open
				m.open = func(ctx context.Context, c A2AStateConfig, r *A2AReceiver) (*a2aState, error) {
					s, err := original(ctx, c, r)
					m.now = func() time.Time { return f.now.Add(time.Hour) }
					return s, err
				}
			case "canceled":
				cancel()
				want = ErrA2AState
			}
			if _, err := m.Execute(ctx, e); !errors.Is(err, want) {
				t.Fatal(mode, err, want)
			}
			if p.calls.Load() != 0 || !bytes.Equal(before, a2aJournalBytes(t, m)) {
				t.Fatal("pre-reservation effects")
			}
		})
	}
}

// Faults at every durable append boundary keep any already-reserved use held.
// UNKNOWN distinguishes an attempted/possible dispatch from pre-call refusal;
// no branch truncates a partial tail or retries the provider.
func TestA2ADurableFaultBoundaries(t *testing.T) {
	for _, mode := range []string{"reservation-write", "reservation-sync", "intent-write", "intent-sync", "outcome-write", "outcome-sync", "provider", "receipt", "context-after-intent", "expiry-after-intent"} {
		t.Run(mode, func(t *testing.T) {
			f, m, p, e := a2aMediatorFixture(t)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := m.open
			writes, syncs := 0, 0
			m.open = func(ctx context.Context, c A2AStateConfig, r *A2AReceiver) (*a2aState, error) {
				s, err := original(ctx, c, r)
				if err != nil {
					return nil, err
				}
				write, synchronize := s.write, s.sync
				s.write = func(file *os.File, b []byte) (int, error) {
					writes++
					if mode == "reservation-write" && writes == 1 || mode == "intent-write" && writes == 2 || mode == "outcome-write" && writes == 3 {
						return write(file, b[:len(b)/2])
					}
					return write(file, b)
				}
				s.sync = func(file *os.File) error {
					syncs++
					if mode == "context-after-intent" && syncs == 2 {
						cancel()
					}
					if mode == "expiry-after-intent" && syncs == 2 {
						m.now = func() time.Time { return f.now.Add(time.Hour) }
					}
					if mode == "reservation-sync" && syncs == 1 || mode == "intent-sync" && syncs == 2 || mode == "outcome-sync" && syncs == 3 {
						return errors.New("inert sync failure")
					}
					return synchronize(file)
				}
				return s, nil
			}
			want, wantCalls := error(ErrA2AState), int64(0)
			switch mode {
			case "provider":
				p.err = errors.New("inert provider failure")
				want, wantCalls = ErrA2AUnknown, 1
			case "receipt":
				p.result = []byte("{}")
				want, wantCalls = ErrA2AUnknown, 1
			case "outcome-write", "outcome-sync":
				want, wantCalls = ErrA2AUnknown, 1
			case "context-after-intent", "expiry-after-intent":
				want = ErrA2AUnknown
			}
			out, err := m.Execute(ctx, e)
			if !errors.Is(err, want) || p.calls.Load() != wantCalls || writes == 0 {
				t.Fatal("fault verdict", mode, out, err, p.calls.Load(), writes)
			}
			if want == ErrA2AUnknown && (out == nil || out.State != "unknown") {
				t.Fatal("missing unknown outcome")
			}
			m.open = original
			m.now = func() time.Time { return f.now }
			before := a2aJournalBytes(t, m)
			_, err = m.Execute(context.Background(), e)
			if !(errors.Is(err, ErrA2AUseHeld) || errors.Is(err, ErrA2AState)) || p.calls.Load() != wantCalls || !bytes.Equal(before, a2aJournalBytes(t, m)) {
				t.Fatal("fault replay resent/repaired", err, p.calls.Load())
			}
		})
	}
}

// One flock spans reservation through receipt. Two cooperating concurrent
// callers obtain exactly one fake call and one consumed-use refusal.
func TestA2ADurableConcurrentUse(t *testing.T) {
	_, m, p, e := a2aMediatorFixture(t)
	p.enter = make(chan struct{})
	p.release = make(chan struct{})
	errs := make(chan error, 2)
	go func() { _, err := m.Execute(context.Background(), e); errs <- err }()
	select {
	case <-p.enter:
	case err := <-errs:
		t.Fatal("no first provider entry", err)
	case <-time.After(3 * time.Second):
		close(p.release)
		t.Fatal("no provider entry")
	}
	go func() { _, err := m.Execute(context.Background(), e); errs <- err }()
	close(p.release)
	success, held := 0, 0
	for i := 0; i < 2; i++ {
		select {
		case err := <-errs:
			if err == nil {
				success++
			} else if errors.Is(err, ErrA2AUseHeld) {
				held++
			} else {
				t.Fatal(err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("concurrent caller did not finish")
		}
	}
	if success != 1 || held != 1 || p.calls.Load() != 1 {
		t.Fatal("duplicate concurrent dispatch", success, held, p.calls.Load())
	}
}

// Missing/corrupt/insecure state never becomes an empty replacement. All
// mutations occur only inside test-owned directories; no user state is opened.
func TestA2ADurableStateRefusals(t *testing.T) {
	for _, mode := range []string{"missing", "empty", "partial", "checksum", "epoch", "permissions", "directory-mode", "directory-link", "journal-link", "hardlink"} {
		t.Run(mode, func(t *testing.T) {
			_, m, p, e := a2aMediatorFixture(t)
			path := filepath.Join(m.state.Directory, "a2a.journal")
			raw := a2aJournalBytes(t, m)
			switch mode {
			case "missing":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
			case "empty":
				if err := os.WriteFile(path, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "partial":
				if err := os.WriteFile(path, raw[:len(raw)-1], 0600); err != nil {
					t.Fatal(err)
				}
			case "checksum":
				raw[len(raw)-1] ^= 1
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "epoch":
				m.state.Epoch[0] ^= 1
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "directory-mode":
				if err := os.Chmod(m.state.Directory, 0755); err != nil {
					t.Fatal(err)
				}
			case "directory-link":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(m.state.Directory, link); err != nil {
					t.Fatal(err)
				}
				m.state.Directory = link
			case "journal-link":
				target := filepath.Join(m.state.Directory, "saved")
				if err := os.Rename(path, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, path); err != nil {
					t.Fatal(err)
				}
			case "hardlink":
				if err := os.Link(path, filepath.Join(m.state.Directory, "alias")); err != nil {
					t.Fatal(err)
				}
			}
			before, _ := os.ReadFile(path)
			if _, err := m.Execute(context.Background(), e); !errors.Is(err, ErrA2AState) || p.calls.Load() != 0 {
				t.Fatal("insecure state accepted", mode, err, p.calls.Load())
			}
			after, err := os.ReadFile(path)
			if mode == "missing" && !errors.Is(err, os.ErrNotExist) {
				t.Fatal("missing journal recreated")
			}
			if !bytes.Equal(before, after) {
				t.Fatal("state repaired/rewritten")
			}
		})
	}
}

// Initialization is explicit/exclusive and refuses any occupied directory,
// including an old-profile-looking directory, without creating G2 files.
func TestA2ADurableInitializationRefusals(t *testing.T) {
	f := a2aFixtureForTest(t)
	r, _ := f.receiver(t)
	dir := t.TempDir()
	config := A2AStateConfig{Directory: dir, Epoch: sha256.Sum256([]byte("fixture"))}
	if err := os.WriteFile(filepath.Join(dir, "local.journal"), []byte("preserved"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitializeA2AState(config, r); !errors.Is(err, ErrA2AState) {
		t.Fatal("occupied directory initialized", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, "a2a.lock")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("G2 file created in occupied directory")
	}
	_, m, _, _ := a2aMediatorFixture(t)
	before := a2aJournalBytes(t, m)
	if err := InitializeA2AState(m.state, m.receiver); !errors.Is(err, ErrA2AState) || !bytes.Equal(before, a2aJournalBytes(t, m)) {
		t.Fatal("existing state reinitialized", err)
	}
}
