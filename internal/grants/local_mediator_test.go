package grants

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func localReceiptFixture() []byte {
	return []byte(`{"id":42,"node_id":"R_kgDO_fixture","full_name":"relux-works/matrix-grants-poc-261031","private":true,"owner":{"login":"relux-works"},"description":null}`)
}

type localFakeProvider struct {
	mu     sync.Mutex
	calls  int
	result []byte
	err    error
	check  func(*checkedLocalCreate)
}

func (p *localFakeProvider) create(_ context.Context, c *checkedLocalCreate) ([]byte, error) {
	p.mu.Lock()
	p.calls++
	p.mu.Unlock()
	if p.check != nil {
		p.check(c)
	}
	return bytes.Clone(p.result), p.err
}

func localMediatorFixture(t *testing.T) (*localFixture, *LocalMediator, *localFakeProvider, []byte, []byte) {
	t.Helper()
	f := localTestFixture(t)
	e, err := ParseLocalEnrollment(requestTestBytes(t, f.config))
	if err != nil {
		t.Fatal(err)
	}
	m := NewLocalMediator(e)
	provider := &localFakeProvider{result: localReceiptFixture()}
	m.provider = provider
	m.now = func() time.Time { return f.now }
	c, q := f.envelopes(t)
	return f, m, provider, c, q
}

// The provider receives the same immutable checked request, only after exactly
// two valid physical frames (reservation+intent) are on disk. Success adds its
// receipt; reopening or changing request_id never supplies another allowance.
func TestLocalMediatorDurableAndReplay(t *testing.T) {
	f, m, p, c, q := localMediatorFixture(t)
	p.check = func(checked *checkedLocalCreate) {
		if !bytes.Equal(checked.certificate, c) || !bytes.Equal(checked.attestation, q) || checked.request.createTarget.name != LocalRepository {
			t.Error("provider did not receive exact checked bytes")
		}
		file, err := os.Open(filepath.Join(m.enrollment.stateDir, "local.journal"))
		if err != nil {
			t.Error(err)
			return
		}
		defer file.Close()
		scan, err := scanJournalFrames(file, m.enrollment.epoch, journalScanMaxBytes)
		if err != nil || scan.frameCount != 2 {
			t.Error("intent not durable before dispatch", scan, err)
		}
	}
	out, err := m.Execute(context.Background(), c, q)
	if err != nil || out.State != "succeeded" || out.RepositoryID != "42" || p.calls != 1 {
		t.Fatal("valid mediation", out, err, p.calls)
	}
	p.check = nil
	if _, err := m.Execute(context.Background(), c, q); !errors.Is(err, ErrLocalUseHeld) || p.calls != 1 {
		t.Fatal("exact replay dispatched", err, p.calls)
	}
	f.request["request_id"] = "request-B"
	_, changed := f.envelopes(t)
	if _, err := m.Execute(context.Background(), c, changed); !errors.Is(err, ErrLocalUseHeld) || p.calls != 1 {
		t.Fatal("request ID replenished use", err, p.calls)
	}
	s, err := openLocalState(context.Background(), m.enrollment)
	if err != nil {
		t.Fatal("replay failed", err)
	}
	defer s.close()
	if s.link.sequence != 4 || len(s.uses) != 1 {
		t.Fatal("wrong durable frame/state count")
	}
	for _, held := range s.uses {
		if !held.intent || held.receipt == nil || held.receipt.id != 42 {
			t.Fatal("receipt not reconstructed")
		}
	}
}

// Invalid authority performs no state open, no authorizing writes and no
// provider attempt. A valid control follows each refusal in a fresh fixture.
func TestLocalMediatorRejectsBeforeState(t *testing.T) {
	for _, mode := range []string{"unsigned", "wrong-requester", "changed-request", "expired", "target", "delete"} {
		t.Run(mode, func(t *testing.T) {
			f, m, p, c, q := localMediatorFixture(t)
			want := error(errBadSchema)
			switch mode {
			case "unsigned":
				c = requestTestBytes(t, f.certificate)
			case "wrong-requester":
				m.enrollment.requesterDER = f.ownerDER
				want = errRequesterMismatch
			case "changed-request":
				q = append(bytes.Clone(q), '\n')
				want = errBadEncoding
			case "expired":
				m.now = func() time.Time { return f.now.Add(time.Hour) }
				want = ErrExpired
			case "target":
				f.request["target"].(map[string]any)["name"] = "other"
				_, q = f.envelopes(t)
				want = errResourceMismatch
			case "delete":
				f.request["action"] = "repository.delete"
				f.request["entry_id"] = "repo-delete"
				f.request["target"] = map[string]any{"organization": LocalOrganization, "name": LocalRepository, "repository_id": "42", "create_operation_use_id": "codex-dm/create", "create_result_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
				_, q = f.envelopes(t)
				want = errResourceMismatch
			}
			opened := 0
			original := m.open
			m.open = func(ctx context.Context, e *LocalEnrollment) (*localState, error) { opened++; return original(ctx, e) }
			if out, err := m.Execute(context.Background(), c, q); !errors.Is(err, want) || out != nil || p.calls != 0 || opened != 0 {
				t.Fatal("authority refusal touched state/provider", out, err, p.calls, opened)
			}
			entries, err := os.ReadDir(m.enrollment.stateDir)
			if err != nil || len(entries) != 0 {
				t.Fatal("refusal changed state directory", err)
			}
			_, valid, vp, vc, vq := localMediatorFixture(t)
			if _, err := valid.Execute(context.Background(), vc, vq); err != nil || vp.calls != 1 {
				t.Fatal("valid neighbor", err)
			}
		})
	}
}

// Provider rejection/invalid or ambiguous output and receipt-write failure make
// one attempt, retain intent, and never resend after reopening. Pre-dispatch
// append/sync failures make no provider call; partial tails block without repair.
func TestLocalMediatorFaults(t *testing.T) {
	for _, mode := range []string{"reservation-write", "reservation-short", "reservation-sync", "intent-write", "intent-sync", "provider-failed", "receipt-invalid", "outcome-write", "outcome-sync", "context-after-intent"} {
		t.Run(mode, func(t *testing.T) {
			_, m, p, c, q := localMediatorFixture(t)
			writes, syncs := 0, 0
			wantCalls := 0
			wantErr := error(ErrLocalState)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			original := m.open
			m.open = func(ctx context.Context, e *LocalEnrollment) (*localState, error) {
				s, err := original(ctx, e)
				if err != nil {
					t.Fatal("fault fixture could not open valid state", err)
				}
				s.write = func(file *os.File, raw []byte) (int, error) {
					writes++
					if mode == "reservation-write" && writes == 1 || mode == "intent-write" && writes == 2 || mode == "outcome-write" && writes == 3 {
						return 0, io.ErrClosedPipe
					}
					if mode == "reservation-short" && writes == 1 {
						return file.Write(raw[:len(raw)/2])
					}
					return file.Write(raw)
				}
				s.sync = func(file *os.File) error {
					syncs++
					if mode == "reservation-sync" && syncs == 1 || mode == "intent-sync" && syncs == 2 || mode == "outcome-sync" && syncs == 3 {
						return io.ErrClosedPipe
					}
					err := file.Sync()
					if mode == "context-after-intent" && syncs == 2 {
						cancel()
					}
					return err
				}
				return s, nil
			}
			switch mode {
			case "provider-failed":
				p.err = errors.New("fixture failure")
				wantCalls = 1
				wantErr = ErrLocalUnknown
			case "receipt-invalid":
				p.result = []byte(`{"id":42}`)
				wantCalls = 1
				wantErr = ErrLocalUnknown
			case "outcome-write", "outcome-sync":
				wantCalls = 1
				wantErr = ErrLocalUnknown
			case "context-after-intent":
				wantErr = ErrLocalUnknown
			}
			out, err := m.Execute(ctx, c, q)
			if writes == 0 {
				t.Fatal("fault did not exercise the append boundary")
			}
			if !errors.Is(err, wantErr) || p.calls != wantCalls {
				t.Fatal("fault boundary", out, err, p.calls)
			}
			if wantErr == ErrLocalUnknown && (out == nil || out.State != "unknown") {
				t.Fatal("unknown not explicit")
			}
			// With a retained complete reservation, every later replay stays held.
			// A deliberately partial first frame is corruption, never auto-truncated.
			if mode != "reservation-write" {
				m.open = original
				before, _ := os.ReadFile(filepath.Join(m.enrollment.stateDir, "local.journal"))
				_, err := m.Execute(context.Background(), c, q)
				if !(errors.Is(err, ErrLocalUseHeld) || errors.Is(err, ErrLocalState)) || p.calls != wantCalls {
					t.Fatal("fault replay resent", err, p.calls)
				}
				after, _ := os.ReadFile(filepath.Join(m.enrollment.stateDir, "local.journal"))
				if !bytes.Equal(before, after) {
					t.Fatal("replay repaired/rewrote journal")
				}
			}
		})
	}
}

// The local flock serializes concurrent requests for the same logical use.
// A second verified request cannot get a dispatch while the first is in flight.
func TestLocalMediatorConcurrentUse(t *testing.T) {
	_, m, p, c, q := localMediatorFixture(t)
	entered := make(chan struct{})
	release := make(chan struct{})
	p.check = func(*checkedLocalCreate) { close(entered); <-release }
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	wg.Add(1)
	go func() { defer wg.Done(); _, err := m.Execute(context.Background(), c, q); errs <- err }()
	select {
	case <-entered:
	case err := <-errs:
		t.Fatal("first caller refused before provider entry", err)
	case <-time.After(2 * time.Second):
		t.Fatal("fixture did not reach provider boundary")
	}
	wg.Add(1)
	go func() { defer wg.Done(); _, err := m.Execute(context.Background(), c, q); errs <- err }()
	close(release)
	wg.Wait()
	close(errs)
	success, held := 0, 0
	for err := range errs {
		if err == nil {
			success++
		} else if errors.Is(err, ErrLocalUseHeld) {
			held++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || held != 1 || p.calls != 1 {
		t.Fatal("concurrent duplicate dispatch", success, held, p.calls)
	}
}

// Physical corruption, partial tail, changed enrollment epoch and immutable ID
// collisions refuse without another provider call or any journal rewrite.
func TestLocalMediatorStateRefusals(t *testing.T) {
	for _, mode := range []string{"checksum", "incomplete", "epoch", "certificate-id", "request-id", "permissions", "symlink"} {
		t.Run(mode, func(t *testing.T) {
			f, m, p, c, q := localMediatorFixture(t)
			if _, err := m.Execute(context.Background(), c, q); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(m.enrollment.stateDir, "local.journal")
			raw, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			want := error(ErrLocalState)
			switch mode {
			case "checksum":
				raw[len(raw)-1] ^= 1
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "incomplete":
				raw = append(raw, 1)
				if err := os.WriteFile(path, raw, 0600); err != nil {
					t.Fatal(err)
				}
			case "epoch":
				f.config["gh_path"] = localExecutableMetadataFixture(t)
				m.enrollment, err = ParseLocalEnrollment(requestTestBytes(t, f.config))
				if err != nil {
					t.Fatal(err)
				}
			case "certificate-id":
				c, _ = f.envelopes(t)
				want = ErrLocalCertificateCollision
			case "request-id":
				f.request["expires_at"] = "2026-11-02T11:29:59Z"
				_, q = f.envelopes(t)
				want = ErrLocalRequestCollision
			case "permissions":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				other := path + ".retained"
				if err := os.Rename(path, other); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(other, path); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := m.Execute(context.Background(), c, q); !errors.Is(err, want) || p.calls != 1 {
				t.Fatal("state refusal", err, p.calls)
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, raw) {
				t.Fatal("refusal changed journal", err)
			}
		})
	}
}

// Host-time validity is checked again after acquiring a potentially contended
// lock and again immediately before dispatch; neither expiry can trigger gh.
func TestLocalMediatorExpiryWhileWaiting(t *testing.T) {
	for _, at := range []int{2, 3} {
		t.Run(string(rune('0'+at)), func(t *testing.T) {
			f, m, p, c, q := localMediatorFixture(t)
			calls := 0
			m.now = func() time.Time {
				calls++
				if calls >= at {
					return f.now.Add(time.Hour)
				}
				return f.now
			}
			_, err := m.Execute(context.Background(), c, q)
			if p.calls != 0 {
				t.Fatal("expired request dispatched")
			}
			if at == 2 && !errors.Is(err, ErrExpired) || at == 3 && !errors.Is(err, ErrLocalUnknown) {
				t.Fatal("wrong expiry boundary", err)
			}
		})
	}
}
