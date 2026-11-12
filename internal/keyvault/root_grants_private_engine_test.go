package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"
)

func rootGrantsEngine28(t *testing.T, ctx context.Context) *rootGrantsPrivateEngine {
	t.Helper()
	r, raw := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	e, err := newRootGrantsPrivateEngine(ctx, rootGrantsEngineInput{pairMetadata: raw, pair: r.Pair,
		target: RootGrantsAddress{Service: "example-root", Version: 1}, created: r.Created})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.close)
	return e
}

// Test-only composition mirrors prepare's phases, substituting only the pure
// line-I/O grammar for the production self-opened tty. No external seed API,
// native wrap, biometric success, stored/enrolled receipt or ABI is simulated.
func rootGrantsPrepareLines28(e *rootGrantsPrivateEngine, f *rootGrantsLines28) (RootGrantsPreparationPublic, error) {
	if err := e.startInput(); err != nil {
		return RootGrantsPreparationPublic{}, err
	}
	phrase, err := readRootGrantsNumbered(e.state.ctx, f)
	if err != nil {
		e.close()
		return RootGrantsPreparationPublic{}, err
	}
	return e.finishInput(phrase)
}

func rootGrantsEnginePrepared28(e *rootGrantsPrivateEngine) *rootGrantsPrepared {
	e.state.mu.Lock()
	defer e.state.mu.Unlock()
	return e.state.prepared
}

func rootGrantsPreparedCleared28(t *testing.T, p *rootGrantsPrepared) {
	t.Helper()
	if p == nil {
		return
	}
	p.state.mu.Lock()
	defer p.state.mu.Unlock()
	if *p.state.scalar != [32]byte{} || p.state.ready {
		t.Fatal("private preparation retained material after closure")
	}
}

// Claim: one bounded private attempt accepts both retained pins from published
// numbered input, returns public preparation only, then seals once; same900s
// deadline and opaque/shared-clear lifetime survive phases and copied handles.
// Limits: fake public point/blob; no actual tty/native review/biometry or store.
func TestRootGrantsPrivateEngine28Flow(t *testing.T) {
	e := rootGrantsEngine28(t, context.Background())
	alias := *e
	deadline, ok := e.state.ctx.Deadline()
	if !ok || time.Until(deadline) > rootGrantsAttemptLimit || time.Until(deadline) <= 0 {
		t.Fatal("whole-attempt deadline missing")
	}
	f := &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\r', '\n'})}
	view, err := rootGrantsPrepareLines28(e, f)
	if err != nil || view.Pair != e.state.input.pair || view.Root.Path != "m/83696968h/2h/7h" {
		t.Fatal("numbered existing-pair preparation failed")
	}
	rootGrantsReturnedCleared28(t, f)
	after, _ := e.state.ctx.Deadline()
	if after != deadline {
		t.Fatal("phase renewed whole-attempt deadline")
	}
	prepared := *rootGrantsEnginePrepared28(e)
	e.state.mu.Lock()
	stateCopy := *e.state
	e.state.mu.Unlock()
	for _, value := range []any{e, alias, stateCopy, &stateCopy} {
		if fmt.Sprintf("%#v", value) != "<private-root-grants-engine>" {
			t.Fatal("private engine formatted its state")
		}
		if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
			t.Fatal("private engine serialized its state")
		}
	}
	r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	random := &rootGrantsRandom28{}
	sealed, err := e.sealWithRandom(r.WrappingPoint, []byte{1}, random)
	if err != nil || random.calls != 1 || len(sealed.metadata) == 0 || len(sealed.envelope.Ciphertext) != 149 {
		t.Fatal("one private engine seal failed")
	}
	record, err := ParseRootGrantsRecord(sealed.metadata)
	if err != nil || record.PublicKey != view.Root.PublicKey || record.Pair != view.Pair {
		t.Fatal("sealed public metadata changed preparation")
	}
	plain, err := rootGrantsOpen28(sealed.envelope, record, 3)
	if err != nil {
		t.Fatal("engine envelope failed independent private binding check")
	}
	plain.clear()
	rootGrantsPreparedCleared28(t, &prepared)
	if rootGrantsEnginePrepared28(e) != nil {
		t.Fatal("closed engine retained preparation")
	}
	second, err := alias.sealWithRandom(r.WrappingPoint, []byte{1}, random)
	if err == nil || !reflect.DeepEqual(second, rootGrantsEngineSealed{}) || random.calls != 1 {
		t.Fatal("post-call alias reused sealing phase")
	}
}

// Claim: malformed numbered input/checksum and a checksum-valid WRONG published
// phrase produce no preparation/sealed result and no random/wrap invocation;
// cancellation at read/after pins/before seal and duplicate phases clear state.
// Limits: pure private composition and synthetic randomness; native effects absent.
func TestRootGrantsPrivateEngine28Refusals(t *testing.T) {
	cases := rootGrantsBadLines28()
	wrong := append(bytes.Repeat([]byte("abandon "), 23), []byte("art")...)
	cases["checksum-valid-wrong-phrase"] = rootGrantsNumbered28(wrong, []byte{'\n'})
	clear(wrong)
	for name, lines := range cases {
		t.Run(name, func(t *testing.T) {
			e := rootGrantsEngine28(t, context.Background())
			view, err := rootGrantsPrepareLines28(e, &rootGrantsLines28{lines: lines})
			if err == nil || view != (RootGrantsPreparationPublic{}) || rootGrantsEnginePrepared28(e) != nil {
				t.Fatal("bad grammar/phrase produced preparation")
			}
			if name == "checksum-valid-wrong-phrase" {
				rootGrantsWantRefusal(t, err, "public_pin_mismatch")
			}
			if name == "bad-checksum" {
				rootGrantsWantRefusal(t, err, "invalid_checksum")
			}
			random := &rootGrantsRandom28{}
			sealed, err := e.sealWithRandom(nil, nil, random)
			if err == nil || !reflect.DeepEqual(sealed, rootGrantsEngineSealed{}) || random.calls != 0 {
				t.Fatal("bad input reached random/sealing")
			}
		})
	}
	for _, mode := range []string{"cancel-read", "cancel-after-pins", "cancel-during-seal", "duplicate-prepare", "duplicate-finish", "seal-before-prepare", "reuse-nostr-wrap", "reuse-namecoin-wrap"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			e := rootGrantsEngine28(t, ctx)
			f := &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}
			var owned *rootGrantsPrepared
			if mode == "cancel-read" {
				f.cancel, f.cancelAt = cancel, 12
			}
			if mode != "seal-before-prepare" {
				view, err := rootGrantsPrepareLines28(e, f)
				if mode == "cancel-read" {
					if err == nil || view != (RootGrantsPreparationPublic{}) {
						t.Fatal("canceled read returned preparation")
					}
				} else if err != nil {
					t.Fatal("paired valid preparation failed")
				}
				owned = rootGrantsEnginePrepared28(e)
			}
			random := &rootGrantsRandom28{}
			wantCalls := 0
			switch mode {
			case "cancel-after-pins":
				cancel()
			case "cancel-during-seal":
				random.cancel, wantCalls = cancel, 1
			case "duplicate-prepare":
				if e.startInput() == nil {
					t.Fatal("duplicate preparation phase accepted")
				}
			case "duplicate-finish":
				phrase := []byte(recoveryFixturePhrase)
				if _, err := e.finishInput(phrase); err == nil || !bytes.Equal(phrase, make([]byte, len(phrase))) {
					t.Fatal("duplicate completion accepted or retained words")
				}
			}
			r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
			if mode == "reuse-nostr-wrap" || mode == "reuse-namecoin-wrap" {
				old, err := parseRecoveryRecord(e.state.input.pairMetadata)
				if err != nil {
					t.Fatal("public pair fixture invalid")
				}
				r.WrappingPoint = old.Nostr.WrappingPoint
				if mode == "reuse-namecoin-wrap" {
					r.WrappingPoint = old.Namecoin.WrappingPoint
				}
			}
			sealed, err := e.sealWithRandom(r.WrappingPoint, []byte{1}, random)
			if err == nil || !reflect.DeepEqual(sealed, rootGrantsEngineSealed{}) || random.calls != wantCalls {
				t.Fatal("failed phase returned result or unexpected randomness")
			}
			rootGrantsPreparedCleared28(t, owned)
		})
	}
}

// Claim: each independently swapped VALID social/account/origin pin reaches
// derived-pin comparison despite a matching full metadata hash/external record.
// Limits: published/synthetic offline fixtures, not authenticated native lookup.
func TestRootGrantsPrivateEngine28BothPins(t *testing.T) {
	var rows []struct {
		Public string `json:"public_key"`
		NPub   string `json:"npub"`
		XPub   string `json:"namecoin_xpub"`
		Origin string `json:"origin"`
	}
	fixture, err := os.ReadFile("testdata/recovery/reference-public.json")
	if err != nil || json.Unmarshal(fixture, &rows) != nil || len(rows) != 5 {
		t.Fatal("public reference fixture unavailable")
	}
	for _, mutate := range []func(*RecoveryRecord){
		func(r *RecoveryRecord) { r.Nostr.PublicKey, r.Nostr.NPub = rows[2].Public, rows[2].NPub },
		func(r *RecoveryRecord) { r.Namecoin.XPub = rows[2].XPub },
		func(r *RecoveryRecord) { r.Namecoin.Origin = rows[2].Origin },
	} {
		root, raw := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
		r, err := parseRecoveryRecord(raw)
		if err != nil {
			t.Fatal("retained public fixture invalid")
		}
		mutate(&r)
		changed := rootGrantsRaw13(t, r)
		pins := rootGrantsPairBinding(changed, r)
		e, err := newRootGrantsPrivateEngine(context.Background(), rootGrantsEngineInput{pairMetadata: changed, pair: pins,
			target: RootGrantsAddress{Service: "example-root", Version: 1}, created: root.Created})
		if err != nil {
			t.Fatal("valid negative pin record rejected before derived comparison")
		}
		t.Cleanup(e.close)
		view, err := rootGrantsPrepareLines28(e, &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})})
		rootGrantsWantRefusal(t, err, "public_pin_mismatch")
		if view != (RootGrantsPreparationPublic{}) || rootGrantsEnginePrepared28(e) != nil {
			t.Fatal("wrong derived pin produced preparation")
		}
		random := &rootGrantsRandom28{}
		sealed, err := e.sealWithRandom(root.WrappingPoint, []byte{1}, random)
		if err == nil || !reflect.DeepEqual(sealed, rootGrantsEngineSealed{}) || random.calls != 0 {
			t.Fatal("pin mismatch reached sealing")
		}
	}
}

// Claim: abandonment cancellation clears a prepared handle without needing a
// next phase, invalid config fails before a handle, and phase clocks cannot
// extend900s. Limits: Go context/lifetime only, not actual tty/signal behavior.
func TestRootGrantsPrivateEngine28DeadlineAndInputs(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	e := rootGrantsEngine28(t, ctx)
	if _, err := rootGrantsPrepareLines28(e, &rootGrantsLines28{lines: rootGrantsNumbered28([]byte(recoveryFixturePhrase), []byte{'\n'})}); err != nil {
		t.Fatal(err)
	}
	owned := rootGrantsEnginePrepared28(e)
	cancel()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(2 * time.Second)
	defer timeout.Stop()
	for {
		e.state.mu.Lock()
		closed := e.state.phase == rootGrantsEngineClosed && e.state.prepared == nil
		e.state.mu.Unlock()
		if closed {
			break
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatal("abandoned private preparation was not invalidated")
		}
	}
	if _, err := owned.publicView(); err == nil {
		t.Fatal("canceled abandoned handle remains usable")
	}
	r, raw := rootGrantsRecordFixture13(t, "keyvault-recovery/1")
	for _, mode := range []string{"nil-context", "expired", "metadata", "pin", "target", "created"} {
		input := rootGrantsEngineInput{pairMetadata: raw, pair: r.Pair, target: RootGrantsAddress{Service: "example-root", Version: 1}, created: r.Created}
		var parent context.Context = context.Background()
		var stop context.CancelFunc
		switch mode {
		case "nil-context":
			parent = nil
		case "expired":
			parent, stop = context.WithDeadline(parent, time.Now().Add(-time.Second))
		case "metadata":
			input.pairMetadata = []byte("null")
		case "pin":
			input.pair.NamecoinIdentity = "other"
		case "target":
			input.target.Version = 0
		case "created":
			input.created = "2026-01-02T03:04:05+00:00"
		}
		bad, err := newRootGrantsPrivateEngine(parent, input)
		if stop != nil {
			stop()
		}
		if err == nil || bad != nil {
			t.Fatal("invalid private-engine public config accepted")
		}
	}
}
