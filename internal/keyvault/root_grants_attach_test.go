package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// Fake is deliberately incapable of old private-value access/update/delete or
// native sealing/ACL qualification. Its sealed fixture is structurally valid
// but intentionally NOT an authentic root ciphertext (see envelope tests).
type rootGrantsVault13 struct {
	t                             *testing.T
	pair                          []byte
	oldCiphertext                 []byte
	expected                      rootGrantsSealedItem
	calls                         []string
	held                          bool
	locks, releases, reads, adds  int
	preAddReads                   int
	lockError, inventoryError     bool
	guardWithLockError            bool
	collision, readbackError      bool
	readbackCorrupt, applyOnError bool
	pairErrorAt                   int
	pairChangedAt                 int
	addError                      error
	stored                        *rootGrantsSealedItem
	cancel                        context.CancelFunc
	cancelAt                      string
	entered, proceed              chan struct{}
}

func (f *rootGrantsVault13) LockExistingRootGrants(context.Context) (rootGrantsLockedVault, error) {
	f.calls = append(f.calls, "lock-existing")
	f.locks++
	if f.lockError {
		return nil, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	}
	if f.held {
		f.t.Fatal("fake guard acquired twice")
	}
	f.held = true
	if f.guardWithLockError {
		return f, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	}
	return f, nil
}

func (f *rootGrantsVault13) requireHeld() {
	f.t.Helper()
	if !f.held {
		f.t.Fatal("public storage operation outside existing guard")
	}
}

func (f *rootGrantsVault13) RecoveryPublicMetadata(service string, version int) ([]byte, error) {
	f.requireHeld()
	f.calls = append(f.calls, "pair-public")
	f.reads++
	r, err := ParseRootGrantsRecord([]byte(f.expected.metadata))
	if err != nil || service != r.Pair.Service || version != r.Pair.Version {
		f.t.Fatal("unexpected old public record address")
	}
	if f.reads == f.pairErrorAt {
		return nil, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	}
	if f.cancel != nil && f.cancelAt == "pair-recheck" && f.reads == 2 {
		f.cancel()
	}
	if f.reads == f.pairChangedAt {
		return bytes.Replace(f.pair, []byte("2026-01-02"), []byte("2026-01-03"), 1), nil
	}
	return bytes.Clone(f.pair), nil
}

func (f *rootGrantsVault13) RootGrantsCollision(address RootGrantsAddress) (bool, error) {
	f.requireHeld()
	f.calls = append(f.calls, "collision")
	if address != f.expected.address {
		f.t.Fatal("collision query changed explicit destination")
	}
	if f.inventoryError {
		return false, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	}
	return f.collision || f.stored != nil, nil
}

func (f *rootGrantsVault13) AddRootGrantsOnly(item rootGrantsSealedItem) error {
	f.requireHeld()
	f.calls = append(f.calls, "add-only")
	f.adds++
	wantReads := f.preAddReads
	if wantReads == 0 {
		wantReads = 2
	}
	if f.reads != wantReads || item != f.expected || f.adds != 1 {
		f.t.Fatal("add was not one exact immutable packet after BOTH record checks")
	}
	if f.entered != nil {
		close(f.entered)
		<-f.proceed
	}
	if f.addError == nil || f.applyOnError {
		copy := item
		f.stored = &copy
	}
	if f.cancel != nil && f.cancelAt == "add" {
		f.cancel()
	}
	return f.addError
}

func (f *rootGrantsVault13) RootGrantsPublicMetadata(address RootGrantsAddress) ([]byte, error) {
	f.requireHeld()
	f.calls = append(f.calls, "root-public")
	if address != f.expected.address {
		f.t.Fatal("readback changed explicit destination")
	}
	if f.readbackError || f.stored == nil {
		return nil, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	}
	if f.readbackCorrupt {
		return []byte("{}"), nil
	}
	return []byte(f.stored.metadata), nil
}

func (f *rootGrantsVault13) Release() {
	f.requireHeld()
	f.calls = append(f.calls, "release")
	f.held = false
	f.releases++
}

// Uses only the already published24-word recovery fixture and accepted private
// preparation seam. It consumes the prepared scalar into a PUBLIC/sealed plan.
// Native helper authenticity and enrollment are NOT simulated by this helper.
func rootGrantsAttachFixture13(t *testing.T, schema string) (*rootGrantsAttachment, *rootGrantsVault13, RootGrantsRecord) {
	t.Helper()
	pair, pins := rootGrantsTestPair(t, schema)
	prepared, err := prepareRootGrantsAttach(context.Background(), []byte(recoveryFixturePhrase), pair, pins)
	if err != nil {
		t.Fatal(err)
	}
	defer prepared.clear()
	view, err := prepared.publicView()
	if err != nil {
		t.Fatal(err)
	}
	publicFixture, _ := rootGrantsRecordFixture13(t, schema)
	r, err := NewRootGrantsRecord(RootGrantsAddress{Service: "example-root", Version: 1}, publicFixture.Created, view, publicFixture.WrappingPoint)
	if err != nil {
		t.Fatal(err)
	}
	envelope := rootGrantsEnvelopeFixture13(t, r)
	plan, err := newRootGrantsAttachment(prepared, r, envelope)
	if err != nil {
		t.Fatal(err)
	}
	if *prepared.state.scalar != [32]byte{} {
		t.Fatal("sealed plan retained prepared scalar")
	}
	if _, err := prepared.publicView(); err == nil {
		t.Fatal("consumed prepared handle remains usable")
	}
	f := &rootGrantsVault13{t: t, pair: bytes.Clone(pair), expected: plan.state.item, oldCiphertext: []byte("PUBLIC_FAKE_OLD_CIPHERTEXT_UNCHANGED")}
	return plan, f, r
}

func rootGrantsAttachFailure13(t *testing.T, result RootGrantsAttachResult, err error, code, phase, outcome string) {
	t.Helper()
	var failure *rootGrantsAttachError
	if result != (RootGrantsAttachResult{}) || !errors.As(err, &failure) || failure.public.Code != code || failure.public.Phase != phase || failure.public.Outcome != outcome {
		t.Fatalf("expected closed attach failure %s/%s/%s", code, phase, outcome)
	}
	encoded, marshalError := json.Marshal(failure)
	if marshalError != nil || bytes.Contains(encoded, []byte("PUBLIC_TEST_PRIVATE_SENTINEL")) || bytes.Contains(encoded, []byte("ciphertext")) ||
		bytes.Contains([]byte(fmt.Sprintf("%v %#v", err, err)), []byte("PUBLIC_TEST_PRIVATE_SENTINEL")) {
		t.Fatal("backend diagnostic/sealed value escaped public failure")
	}
	if (outcome == "unknown") != (failure.public.Reference != nil) {
		t.Fatal("unconfirmed public reference/outcome mismatch")
	}
}

// Claim: legitimate v1/v2 attachment does exactly lock/read/collision/re-read/
// ONE add/public readback/old-pair re-read/release; immutable packet and explicit
// destination survive caller buffer changes, and copied attempts cannot replay.
// Limits: fake storage ordering, not actual ACL/native seals or a usable release.
func TestRootGrantsAttach13CreateOnlyOrder(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			plan, fake, r := rootGrantsAttachFixture13(t, schema)
			alias := *plan
			for _, value := range []any{plan, alias} {
				if fmt.Sprintf("%#v", value) != "<root-grants-attachment>" {
					t.Fatal("opaque plan formatted its sealed packet")
				}
				if raw, err := json.Marshal(value); err == nil || len(raw) != 0 {
					t.Fatal("opaque plan serialized its sealed packet")
				}
			}
			oldPair, oldCipher := bytes.Clone(fake.pair), bytes.Clone(fake.oldCiphertext)
			// The plan snapshots canonical bytes, never shallow public slice aliases.
			clear(r.WrappingPoint)
			result, err := plan.commit(context.Background(), fake)
			if err != nil || result.Outcome != "stored" || !result.PairUnchanged || result.Root.Account != "example-root/root-grants@1" || fake.adds != 1 || fake.held || fake.releases != 1 {
				t.Fatal("create-only fake commit failed")
			}
			want := []string{"lock-existing", "pair-public", "collision", "pair-public", "add-only", "root-public", "pair-public", "release"}
			if !reflect.DeepEqual(fake.calls, want) || !bytes.Equal(fake.pair, oldPair) || !bytes.Equal(fake.oldCiphertext, oldCipher) {
				t.Fatal("call order or retained data changed")
			}
			result, err = alias.commit(context.Background(), fake)
			rootGrantsAttachFailure13(t, result, err, "operation_unavailable", "prepare", "not_applied")
			if fake.adds != 1 || fake.locks != 1 {
				t.Fatal("copied attempt retried")
			}
		})
	}
}

// Claim: every pre-add denial (including missing existing guard, stale COMPLETE
// metadata, collision, inventory failure, cancellation) yields no add/readback,
// unchanged old bytes and a terminal attempt. No prerequisite creation exists.
// Limits: guard existence/ACL/code policy are adapter obligations, not fake proof.
func TestRootGrantsAttach13NoWriteOnFailure(t *testing.T) {
	for _, tc := range []struct {
		name, code, phase string
		configure         func(*rootGrantsVault13)
	}{
		{"missing-existing-guard", "lock_unavailable", "lock", func(f *rootGrantsVault13) { f.lockError = true }},
		{"error-with-guard", "lock_unavailable", "lock", func(f *rootGrantsVault13) { f.guardWithLockError = true }},
		{"pair-read-failed", "retained_record_mismatch", "preflight", func(f *rootGrantsVault13) { f.pairErrorAt = 1 }},
		{"first-pair-changed", "retained_record_mismatch", "preflight", func(f *rootGrantsVault13) { f.pairChangedAt = 1 }},
		{"collision", "duplicate", "preflight", func(f *rootGrantsVault13) { f.collision = true }},
		{"inventory-failure", "inventory_changed", "preflight", func(f *rootGrantsVault13) { f.inventoryError = true }},
		{"pair-changed-before-add", "inventory_changed", "commit", func(f *rootGrantsVault13) { f.pairChangedAt = 2 }},
		{"cancel-before-add", "canceled", "commit", func(f *rootGrantsVault13) { f.cancelAt = "pair-recheck" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, fake, _ := rootGrantsAttachFixture13(t, "keyvault-recovery/2")
			before, cipher := bytes.Clone(fake.pair), bytes.Clone(fake.oldCiphertext)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake.cancel = cancel
			tc.configure(fake)
			result, err := plan.commit(ctx, fake)
			rootGrantsAttachFailure13(t, result, err, tc.code, tc.phase, "not_applied")
			if fake.adds != 0 || fake.stored != nil || fake.held || !bytes.Equal(before, fake.pair) || !bytes.Equal(cipher, fake.oldCiphertext) {
				t.Fatal("pre-add failure had a fake storage effect")
			}
			for _, call := range fake.calls {
				if call == "root-public" {
					t.Fatal("pre-add refusal performed root readback")
				}
			}
		})
	}
	for _, mode := range []string{"canceled", "nil-context", "nil-vault"} {
		plan, fake, _ := rootGrantsAttachFixture13(t, "keyvault-recovery/1")
		ctx, cancel := context.WithCancel(context.Background())
		var vault rootGrantsAttachVault = fake
		code, phase := "invalid_arguments", "prepare"
		switch mode {
		case "canceled":
			cancel()
			code, phase = "canceled", "lock"
		case "nil-context":
			ctx = nil
		case "nil-vault":
			vault = nil
		}
		result, err := plan.commit(ctx, vault)
		cancel()
		rootGrantsAttachFailure13(t, result, err, code, phase, "not_applied")
		if len(fake.calls) != 0 {
			t.Fatal("invalid/canceled attempt reached the lock")
		}
	}
}

// Claim: definite backend guarantees remain not_applied; generic add failures
// (whether applied or not), invalid guarantee reasons, lost/corrupt readback,
// post-add old-pair change and cancellation remain UNKNOWN across replay aliases.
// Limits: native dispatch/ACL attestation and real atomic-add behavior unqualified.
func TestRootGrantsAttach13UnknownAndDefiniteEffects(t *testing.T) {
	for _, tc := range []struct {
		name, code, phase, outcome string
		configure                  func(*rootGrantsVault13)
	}{
		{"atomic-duplicate", "duplicate", "commit", "not_applied", func(f *rootGrantsVault13) { f.addError = &rootGrantsAddNotApplied{reason: rootGrantsAddDuplicate} }},
		{"acl-denial", "acl_refused", "commit", "not_applied", func(f *rootGrantsVault13) { f.addError = &rootGrantsAddNotApplied{reason: rootGrantsAddACLRefused} }},
		{"code-denial", "code_not_admitted", "commit", "not_applied", func(f *rootGrantsVault13) { f.addError = &rootGrantsAddNotApplied{reason: rootGrantsAddCodeRefused} }},
		{"wrapping-denial", "wrapping_policy_refused", "commit", "not_applied", func(f *rootGrantsVault13) {
			f.addError = &rootGrantsAddNotApplied{reason: rootGrantsAddWrappingRefused}
		}},
		{"unknown-guarantee", "mutation_unknown", "commit", "unknown", func(f *rootGrantsVault13) { f.addError = &rootGrantsAddNotApplied{reason: 255} }},
		{"legacy-guarantee-is-not-root", "mutation_unknown", "commit", "unknown", func(f *rootGrantsVault13) {
			f.addError = &RecoveryNotAppliedError{Err: errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")}
		}},
		{"nil-guarantee", "mutation_unknown", "commit", "unknown", func(f *rootGrantsVault13) { var absent *rootGrantsAddNotApplied; f.addError = absent }},
		{"generic-pre-effect", "mutation_unknown", "commit", "unknown", func(f *rootGrantsVault13) { f.addError = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL") }},
		{"lost-add-reply", "mutation_unknown", "commit", "unknown", func(f *rootGrantsVault13) {
			f.addError = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
			f.applyOnError = true
		}},
		{"readback-error", "mutation_unknown", "readback", "unknown", func(f *rootGrantsVault13) { f.readbackError = true }},
		{"readback-corrupt", "mutation_unknown", "readback", "unknown", func(f *rootGrantsVault13) { f.readbackCorrupt = true }},
		{"pair-changed-after-add", "mutation_unknown", "readback", "unknown", func(f *rootGrantsVault13) { f.pairChangedAt = 3 }},
		{"cancel-after-add", "mutation_unknown", "readback", "unknown", func(f *rootGrantsVault13) { f.cancelAt = "add" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			plan, fake, _ := rootGrantsAttachFixture13(t, "keyvault-recovery/2")
			alias := *plan
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			fake.cancel = cancel
			tc.configure(fake)
			before, cipher := bytes.Clone(fake.pair), bytes.Clone(fake.oldCiphertext)
			result, err := plan.commit(ctx, fake)
			rootGrantsAttachFailure13(t, result, err, tc.code, tc.phase, tc.outcome)
			if fake.adds != 1 || fake.held || fake.releases != 1 || !bytes.Equal(fake.pair, before) || !bytes.Equal(fake.oldCiphertext, cipher) {
				t.Fatal("mutation handling changed existing data or guard lifetime")
			}
			result, err = alias.commit(context.Background(), fake)
			if tc.outcome == "unknown" {
				rootGrantsAttachFailure13(t, result, err, "mutation_unknown", "commit", "unknown")
			} else {
				rootGrantsAttachFailure13(t, result, err, "operation_unavailable", "prepare", "not_applied")
			}
			if fake.adds != 1 || fake.locks != 1 {
				t.Fatal("terminal attempt retried or selected another generation")
			}
		})
	}
}

// Claim: concurrent copies share one finite attempt; an in-flight replay is
// unconfirmed, never a second add. Limits: Go ownership/race lane only, no native
// cross-process lock or signing-session qualification.
func TestRootGrantsAttach13ConcurrentReplay(t *testing.T) {
	plan, fake, _ := rootGrantsAttachFixture13(t, "keyvault-recovery/2")
	alias := *plan
	fake.entered, fake.proceed = make(chan struct{}), make(chan struct{})
	defer func() {
		select {
		case <-fake.proceed:
		default:
			close(fake.proceed)
		}
	}()
	completed := make(chan error, 1)
	go func() { _, err := plan.commit(context.Background(), fake); completed <- err }()
	select {
	case <-fake.entered:
	case <-time.After(5 * time.Second):
		close(fake.proceed)
		t.Fatal("first attempt did not reach fake add")
	}
	result, err := alias.commit(context.Background(), fake)
	rootGrantsAttachFailure13(t, result, err, "mutation_unknown", "commit", "unknown")
	close(fake.proceed)
	select {
	case err := <-completed:
		if err != nil || fake.adds != 1 || fake.locks != 1 {
			t.Fatal("concurrent alias changed single-add result")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("fake add did not finish")
	}
}

// Claim: prepare failures consume/clear private state and never produce a plan;
// a public record/envelope alone cannot create an opaque attachment capability.
// Limits: private fixture construction does not establish owner enrollment.
func TestRootGrantsAttach13PreparationRefusals(t *testing.T) {
	// This is the complete permitted public-data storage surface, not a broad
	// legacy backend that could later be used to unwrap/change an old pair.
	locked := reflect.TypeOf((*rootGrantsLockedVault)(nil)).Elem()
	allowed := []string{"AddRootGrantsOnly", "RecoveryPublicMetadata", "Release", "RootGrantsCollision", "RootGrantsPublicMetadata"}
	if locked.NumMethod() != len(allowed) {
		t.Fatal("attach store interface widened")
	}
	for i, name := range allowed {
		if locked.Method(i).Name != name {
			t.Fatal("attach store gained an unadmitted operation")
		}
	}
	for _, mode := range []string{"nil", "pair", "public-pin", "envelope", "record"} {
		r, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
		prepared := rootGrantsPrivateFixture13(t, r)
		envelope := rootGrantsEnvelopeFixture13(t, r)
		switch mode {
		case "nil":
			prepared.clear()
			prepared = nil
		case "pair":
			r.Pair.NamecoinIdentity = "other"
		case "public-pin":
			r.PublicKey = ""
		case "envelope":
			envelope.Ciphertext = nil
		case "record":
			r.Presence = "none"
		}
		plan, err := newRootGrantsAttachment(prepared, r, envelope)
		if err == nil || plan != nil {
			t.Fatal("invalid public packet produced attachment plan")
		}
		if prepared != nil && (*prepared.state.scalar != [32]byte{} || prepared.state.ready) {
			t.Fatal("failed attachment preparation retained private state")
		}
	}
}
