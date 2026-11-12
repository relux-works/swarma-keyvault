//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

var syntheticStorageFailure = errors.New("synthetic storage failure")

type sessionFixture struct {
	t                                *testing.T
	records                          [][]byte
	descriptors, results             map[namecoinjournal.AttemptID][]byte
	protected                        []byte
	events                           []string
	fault                            string
	loads, replaces, appends, closes int
	output                           []byte
}

func (f *sessionFixture) Records() ([][]byte, error) {
	f.events = append(f.events, "records")
	return f.records, nil
}
func (f *sessionFixture) Append(b []byte) error {
	f.appends++
	kind := "D"
	if f.appends == 2 {
		kind = "S"
	}
	f.events = append(f.events, "append-"+kind)
	if f.fault == "append-"+kind {
		return syntheticStorageFailure
	}
	f.records = append(f.records, bytes.Clone(b))
	return nil
}
func (f *sessionFixture) Descriptor(id namecoinjournal.AttemptID) ([]byte, error) {
	b, ok := f.descriptors[id]
	if !ok {
		return nil, syntheticStorageFailure
	}
	return bytes.Clone(b), nil
}
func (f *sessionFixture) Result(id namecoinjournal.AttemptID) ([]byte, error) {
	b, ok := f.results[id]
	if !ok {
		return nil, syntheticStorageFailure
	}
	return bytes.Clone(b), nil
}
func (f *sessionFixture) PutDescriptor(id namecoinjournal.AttemptID, b []byte) error {
	f.events = append(f.events, "descriptor")
	if _, ok := f.descriptors[id]; ok {
		return syntheticStorageFailure
	}
	f.descriptors[id] = bytes.Clone(b)
	return nil
}
func (f *sessionFixture) PutResult(id namecoinjournal.AttemptID, b []byte) error {
	f.events = append(f.events, "result")
	if f.fault == "result" {
		return syntheticStorageFailure
	}
	f.results[id] = bytes.Clone(b)
	return nil
}
func (f *sessionFixture) Close() error { f.closes++; return nil }
func (f *sessionFixture) LoadProtected() ([]byte, error) {
	f.loads++
	kind := "initial"
	if f.loads == 2 {
		kind = "D"
	}
	if f.loads == 3 {
		kind = "S"
	}
	f.events = append(f.events, "load-"+kind)
	b := bytes.Clone(f.protected)
	if f.fault == "readback-"+kind {
		b[len(b)-1] ^= 1
	}
	return b, nil
}
func (f *sessionFixture) ReplaceProtected(b []byte) error {
	f.replaces++
	kind := "D"
	if f.replaces == 2 {
		kind = "S"
	}
	f.events = append(f.events, "replace-"+kind)
	if f.fault == "replace-"+kind {
		return syntheticStorageFailure
	}
	clear(f.protected)
	f.protected = bytes.Clone(b)
	return nil
}
func (f *sessionFixture) WriteVerifiedResult(b []byte) error {
	f.events = append(f.events, "output")
	if f.fault == "output" {
		return syntheticStorageFailure
	}
	result, err := namecoinwire.DecodeResult(b)
	if err != nil {
		return err
	}
	if sha256.Sum256(b) != sha256.Sum256(f.results[attemptIdentity(result.Receipt.PlanSHA256, result.Receipt.Slot)]) {
		return syntheticStorageFailure
	}
	f.output = bytes.Clone(b)
	return nil
}
func newSessionFixture(t *testing.T) (*Session, *sessionFixture, []byte) {
	t.Helper()
	a := preparedFixture(t, "all-four-before-release", "A")
	selected := a.Selection()
	var pin [32]byte
	_, _ = hex.Decode(pin[:], []byte(selected.AccountPinSHA256))
	binding := namecoinjournal.Binding{Group: selected.Group, Account: selected.Account, PublicPin: pin, Policy: selected.Policy.Revision}
	sidecar := namecoinjournal.Sidecar{Binding: binding, NostrAccount: "fixture/nostr@1"}
	// Match the existing group namespace used in the published fixture, never a
	// real selected item. All stores below are explicitly in-memory test fixtures.
	sidecar.NostrAccount = selected.Group[:bytes.IndexByte([]byte(selected.Group), '/')] + "/nostr@1"
	if err := sessionBinding(a, sidecar); err != nil {
		t.Fatal(err)
	}
	material := publishedAccountMaterial(t)
	anchor, err := namecoinjournal.NewInitialization(binding, material)
	if err != nil {
		t.Fatal(err)
	}
	protected, err := anchor.EncodeProtected()
	anchor.Clear()
	if err != nil {
		t.Fatal(err)
	}
	f := &sessionFixture{t: t, protected: protected, descriptors: make(map[namecoinjournal.AttemptID][]byte), results: make(map[namecoinjournal.AttemptID][]byte)}
	s := &Session{attempt: a, sidecar: sidecar, storage: f, now: func() time.Time { return time.Unix(int64(selected.Policy.CreatedAt)+1, 0) }}
	t.Cleanup(func() {
		clear(material)
		clear(f.protected)
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
	})
	return s, f, material
}

// Actual synthetic-account ECDSA produces a publicly verified result only after
// D/protected readback, result persistence/output, then S/protected readback.
// These in-memory adapter fixtures prove orchestration and cryptographic result
// correlation, not filesystem durability, Keychain policy or biometric presence.
func TestSessionCompletedOrderingAndSingleUse(t *testing.T) {
	s, f, material := newSessionFixture(t)
	result, err := s.CompleteReviewed(material, f, f)
	if err != nil {
		t.Fatal(err)
	}
	expected := []string{"load-initial", "records", "descriptor", "append-D", "replace-D", "load-D", "result", "output", "append-S", "replace-S", "load-S"}
	if len(f.events) != len(expected) {
		t.Fatal("unexpected event count", f.events)
	}
	for i, e := range expected {
		if f.events[i] != e {
			t.Fatal("wrong ordering", f.events)
		}
	}
	if !bytes.Equal(result, f.output) {
		t.Fatal("ack result differs from durable output")
	}
	if _, err := s.attempt.candidate.VerifyResult(result, s.attempt.ReviewDigest()); err != nil {
		t.Fatal(err)
	}
	count := len(f.events)
	_, err = s.CompleteReviewed(material, f, f)
	requireCode(t, err, namecoinwire.ReplayRefused)
	if len(f.events) != count {
		t.Fatal("retry touched state")
	}
	if s.Close() != nil || s.Close() != nil || f.closes != 1 {
		t.Fatal("gate released more than once")
	}
}

// Each interrupted durability boundary returns UNKNOWN with no acknowledged
// result. It never retries, removes a fence, auto-initializes or appends S before
// the exact verified public output succeeds. Some failures can leave exported
// signatures; UNKNOWN expressly does not claim that private effect was absent.
func TestSessionInterruptedBoundariesRemainUnknown(t *testing.T) {
	for _, fault := range []string{"append-D", "replace-D", "readback-D", "result", "output", "append-S", "replace-S", "readback-S"} {
		t.Run(fault, func(t *testing.T) {
			s, f, material := newSessionFixture(t)
			f.fault = fault
			result, err := s.CompleteReviewed(material, f, f)
			requireCode(t, err, namecoinwire.OutcomeUnknown)
			if len(result) != 0 {
				t.Fatal("acknowledged incomplete result")
			}
			count := len(f.events)
			_, err = s.CompleteReviewed(material, f, f)
			requireCode(t, err, namecoinwire.ReplayRefused)
			if len(f.events) != count {
				t.Fatal("failed session retried private or durable effect")
			}
			if fault == "append-D" || fault == "replace-D" || fault == "readback-D" {
				if len(f.output) != 0 || len(f.results) != 0 || f.appends != 1 {
					t.Fatal("result/sign completion preceded D readback")
				}
			}
			if fault == "result" || fault == "output" {
				if f.appends != 1 {
					t.Fatal("S preceded successful public persistence/output")
				}
			}
		})
	}
}

// Wrong account material and expired policy refuse before protected/native
// reads or public writes; the nearby complete positive path above still signs.
func TestSessionPresignRefusalsHaveNoObservableEffects(t *testing.T) {
	for _, kind := range []string{"wrong-key", "expired", "wrong-binding"} {
		t.Run(kind, func(t *testing.T) {
			s, f, material := newSessionFixture(t)
			if kind == "wrong-binding" {
				bad := s.sidecar
				bad.Binding.Account = "other/namecoin@1"
				requireCode(t, sessionBinding(s.attempt, bad), namecoinwire.AccountMismatch)
				return
			}
			borrowed := bytes.Clone(material)
			defer clear(borrowed)
			code := namecoinwire.AccountMismatch
			if kind == "wrong-key" {
				borrowed[0] ^= 1
			} else {
				code = namecoinwire.RequestExpired
				s.now = func() time.Time { return time.Unix(int64(s.attempt.candidate.snapshot.Request().ExpiresAt), 0) }
			}
			result, err := s.CompleteReviewed(borrowed, f, f)
			requireCode(t, err, code)
			if len(result) != 0 || len(f.events) != 0 {
				t.Fatal("presign refusal touched native/public state")
			}
		})
	}
}

// Reconciliation after lost acknowledgement recovers exact historical bytes
// without expiry reauthorization, ECDSA, append or protected replacement. A
// result left before S and forged cached bytes remain unrecoverable UNKNOWN.
func TestSessionReconcileCompletedOnly(t *testing.T) {
	for _, kind := range []string{"complete-expired", "missing-S", "changed-result", "changed-descriptor", "wrong-key"} {
		t.Run(kind, func(t *testing.T) {
			s, f, material := newSessionFixture(t)
			if kind == "missing-S" {
				f.fault = "append-S"
			}
			original, firstErr := s.CompleteReviewed(material, f, f)
			if kind == "missing-S" {
				requireCode(t, firstErr, namecoinwire.OutcomeUnknown)
			} else if firstErr != nil {
				t.Fatal(firstErr)
			}
			f.fault = ""
			f.loads = 0
			if kind == "changed-result" {
				f.results[s.attempt.ID()] = append(f.results[s.attempt.ID()], ' ')
			}
			if kind == "changed-descriptor" {
				f.descriptors[s.attempt.ID()][0] ^= 1
			}
			borrowed := bytes.Clone(material)
			defer clear(borrowed)
			if kind == "wrong-key" {
				borrowed[0] ^= 1
			}
			priorEvents, priorAppends, priorReplaces := len(f.events), f.appends, f.replaces
			recovery := &Session{attempt: s.attempt, sidecar: s.sidecar, storage: f, now: func() time.Time { t.Fatal("reconcile consulted signature expiry clock"); return time.Time{} }}
			recovered, err := recovery.ReconcileReviewed(borrowed, f, f)
			if kind == "complete-expired" {
				if err != nil || !bytes.Equal(original, recovered) {
					t.Fatal("completed recovery", err)
				}
			} else {
				code := namecoinwire.OutcomeUnknown
				if kind == "wrong-key" {
					code = namecoinwire.AccountMismatch
				}
				requireCode(t, err, code)
				if len(recovered) != 0 {
					t.Fatal("forged/incomplete result acknowledged")
				}
				for _, event := range f.events[priorEvents:] {
					if event == "output" {
						t.Fatal("unverified recovery exported result")
					}
				}
			}
			if f.appends != priorAppends || f.replaces != priorReplaces {
				t.Fatal("recovery changed fenced or protected state")
			}
		})
	}
}
