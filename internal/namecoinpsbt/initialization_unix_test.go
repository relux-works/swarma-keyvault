//go:build darwin || linux

package namecoinpsbt

import (
	"bytes"
	"reflect"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

type initializationFixture struct {
	events                    []string
	fault                     string
	protected, readback       []byte
	absences, creates, closes int
}

func (f *initializationFixture) checkAbsent() error {
	f.events = append(f.events, "public-absent")
	if f.fault == "public-absent" {
		return syntheticStorageFailure
	}
	return nil
}
func (f *initializationFixture) create() (initializationHistory, error) {
	f.events = append(f.events, "public-create")
	if f.fault == "public-create" {
		return nil, syntheticStorageFailure
	}
	return f, nil
}
func (f *initializationFixture) Close() error { f.closes++; return nil }
func (f *initializationFixture) RequireAbsentForExplicitInitialization() error {
	f.absences++
	f.events = append(f.events, "absent")
	if len(f.protected) != 0 || (f.fault == "absent-first" && f.absences == 1) || (f.fault == "absent-second" && f.absences == 2) {
		return syntheticStorageFailure
	}
	return nil
}
func (f *initializationFixture) CreateInitializedAnchor(b []byte) error {
	f.events = append(f.events, "protected-create")
	f.creates++
	if f.fault == "create-before" {
		return syntheticStorageFailure
	}
	f.protected = bytes.Clone(b)
	if f.fault == "create-after" {
		return syntheticStorageFailure
	}
	return nil
}
func (f *initializationFixture) LoadProtected() ([]byte, error) {
	f.events = append(f.events, "readback")
	f.readback = bytes.Clone(f.protected)
	if f.fault == "readback-tamper" {
		f.readback[len(f.readback)-1] ^= 1
	}
	if f.fault == "readback-error" {
		return f.readback, syntheticStorageFailure
	}
	return f.readback, nil
}
func (f *initializationFixture) Records() ([][]byte, error) {
	f.events = append(f.events, "records")
	if f.fault == "records-error" {
		return nil, syntheticStorageFailure
	}
	if f.fault == "records-present" {
		return [][]byte{{1}}, nil
	}
	return nil, nil
}
func newInitializationFixture(t *testing.T) (*InitializationSession, *initializationFixture, []byte) {
	t.Helper()
	signing, _, material := newSessionFixture(t)
	config := NativeSelection{Schema: "keyvault-namecoin-native-selection/1", Selection: signing.attempt.Selection(), Sidecar: signing.sidecar}
	account, err := initializationAccount(config, fixture(t, "all-four-before-release", "account-pin.json"))
	if err != nil {
		t.Fatal(err)
	}
	f := &initializationFixture{}
	s := &InitializationSession{config: config, account: account, reservation: f}
	t.Cleanup(func() {
		clear(f.protected)
		clear(f.readback)
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, f, material
}

// This in-memory adapter witness checks authentic account-bound genesis,
// exact create/readback ordering and single use. It does not prove native
// absence, durability, consent, biometric policy or production admission.
func TestExplicitInitializationOrderingAndOwnership(t *testing.T) {
	s, f, material := newInitializationFixture(t)
	before := bytes.Clone(material)
	defer clear(before)
	if err := s.CompleteReviewed(material, f); err != nil {
		t.Fatal(err)
	}
	want := []string{"public-absent", "absent", "public-create", "absent", "protected-create", "readback", "records"}
	if !reflect.DeepEqual(f.events, want) || f.creates != 1 {
		t.Fatalf("unexpected event trace: %v", f.events)
	}
	if !bytes.Equal(material, before) {
		t.Fatal("borrowed input changed")
	}
	if !bytes.Equal(f.readback, make([]byte, len(f.readback))) {
		t.Fatal("owned protected readback not cleared")
	}
	anchor, err := namecoinjournal.DecodeProtected(f.protected, s.config.Sidecar.Binding)
	if err != nil {
		t.Fatal(err)
	}
	defer anchor.Clear()
	if err := anchor.VerifyAccount(material); err != nil {
		t.Fatal(err)
	}
	seq, _, err := anchor.Head()
	if err != nil || seq != 0 {
		t.Fatal("initial anchor not genesis")
	}
	requireCode(t, s.CompleteReviewed(material, f), namecoinwire.OutcomeUnknown)
	if !reflect.DeepEqual(f.events, want) || f.creates != 1 {
		t.Fatal("replay produced effects")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if f.closes != 1 {
		t.Fatal("reservation not released exactly once")
	}
}

// Invalid account material and known pre-create refusals cannot create public
// or protected state. A nearby valid control is exercised above.
func TestExplicitInitializationPreCreateRefusals(t *testing.T) {
	for _, tc := range []string{"scalar", "chain", "short", "native-missing", "absent-first", "already-present", "closed"} {
		t.Run(tc, func(t *testing.T) {
			s, f, material := newInitializationFixture(t)
			material = bytes.Clone(material)
			defer clear(material)
			var native ProtectedInitializer = f
			want := namecoinwire.AccountMismatch
			switch tc {
			case "scalar":
				material[0] ^= 1
			case "chain":
				material[32] ^= 1
			case "short":
				material = material[:63]
			case "native-missing":
				native = nil
				want = namecoinwire.JournalUnavailable
			case "absent-first":
				f.fault = tc
				want = namecoinwire.JournalUnavailable
			case "already-present":
				f.protected = []byte("existing opaque item")
				want = namecoinwire.JournalUnavailable
			case "closed":
				if err := s.Close(); err != nil {
					t.Fatal(err)
				}
				want = namecoinwire.OutcomeUnknown
			}
			old := bytes.Clone(f.protected)
			requireCode(t, s.CompleteReviewed(material, native), want)
			if f.creates != 0 || !bytes.Equal(f.protected, old) {
				t.Fatal("pre-create refusal changed protected state")
			}
			for _, event := range f.events {
				if event != "absent" && event != "public-absent" {
					t.Fatalf("pre-create effect: %s", event)
				}
			}
		})
	}
}

// Once public create is attempted every interruption is UNKNOWN. The same
// session cannot retry, delete or repair possibly applied state, including a
// native create that applied its effect before returning an error.
func TestExplicitInitializationInterruptedBoundaries(t *testing.T) {
	for _, fault := range []string{"public-create", "absent-second", "create-before", "create-after", "readback-error", "readback-tamper", "records-error", "records-present"} {
		t.Run(fault, func(t *testing.T) {
			s, f, material := newInitializationFixture(t)
			f.fault = fault
			requireCode(t, s.CompleteReviewed(material, f), namecoinwire.OutcomeUnknown)
			before := bytes.Clone(f.protected)
			defer clear(before)
			events := append([]string(nil), f.events...)
			requireCode(t, s.CompleteReviewed(material, f), namecoinwire.OutcomeUnknown)
			if !reflect.DeepEqual(events, f.events) || !bytes.Equal(before, f.protected) {
				t.Fatal("retry changed possibly applied state")
			}
			if f.creates > 1 || f.closes != 0 {
				t.Fatal("automatic retry or early gate release")
			}
			if fault == "create-after" && len(f.protected) == 0 {
				t.Fatal("lost partially applied state")
			}
			if len(f.readback) != 0 && !bytes.Equal(f.readback, make([]byte, len(f.readback))) {
				t.Fatal("failed readback retained owned secret")
			}
		})
	}
}

// Public selection and exact account pin are checked before gate acquisition;
// these tests exercise only that pure admission step, with no host inventory.
func TestInitializationPublicSelectionRefusals(t *testing.T) {
	for _, change := range []string{"valid", "schema", "pin", "group"} {
		t.Run(change, func(t *testing.T) {
			s, _, _ := newInitializationFixture(t)
			config := s.config
			pin := bytes.Clone(fixture(t, "all-four-before-release", "account-pin.json"))
			switch change {
			case "schema":
				config.Schema = "unknown"
			case "pin":
				pin[len(pin)-1] ^= 1
			case "group":
				config.Selection.Group = "other/recovery@1"
			}
			_, err := initializationAccount(config, pin)
			if change == "valid" {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			want := namecoinwire.AccountMismatch
			if change == "schema" {
				want = namecoinwire.PolicyRefused
			}
			requireCode(t, err, want)
		})
	}
}

// Public absence failure precedes even invalid private material parsing, invokes
// no protected callbacks/create, and latches the session until explicit Close.
// This is a software reservation adapter witness, not native Keychain absence.
func TestExplicitInitializationPublicAbsenceLatches(t *testing.T) {
	s, f, material := newInitializationFixture(t)
	if err := s.CheckPublicAbsent(); err != nil {
		t.Fatal(err)
	}
	f.fault = "public-absent"
	requireCode(t, s.CheckPublicAbsent(), namecoinwire.JournalUnavailable)
	f.fault = ""
	requireCode(t, s.CheckPublicAbsent(), namecoinwire.OutcomeUnknown)
	requireCode(t, s.CompleteReviewed(material, f), namecoinwire.OutcomeUnknown)
	if f.absences != 0 || f.creates != 0 || f.closes != 0 {
		t.Fatal("query failure reached private/create/close")
	}
	if err := s.Close(); err != nil || f.closes != 1 {
		t.Fatal("explicit close")
	}
	s, f, material = newInitializationFixture(t)
	f.fault = "public-absent"
	requireCode(t, s.CompleteReviewed(material[:1], f), namecoinwire.JournalUnavailable)
	if f.absences != 0 || f.creates != 0 {
		t.Fatal("public collision reached protected adapter")
	}
}
