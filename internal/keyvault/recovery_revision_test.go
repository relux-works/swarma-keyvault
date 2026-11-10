package keyvault

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

type recoveryLostResponseStore struct{ *recoveryFakeStore }

func (s *recoveryLostResponseStore) RecoveryStore(r RecoveryRecord, b []byte) error {
	if err := s.recoveryFakeStore.RecoveryStore(r, b); err != nil {
		return err
	}
	return &StatusError{Op: "synthetic response loss", Status: -25291}
}

// A committed fake add followed by response loss must retain an unconfirmed
// public reference and forbid a blind retry; it must not erase the created pair.
func TestRecoveryPostEffectResponseLoss(t *testing.T) {
	for _, restore := range []bool{false, true} {
		t.Run(map[bool]string{false: "generate", true: "restore"}[restore], func(t *testing.T) {
			m, f, _ := recoveryTestManager(t)
			m.backend = &recoveryLostResponseStore{f}
			q := recoveryTestRequest()
			terminal := &recoveryFakeTerminal{}
			op := "generate"
			if restore {
				v, err := deriveRecovery([]byte(recoveryFixturePhrase))
				if err != nil {
					t.Fatal(err)
				}
				defer v.clear()
				q.ExpectedNPub = v.npub
				q.ExpectedXPub = v.xpub
				q.ExpectedOrigin = v.origin
				terminal.phrase = []byte(recoveryFixturePhrase)
				op = "restore"
			}
			r, err := m.Create(q, terminal, restore)
			c := ClassifyError(err)
			var u *RecoveryOutcomeUnknown
			if !errors.As(err, &u) || u.Operation != op || u.Outcome != "unknown" || u.Reference.GroupID != r.GroupID || c.Code != RecoveryOutcomeUnknownCode || !c.Failure || r.GroupID == "" || len(f.groups) != 1 || f.stores != 1 || f.deletes != 0 {
				t.Fatalf("lost add response discarded uncertainty/reference: code=%s failure=%v reference=%v stores=%d deletes=%d", c.Code, c.Failure, r.GroupID != "", f.stores, f.deletes)
			}
			if strings.Contains(c.Message, "synthetic") || strings.Contains(c.Hint, "rerun") {
				t.Fatal("unsafe backend diagnostic escaped")
			}
		})
	}
}

type recoveryNamespaceStore struct {
	*recoveryFakeStore
	creates int
}

func (s *recoveryNamespaceStore) rows() ([]NostrRecord, []RecoveryRecord, error) {
	var rows bytes.Buffer
	for _, r := range s.keys {
		b, _ := json.Marshal(r)
		rows.WriteString(r.Account())
		rows.WriteByte(0x1f)
		rows.Write(b)
		rows.WriteByte(0x1e)
	}
	for _, r := range s.groups {
		b, _ := json.Marshal(r)
		rows.WriteString(r.Account())
		rows.WriteByte(0x1f)
		rows.Write(b)
		rows.WriteByte(0x1e)
	}
	return recoveryRows(rows.Bytes())
}
func (s *recoveryNamespaceStore) List() ([]NostrRecord, error) { n, _, err := s.rows(); return n, err }
func (s *recoveryNamespaceStore) RecoveryList() ([]RecoveryRecord, error) {
	_, g, err := s.rows()
	return g, err
}
func (s *recoveryNamespaceStore) Create(r NostrRecord) (NostrRecord, error) {
	s.creates++
	r, secret, err := newNostrMaterial(r)
	clear(secret)
	if err == nil {
		s.keys = append(s.keys, r)
	}
	return r, err
}

// All physical/logical pair accounts reserve legacy names, while a neighboring
// purpose/version/service remains usable. The inverse creation order is refused.
func TestRecoveryNamespaceReservations(t *testing.T) {
	for _, purpose := range []string{"namecoin", "recovery", "nostr"} {
		t.Run(purpose, func(t *testing.T) {
			m, f, _ := recoveryTestManager(t)
			r := recoveryTestRestore(t, m)
			s := &recoveryNamespaceStore{recoveryFakeStore: f}
			n := NewNostrManager(s, m.lock)
			version := r.Version
			if purpose == "nostr" {
				version = r.Nostr.Version
			}
			_, err := n.Generate(r.Service, purpose, version)
			var refusal *Refusal
			if !errors.As(err, &refusal) || refusal.Code != "nostr_duplicate" || s.creates != 0 {
				t.Fatalf("reserved name admitted: purpose=%s creates=%d err=%v", purpose, s.creates, err)
			}
			for _, q := range []struct {
				s, p string
				v    int
			}{{r.Service, purpose, version + 10}, {r.Service, "other", version}, {"other", purpose, version}} {
				if _, err := n.Generate(q.s, q.p, q.v); err != nil {
					t.Fatal("valid neighbor refused", err)
				}
				if _, _, err := s.rows(); err != nil {
					t.Fatal("inventory poisoned by valid neighbor", err)
				}
			}
		})
	}
}

// The inverse order rejects every paired address before terminal or helper
// work; unrelated pre-existing legacy records do not block a valid pair.
func TestRecoveryNamespaceInverseOrder(t *testing.T) {
	for _, purpose := range []string{"nostr", "namecoin", "recovery", "other"} {
		t.Run(purpose, func(t *testing.T) {
			m, f, h := recoveryTestManager(t)
			s := &recoveryNamespaceStore{recoveryFakeStore: f}
			m.backend = s
			n := NewNostrManager(s, m.lock)
			v := 1
			if purpose == "nostr" {
				v = 2
			}
			if _, err := n.Generate("test", purpose, v); err != nil {
				t.Fatal(err)
			}
			terminal := &recoveryFakeTerminal{}
			_, err := m.Create(recoveryTestRequest(), terminal, false)
			if purpose == "other" {
				if err != nil || f.stores != 1 {
					t.Fatal("valid existing neighbor refused", err)
				}
			} else {
				recoveryCode(t, err, "duplicate")
				if terminal.confirmation != 0 || h.calls != 0 || f.stores != 0 {
					t.Fatal("reservation refusal followed side effects")
				}
			}
			if _, _, err := s.rows(); err != nil {
				t.Fatal("inventory poisoned", err)
			}
		})
	}
}

type recoveryLostDeleteStore struct{ *recoveryFakeStore }

func (s *recoveryLostDeleteStore) RecoveryDelete(r RecoveryRecord) error {
	if err := s.recoveryFakeStore.RecoveryDelete(r); err != nil {
		return err
	}
	return errors.New("synthetic sensitive backend detail")
}

// Lost deletion acknowledgement preserves the public reconciliation reference
// but cannot claim the item was retained, deleted, or safe to delete again.
func TestRecoveryDeleteResponseLoss(t *testing.T) {
	m, f, _ := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	m.backend = &recoveryLostDeleteStore{f}
	err := m.Delete(r.Service, r.Version, r.GroupID)
	var u *RecoveryOutcomeUnknown
	if !errors.As(err, &u) || u.Reference.GroupID != r.GroupID || u.Operation != "delete" || f.deletes != 1 || len(f.groups) != 0 {
		t.Fatal("delete uncertainty discarded")
	}
	c := ClassifyError(err)
	if c.Code != RecoveryOutcomeUnknownCode || !c.Failure || strings.Contains(c.Message, "synthetic") || strings.Contains(c.Hint, "rerun") {
		t.Fatal("unsafe unknown diagnostic")
	}
}

// An explicit backend no-effect guarantee preserves its definite refusal;
// no created record/reference, retry, or cleanup is produced.
func TestRecoveryKnownNoEffect(t *testing.T) {
	m, f, _ := recoveryTestManager(t)
	f.fail = true
	r, err := m.Create(recoveryTestRequest(), &recoveryFakeTerminal{}, false)
	recoveryCode(t, err, "store_refused")
	var unknown *RecoveryOutcomeUnknown
	if errors.As(err, &unknown) || r.GroupID != "" || len(f.groups) != 0 || f.stores != 0 || f.deletes != 0 {
		t.Fatal("known no-effect became unknown or wrote")
	}
	f.fail = false
	r = recoveryTestRestore(t, m)
	f.fail = true
	err = m.Delete(r.Service, r.Version, r.GroupID)
	recoveryCode(t, err, "delete_refused")
	if errors.As(err, &unknown) || f.deletes != 0 || len(f.groups) != 1 {
		t.Fatal("known refused delete changed state")
	}
}

// This opens the retained account ciphertext, rather than deriving a fresh
// account from the phrase. Its receive/change children must match fixtures
// regenerated with the independent, unmodified reference module.
func TestRecoveryRetainedNamecoinChildren(t *testing.T) {
	m, f, h := recoveryTestManager(t)
	r := recoveryTestRestore(t, m)
	c, err := parseRecoveryCiphertext(f.data[r.Account()], r)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := recoveryTestOpen(h.keys[1], c.Namecoin.Ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(plain)
	if len(plain) != 100 || string(plain[:4]) != "KVN1" {
		t.Fatal("invalid retained account plaintext")
	}
	var account recoveryNode
	defer account.clear()
	copy(account.key[:], plain[36:68])
	copy(account.chain[:], plain[68:])
	raw, err := os.ReadFile("testdata/recovery/reference-public.json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []struct {
		Phrase  string `json:"phrase"`
		Receive string `json:"receive_0_public"`
		Change  string `json:"change_0_public"`
	}
	if json.Unmarshal(raw, &rows) != nil {
		t.Fatal("reference fixture malformed")
	}
	found := false
	for _, v := range rows {
		if v.Phrase != recoveryFixturePhrase {
			continue
		}
		found = true
		for branch, want := range []string{v.Receive, v.Change} {
			child, err := account.path([]uint32{uint32(branch), 0})
			if err != nil {
				t.Fatal("retained account cannot derive child", err)
			}
			pub, err := child.public()
			child.clear()
			if err != nil || hex.EncodeToString(pub) != want {
				t.Fatal("retained account child disagrees with independent reference")
			}
		}
	}
	if !found {
		t.Fatal("independent fixture missing")
	}
}

type recoveryWithoutReservations struct{ NostrBackend }

// A paired Nostr projection without the full reservation provider cannot
// establish that another purpose is free; a legacy-only provider still works.
func TestRecoveryReservationProviderRequired(t *testing.T) {
	m, f, _ := recoveryTestManager(t)
	recoveryTestRestore(t, m)
	s := &recoveryNamespaceStore{recoveryFakeStore: f}
	n := NewNostrManager(recoveryWithoutReservations{NostrBackend: s}, m.lock)
	_, err := n.Generate("test", "other", 1)
	var r *Refusal
	if !errors.As(err, &r) || r.Code != "nostr_store_unavailable" || s.creates != 0 {
		t.Fatal("missing paired reservations allowed mutation")
	}
	s.groups = nil
	if _, err := n.Generate("test", "other", 1); err != nil || s.creates != 1 {
		t.Fatal("legacy-only provider refused", err)
	}
}

type recoveryDuplicateAddStore struct{ *recoveryFakeStore }

func (s *recoveryDuplicateAddStore) RecoveryStore(RecoveryRecord, []byte) error {
	return &RecoveryNotAppliedError{Err: recoveryRefuse("duplicate")}
}

// An atomic-add duplicate is definite even when discovered after preflight;
// the failed attempt yields no created reference, write, retry or cleanup.
func TestRecoveryAtomicAddDuplicateNoEffect(t *testing.T) {
	m, f, _ := recoveryTestManager(t)
	m.backend = &recoveryDuplicateAddStore{f}
	r, err := m.Create(recoveryTestRequest(), &recoveryFakeTerminal{}, false)
	recoveryCode(t, err, "duplicate")
	var u *RecoveryOutcomeUnknown
	if errors.As(err, &u) || r.GroupID != "" || f.stores != 0 || f.deletes != 0 || len(f.groups) != 0 {
		t.Fatal("definite duplicate became uncertain or changed state")
	}
}
