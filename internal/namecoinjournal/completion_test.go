package namecoinjournal

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"testing"
)

// A receipt's immutable D reference plus the exact later S permits recovery
// after legitimate later head advancement. This uses the public fixture account;
// it proves history/account checks, not actual Keychain or filesystem ordering.
func TestCompletedDispatchReferenceAndLaterAdvance(t *testing.T) {
	a := fixtureAnchor(t)
	id := AttemptID{1}
	commitment := sha256.Sum256([]byte("public descriptor"))
	result := []byte("exact public result\n")
	l, err := a.RestoreLedger(nil)
	if err != nil {
		t.Fatal(err)
	}
	tr, err := l.DispatchBound(id, []Outpoint{fixtureInput()}, commitment)
	if err != nil {
		t.Fatal(err)
	}
	var records [][]byte
	l = addTransition(t, a, &records, tr)
	dseq, dhead, err := a.Head()
	if err != nil {
		t.Fatal(err)
	}
	// A result without completed S is never promoted, even though D is authentic.
	if err = a.VerifyCompleted(id, commitment, result, dseq, dhead, records); !errors.Is(err, ErrUnknown) {
		t.Fatal("result-only promoted", err)
	}
	tr, err = l.Complete(id, result)
	if err != nil {
		t.Fatal(err)
	}
	l = addTransition(t, a, &records, tr)
	if err = a.VerifyCompleted(id, commitment, result, dseq, dhead, records); err != nil {
		t.Fatal(err)
	}
	second := AttemptID{2}
	tr, err = l.DispatchBound(second, []Outpoint{{Transaction: [32]byte{8}, Index: 2}}, [32]byte{9})
	if err != nil {
		t.Fatal(err)
	}
	l = addTransition(t, a, &records, tr)
	tr, err = l.Complete(second, []byte("later complete result"))
	if err != nil {
		t.Fatal(err)
	}
	_ = addTransition(t, a, &records, tr)
	if err = a.VerifyCompleted(id, commitment, result, dseq, dhead, records); err != nil {
		t.Fatal("legitimate advanced anchor refused", err)
	}
	sequence, currentHead, err := a.Head()
	if err != nil || sequence != 4 || currentHead == dhead {
		t.Fatal("advance control", err)
	}
	wrongHead := dhead
	wrongHead[0] ^= 1
	wrongCommitment := commitment
	wrongCommitment[0] ^= 1
	for _, check := range []struct {
		name       string
		id         AttemptID
		commitment [32]byte
		result     []byte
		sequence   uint64
		head       [32]byte
	}{
		{"wrong-head", id, commitment, result, dseq, wrongHead},
		{"current-head-is-not-D", id, commitment, result, dseq, currentHead},
		{"wrong-sequence", id, commitment, result, 2, dhead},
		{"zero-sequence", id, commitment, result, 0, dhead},
		{"overflow-sequence", id, commitment, result, ^uint64(0), dhead},
		{"wrong-attempt", second, commitment, result, dseq, dhead},
		{"wrong-descriptor", id, wrongCommitment, result, dseq, dhead},
		{"wrong-result", id, commitment, append(bytes.Clone(result), ' '), dseq, dhead},
	} {
		t.Run(check.name, func(t *testing.T) {
			if err := a.VerifyCompleted(check.id, check.commitment, check.result, check.sequence, check.head, records); !errors.Is(err, ErrUnknown) {
				t.Fatal("wrong completion admitted", err)
			}
		})
	}
	protected, err := a.EncodeProtected()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(protected)
	loaded, err := DecodeProtected(protected, fixtureBinding())
	if err != nil {
		t.Fatal(err)
	}
	defer loaded.Clear()
	if err = loaded.VerifyCompleted(id, commitment, result, dseq, dhead, records); !errors.Is(err, ErrUnknown) {
		t.Fatal("unrederived authority admitted", err)
	}
	if err = loaded.VerifyAccount(fixtureMaterial()); err != nil {
		t.Fatal(err)
	}
	if err = loaded.VerifyCompleted(id, commitment, result, dseq, dhead, records); err != nil {
		t.Fatal("fresh account correspondence", err)
	}
	for i := range records {
		changed := make([][]byte, len(records))
		for j := range records {
			changed[j] = bytes.Clone(records[j])
		}
		changed[i][len(changed[i])-1] ^= 1
		if err = loaded.VerifyCompleted(id, commitment, result, dseq, dhead, changed); !errors.Is(err, ErrUnknown) {
			t.Fatal("altered checked history", i, err)
		}
	}
}

// Even individually valid typed histories cannot authenticate a receipt using
// an unrelated D, a nonadjacent S, UNKNOWN, or an S committing different bytes.
func TestCompletedRefusesWrongLifecycleAndSubstitutedAuthority(t *testing.T) {
	for _, kind := range []string{"different-result", "unknown", "intervening-dispatch", "legacy-unbound", "substituted-key"} {
		t.Run(kind, func(t *testing.T) {
			a := fixtureAnchor(t)
			id := AttemptID{1}
			commitment := [32]byte{3}
			result := []byte("public result")
			var records [][]byte
			l, err := a.RestoreLedger(nil)
			if err != nil {
				t.Fatal(err)
			}
			var tr Transition
			if kind == "legacy-unbound" {
				tr, err = l.Dispatch(id, []Outpoint{fixtureInput()})
			} else {
				tr, err = l.DispatchBound(id, []Outpoint{fixtureInput()}, commitment)
			}
			if err != nil {
				t.Fatal(err)
			}
			l = addTransition(t, a, &records, tr)
			dseq, dhead, err := a.Head()
			if err != nil {
				t.Fatal(err)
			}
			if kind == "intervening-dispatch" {
				tr, err = l.DispatchBound(AttemptID{2}, []Outpoint{{Transaction: [32]byte{9}}}, [32]byte{4})
				if err != nil {
					t.Fatal(err)
				}
				l = addTransition(t, a, &records, tr)
			}
			if kind == "unknown" {
				tr, err = l.MarkUnknown(id)
			} else if kind == "different-result" {
				tr, err = l.Complete(id, []byte("other public result"))
			} else {
				tr, err = l.Complete(id, result)
			}
			if err != nil {
				t.Fatal(err)
			}
			_ = addTransition(t, a, &records, tr)
			if kind == "substituted-key" {
				// A self-consistent attacker-created protected blob is not enough:
				// genuine account rederivation must refuse its substituted key.
				a.key[0] ^= 1
				a.token = headToken(a.key, a.binding, a.sequence, a.head)
				blob, e := a.EncodeProtected()
				if e != nil {
					t.Fatal(e)
				}
				defer clear(blob)
				fake, e := DecodeProtected(blob, fixtureBinding())
				if e != nil {
					t.Fatal("self-consistency control", e)
				}
				defer fake.Clear()
				if e = fake.VerifyAccount(fixtureMaterial()); !errors.Is(e, ErrUnknown) {
					t.Fatal("substituted integrity authority", e)
				}
				a = fake
			}
			if err = a.VerifyCompleted(id, commitment, result, dseq, dhead, records); !errors.Is(err, ErrUnknown) {
				t.Fatal("invalid lifecycle passed", kind, err)
			}
		})
	}
}
