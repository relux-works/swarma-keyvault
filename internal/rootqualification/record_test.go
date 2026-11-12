package rootqualification

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

const literalProjectionSHA = "97d488352956a987d918f37f53be37b3968b71afd88d68c34f2a3bfa5334c274"

func candidateFixture() Candidate {
	return Candidate{SourceHead: strings.Repeat("a", 40), SourceTree: strings.Repeat("b", 40), Vault: Artifact{strings.Repeat("1", 64), strings.Repeat("1", 40)}, Helper: Artifact{strings.Repeat("2", 64), strings.Repeat("2", 40)}, Foreign: Artifact{strings.Repeat("3", 64), strings.Repeat("3", 40)}}
}
func nativeCreationFixture() NativeCreation {
	p := Projection{OwnerUID: 501, OwnerGID: 20, ACLs: []ACLProjection{}}
	return NativeCreation{Outcome: CreationReadback, Reference: []byte{1, 2, 3}, Before: &p, After: &p, BeforeSHA256: literalProjectionSHA, AfterSHA256: literalProjectionSHA}
}
func recordFixture(t *testing.T) creationRecord {
	t.Helper()
	r, err := recordFromNative(time.Date(2026, 11, 12, 1, 2, 3, 0, time.UTC), candidateFixture(), strings.Repeat("4", 32), PendingIdentity{DirectoryDevice: 1, DirectoryInode: 2, Device: 1, Inode: 3, UID: 501, GID: 20, SHA256: strings.Repeat("f", 64)}, nativeCreationFixture(), FileIdentity{Device: 1, Inode: 4, UID: 501, GID: 20})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// The complete canonical record has all fixed bindings, explicit native
// observations and the independently fixed KVQP1 hash. Opaque evidence is
// recorded without classifying it as a safe root ACL.
func TestCompletedReceiptCanonicalRecord(t *testing.T) {
	r := recordFixture(t)
	raw, err := canonicalRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"marker_sha256":"6cf7638c107e685379c0580c849425f0f9eafa5f78f52f42c787a9113256f38e"`)) || !bytes.Contains(raw, []byte(`"persistent_reference":"AQID"`)) || !bytes.HasSuffix(raw, []byte("}\n")) {
		t.Fatal("fixed record bindings changed")
	}
	got, err := decodeRecord(raw)
	if err != nil || got.State != "created" || got.Candidate != candidateFixture() || got.Pending != r.Pending || got.ReservationID != r.ReservationID || got.AfterSHA256 != literalProjectionSHA {
		t.Fatal("complete record lost binding")
	}
	request, err := requestFromRecord(got, strings.Repeat("c", 64))
	if err != nil {
		t.Fatal(err)
	}
	defer request.Clear()
	if !bytes.Equal(request.Reference(), []byte{1, 2, 3}) {
		t.Fatal("actual recorded reference lost")
	}
	for _, state := range []CreationOutcome{CreationRefused, CreationUnknown} {
		n := NativeCreation{Outcome: state}
		refused, err := recordFromNative(time.Now(), candidateFixture(), r.ReservationID, r.Pending, n, r.CreatedIdentity)
		if err != nil {
			t.Fatal(err)
		}
		b, err := canonicalRecord(refused)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := decodeRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := requestFromRecord(parsed, strings.Repeat("c", 64)); !errors.Is(err, ErrReceipt) {
			t.Fatal("non-created audit admitted item request")
		}
	}
}

// Each malformed/partial binding fails the intended receipt refusal beside a
// valid complete control. Unknown/duplicate/missing/noncanonical JSON cannot
// borrow a digest or yield a public item request.
func TestCompletedReceiptRefusesPartialAndNoncanonical(t *testing.T) {
	for name, change := range map[string]func(*creationRecord){
		"schema":              func(r *creationRecord) { r.Schema = "other" },
		"namespace":           func(r *creationRecord) { r.Namespace = "other" },
		"account":             func(r *creationRecord) { r.Account = "other" },
		"class":               func(r *creationRecord) { r.ItemClass = "key" },
		"marker":              func(r *creationRecord) { r.MarkerSHA256 = strings.Repeat("0", 64) },
		"timezone":            func(r *creationRecord) { r.UTC = "2026-11-12T01:02:03+00:00" },
		"missing-reference":   func(r *creationRecord) { r.PersistentReference = "" },
		"wrong-pad-bits":      func(r *creationRecord) { r.PersistentReference = "AR==" },
		"base64-newline":      func(r *creationRecord) { r.PersistentReference = "AQID\n" },
		"missing-before":      func(r *creationRecord) { r.Before = nil },
		"missing-after":       func(r *creationRecord) { r.After = nil },
		"projection-hash":     func(r *creationRecord) { r.AfterSHA256 = strings.Repeat("a", 64) },
		"projection-fields":   func(r *creationRecord) { p := *r.After; p.OwnerUID++; r.After = &p },
		"null-acls":           func(r *creationRecord) { p := *r.After; p.ACLs = nil; r.After = &p },
		"pending-inode":       func(r *creationRecord) { r.Pending.Inode = 0 },
		"pending-hash":        func(r *creationRecord) { r.Pending.SHA256 = "" },
		"reservation":         func(r *creationRecord) { r.ReservationID = strings.Repeat("A", 32) },
		"source":              func(r *creationRecord) { r.Candidate.SourceHead = "unknown" },
		"colliding-artifacts": func(r *creationRecord) { r.Candidate.Foreign = r.Candidate.Vault },
		"state":               func(r *creationRecord) { r.State = "pending" },
		"refused-with-ref":    func(r *creationRecord) { r.State = "refused" },
	} {
		t.Run(name, func(t *testing.T) {
			r := recordFixture(t)
			change(&r)
			if b, err := canonicalRecord(r); !errors.Is(err, ErrReceipt) || b != nil {
				t.Fatal("malformed record encoded")
			}
		})
	}
	raw, err := canonicalRecord(recordFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range [][]byte{
		append([]byte(" "), raw...), raw[:len(raw)-1], append(bytes.Clone(raw), '\n'),
		bytes.Replace(raw, []byte(`"state":"created"`), []byte(`"state":"created","extra":1`), 1),
		bytes.Replace(raw, []byte(`"state":"created"`), []byte(`"state":"created","state":"created"`), 1),
		bytes.Replace(raw, []byte(`"state":"created",`), nil, 1),
		bytes.Replace(raw, []byte(`"persistent_reference":"AQID"`), []byte(`"persistent_reference":"AQID\r\n"`), 1),
	} {
		if _, err := decodeRecord(bad); !errors.Is(err, ErrReceipt) {
			t.Fatal("noncanonical record decoded")
		}
	}
	if _, err := decodeRecord(make([]byte, 1048577)); !errors.Is(err, ErrReceipt) {
		t.Fatal("oversize record decoded")
	}
}
