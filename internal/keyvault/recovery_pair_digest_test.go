package keyvault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// SHA-256 of the exact bytes of the frozen public v1 record file, computed with
// the system shasum and not by product code. That file is the canonical encoding
// of its own record, so it is also the digest `recovery pub` must print for it.
const recoveryV1FixtureDigest = "7b1e72bac729e8c1e8872ac2017e3f1ed236b5340010e183ca4475944fd2465c"

func recoveryDigestFixture(t *testing.T) ([]byte, RecoveryRecord) {
	t.Helper()
	raw, err := os.ReadFile("testdata/recovery/v1-public-record.json")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parseRecoveryRecord(raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, r
}

func recoveryDigestOf(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// Claim: the digest printed for the frozen public v1 record equals an
// independently computed literal (the file's own SHA-256), so a function that
// hashes some other encoding, a prefix, or hex of the wrong case fails. The
// literal is first checked against the file itself so a changed fixture cannot
// silently keep the test green. Limit: one frozen record; v2 is covered below.
func TestRecoveryPairDigestFixtureAnchor(t *testing.T) {
	raw, r := recoveryDigestFixture(t)
	if recoveryDigestOf(raw) != recoveryV1FixtureDigest {
		t.Fatal("fixture file changed; the literal pin no longer describes it")
	}
	got, err := r.PairMetadataSHA256()
	if err != nil || got != recoveryV1FixtureDigest {
		t.Fatalf("digest %q err %v, want the independent literal", got, err)
	}
	if len(got) != 64 || got != strings.ToLower(got) {
		t.Fatal("digest is not 64 lowercase hex")
	}
}

// Claim: for both retained schemas the value `recovery pub` prints for a pair
// that the manager described equals (a) the SHA-256 of the exact stored bytes,
// (b) what the attach's own binding computes, and (c) a pin the real attach
// preflight ACCEPTS and carries to the helper stage. The pair is served to the
// attach as bytes by the fake native; the printed side comes from the record the
// manager returns. Limit: fake store and fake native; no Keychain read.
func TestRecoveryPairDigestIsTheAttachPin(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			raw := bytes.Clone(x.fake.pair)
			stored, err := parseRecoveryRecord(raw)
			if err != nil {
				t.Fatal(err)
			}
			manager := NewRecoveryManager(&recoveryFakeStore{groups: []RecoveryRecord{stored}}, FileLock{Path: t.TempDir() + "/recovery.lock"})
			described, err := manager.Describe(stored.Service, stored.Version)
			if err != nil {
				t.Fatal(err)
			}
			printed, err := described.PairMetadataSHA256()
			if err != nil {
				t.Fatal(err)
			}
			if printed != recoveryDigestOf(raw) {
				t.Fatalf("printed digest %s is not the SHA-256 of the stored bytes", printed)
			}
			if rootGrantsPairBinding(raw, described).MetadataSHA256 != printed {
				t.Fatal("printed digest differs from the attach binding")
			}
			q := rootGrantsAttachRequestFor(t, schema)
			q.ExpectedPairMetadataSHA256 = printed
			recorder := &rootGrantsRunRecorder{result: RootGrantsAttachResult{Outcome: "stored", PairUnchanged: true}}
			if _, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run); err != nil || recorder.calls != 1 {
				t.Fatalf("the printed digest was not accepted as the attach pin: %v calls=%d", err, recorder.calls)
			}
		})
	}
}

// Claim: the digest depends on every part of the canonical metadata. Each
// single-field change that leaves the record valid yields a digest different
// from the original and from every other change, and a one-byte change in the
// stored bytes changes it to the independently computed SHA-256 of those bytes.
// The attach refuses the ORIGINAL printed digest for a pair whose stored bytes
// changed by one byte, before the helper stage, and accepts the digest of the
// changed bytes (the pin binds the exact record; a constant or partial hash fails).
// Limit: a sample of fields, not an exhaustive byte sweep.
func TestRecoveryPairDigestBindsTheExactMetadata(t *testing.T) {
	raw, base := recoveryDigestFixture(t)
	original, err := base.PairMetadataSHA256()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(*RecoveryRecord){
		"created":          func(r *RecoveryRecord) { r.Created = "2026-01-02T03:04:06Z" },
		"group-id":         func(r *RecoveryRecord) { r.GroupID = strings.Repeat("1", 32) },
		"version":          func(r *RecoveryRecord) { r.Version = 2 },
		"service":          func(r *RecoveryRecord) { r.Service = "other" },
		"nostr-version":    func(r *RecoveryRecord) { r.Nostr.Version = 3 },
		"namecoin-version": func(r *RecoveryRecord) { r.Namecoin.Version = 2 },
	}
	seen := map[string]string{original: "original"}
	for name, mutate := range mutations {
		m := base
		mutate(&m)
		mraw, err := json.Marshal(m)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseRecoveryRecord(mraw); err != nil {
			t.Fatalf("%s: the mutation is not a valid record, so it proves nothing: %v", name, err)
		}
		digest, err := m.PairMetadataSHA256()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if digest != recoveryDigestOf(mraw) {
			t.Fatalf("%s: digest is not the SHA-256 of the record bytes", name)
		}
		if other, dup := seen[digest]; dup {
			t.Fatalf("%s: digest equals the one of %s", name, other)
		}
		seen[digest] = name
	}
	flipped := bytes.Replace(raw, []byte("03:04:05Z"), []byte("03:04:06Z"), 1)
	if bytes.Equal(flipped, raw) {
		t.Fatal("fixture lost its created time; the one-byte change did not apply")
	}
	flippedRecord, err := parseRecoveryRecord(flipped)
	if err != nil {
		t.Fatal(err)
	}
	if digest, err := flippedRecord.PairMetadataSHA256(); err != nil || digest == original || digest != recoveryDigestOf(flipped) {
		t.Fatalf("a one-byte change did not move the digest to the independent value: %v", err)
	}
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			stored, err := parseRecoveryRecord(x.fake.pair)
			if err != nil {
				t.Fatal(err)
			}
			printed, _ := stored.PairMetadataSHA256()
			changed := stored
			changed.Created = "2026-01-02T03:04:06Z"
			changedRaw, err := json.Marshal(changed)
			if err != nil {
				t.Fatal(err)
			}
			changedDigest, _ := changed.PairMetadataSHA256()
			x.fake.pair = changedRaw
			q := rootGrantsAttachRequestFor(t, schema)
			q.ExpectedPairMetadataSHA256 = printed
			recorder := &rootGrantsRunRecorder{result: RootGrantsAttachResult{Outcome: "stored", PairUnchanged: true}}
			_, err = attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run)
			failure, ok := RootGrantsAttachFailureOf(err)
			if !ok || failure.Code != "retained_record_mismatch" || recorder.calls != 0 {
				t.Fatalf("the stale digest was not refused before the helper: %v calls=%d", err, recorder.calls)
			}
			q.ExpectedPairMetadataSHA256 = changedDigest
			if _, err := attachRootGrantsPinned(context.Background(), x.vault, q, rootGrantsFixedNow, recorder.run); err != nil || recorder.calls != 1 {
				t.Fatalf("the digest of the changed bytes was refused: %v calls=%d", err, recorder.calls)
			}
		})
	}
}

// Claim: no digest is produced for a record the store or the attach would not
// accept, and the refusal is the closed invalid_record code. The valid control
// first shows that a function that refuses everything fails this test.
// Limit: representative invalid fields, one at a time.
func TestRecoveryPairDigestRefusesInvalidRecords(t *testing.T) {
	_, valid := recoveryDigestFixture(t)
	if digest, err := valid.PairMetadataSHA256(); err != nil || digest == "" {
		t.Fatal("positive control failed")
	}
	cases := map[string]RecoveryRecord{"zero": {}}
	for name, mutate := range map[string]func(*RecoveryRecord){
		"schema":            func(r *RecoveryRecord) { r.Schema = "keyvault-recovery/3" },
		"short-group-id":    func(r *RecoveryRecord) { r.GroupID = "00" },
		"upper-group-id":    func(r *RecoveryRecord) { r.GroupID = strings.Repeat("A", 32) },
		"created-form":      func(r *RecoveryRecord) { r.Created = "2026-01-02T03:04:05+00:00" },
		"nostr-presence":    func(r *RecoveryRecord) { r.Nostr.Presence = "biometry-any" },
		"namecoin-origin":   func(r *RecoveryRecord) { r.Namecoin.Origin = "[00000000/84h/7h/1h]" },
		"shared-wrapping":   func(r *RecoveryRecord) { r.Namecoin.WrappingPoint = r.Nostr.WrappingPoint },
		"empty-namecoin-xp": func(r *RecoveryRecord) { r.Namecoin.XPub = "" },
	} {
		m := valid
		mutate(&m)
		cases[name] = m
	}
	for name, r := range cases {
		digest, err := r.PairMetadataSHA256()
		var refusal *Refusal
		if digest != "" || !errors.As(err, &refusal) || refusal.Code != "recovery_invalid_record" {
			t.Fatalf("%s: digest %q err %v; want no digest and recovery_invalid_record", name, digest, err)
		}
	}
}

// Claim: describing a missing pair yields no record and therefore no digest, and
// an ambiguous pair (two records for one address) is refused the same way. The
// single-record control describes and digests normally. Limit: fake store.
func TestRecoveryDescribeMissingOrAmbiguousPairHasNoDigest(t *testing.T) {
	_, r := recoveryDigestFixture(t)
	newManager := func(groups ...RecoveryRecord) *RecoveryManager {
		return NewRecoveryManager(&recoveryFakeStore{groups: groups}, FileLock{Path: t.TempDir() + "/recovery.lock"})
	}
	if described, err := newManager(r).Describe(r.Service, r.Version); err != nil {
		t.Fatal(err)
	} else if digest, err := described.PairMetadataSHA256(); err != nil || digest != recoveryV1FixtureDigest {
		t.Fatal("positive control failed")
	}
	for name, m := range map[string]*RecoveryManager{"missing": newManager(), "ambiguous": newManager(r, r)} {
		described, err := m.Describe(r.Service, r.Version)
		if err == nil {
			t.Fatalf("%s: describe succeeded", name)
		}
		if digest, derr := described.PairMetadataSHA256(); digest != "" || derr == nil {
			t.Fatalf("%s: a digest exists for a pair that was not described", name)
		}
	}
	if _, err := newManager().Describe(r.Service, r.Version); !errors.Is(err, ErrNotFound) {
		t.Fatal("a missing pair is not ErrNotFound")
	}
}

// recoveryDigestUse reports, for one function (key "name" or "Type.name") of a
// source text, whether its body calls the shared digest function and whether it
// hashes with sha256 itself.
func recoveryDigestUse(src, key string) (found, shared, direct bool, err error) {
	f, err := parser.ParseFile(token.NewFileSet(), "source.go", src, 0)
	if err != nil {
		return false, false, false, err
	}
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		name := fd.Name.Name
		if fd.Recv != nil && len(fd.Recv.List) == 1 {
			if id, ok := fd.Recv.List[0].Type.(*ast.Ident); ok {
				name = id.Name + "." + name
			}
		}
		if name != key {
			continue
		}
		found = true
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			switch fn := call.Fun.(type) {
			case *ast.Ident:
				if fn.Name == "recoveryMetadataSHA256" {
					shared = true
				}
			case *ast.SelectorExpr:
				if x, ok := fn.X.(*ast.Ident); ok && x.Name == "sha256" {
					direct = true
				}
			}
			return true
		})
	}
	return found, shared, direct, nil
}

// Claim: the attach binding and the printed digest both go through the single
// function recoveryMetadataSHA256 and neither hashes on its own, so the two
// cannot drift into separate definitions; that function alone hashes. The
// detector is first shown to flag a direct hash, a missing call and a missing
// function (control plants), so a pass is not vacuous. Limit: source shape only;
// the behavioural equality is TestRecoveryPairDigestIsTheAttachPin.
func TestRecoveryPairDigestHasOneDefinition(t *testing.T) {
	const plantDirect = "package p\nfunc rootGrantsPairBinding(raw []byte) string { h := sha256.Sum256(raw); return string(h[:]) }\n"
	const plantShared = "package p\nfunc rootGrantsPairBinding(raw []byte) string { return recoveryMetadataSHA256(raw) }\n"
	if found, shared, direct, err := recoveryDigestUse(plantDirect, "rootGrantsPairBinding"); err != nil || !found || shared || !direct {
		t.Fatal("detector missed a direct hash")
	}
	if found, shared, direct, err := recoveryDigestUse(plantShared, "rootGrantsPairBinding"); err != nil || !found || !shared || direct {
		t.Fatal("detector rejected the shared call")
	}
	if found, _, _, err := recoveryDigestUse(plantShared, "PairMetadataSHA256"); err != nil || found {
		t.Fatal("detector found a function that is not there")
	}
	read := func(name string) string {
		raw, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		return string(raw)
	}
	binding, record := read("recovery_root_grants.go"), read("recovery_record.go")
	for _, c := range []struct{ src, key string }{{binding, "rootGrantsPairBinding"}, {record, "RecoveryRecord.PairMetadataSHA256"}} {
		if found, shared, direct, err := recoveryDigestUse(c.src, c.key); err != nil || !found || !shared || direct {
			t.Fatalf("%s must call recoveryMetadataSHA256 and not hash itself", c.key)
		}
	}
	if found, shared, direct, err := recoveryDigestUse(record, "recoveryMetadataSHA256"); err != nil || !found || shared || !direct {
		t.Fatal("recoveryMetadataSHA256 must be the one place that hashes")
	}
}
