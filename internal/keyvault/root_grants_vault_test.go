package keyvault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
	"golang.org/x/sys/unix"
)

// SYNTHETIC ACL forms. These are public test frames built with the KVQP1 encoder,
// not observed native frames: they exercise where the adapter applies the policy,
// never what the real owner/writer allowlist contains.
func rootGrantsSyntheticProjection() rootqualification.Projection {
	return rootqualification.Projection{OwnerUID: 501, OwnerGID: 20, OwnerType: 2, ACLs: []rootqualification.ACLProjection{{
		AuthorizationNamesState: "readable", Authorizations: []string{"synthetic-release"}, AuthorizationNumbers: []uint32{7},
		ContentsState: "readable", DescriptionState: "present", Description: "synthetic-access",
		RawPromptState: "readable", RawPromptVersion: 1, ApplicationsState: "present",
		Applications: []rootqualification.ApplicationProjection{{RequirementState: "present", Requirement: []byte{0xfa, 0xde, 0x0c, 0x00}, RequirementText: "synthetic requirement"}},
	}}}
}

func rootGrantsSyntheticFrame(t *testing.T, mutate func(*rootqualification.Projection)) []byte {
	t.Helper()
	p := rootGrantsSyntheticProjection()
	if mutate != nil {
		mutate(&p)
	}
	frame, err := rootqualification.EncodeNativeProjection(p)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

// Forbidden variants: each is a well-formed KVQP1 frame that differs from the
// admitted synthetic one in exactly one security-relevant way.
var rootGrantsSyntheticVariants = []struct {
	name   string
	mutate func(*rootqualification.Projection)
}{
	{"extra-acl", func(p *rootqualification.Projection) { p.ACLs = append(p.ACLs, p.ACLs[0]) }},
	{"extra-application", func(p *rootqualification.Projection) {
		a := &p.ACLs[0]
		a.Applications = append(a.Applications, a.Applications[0])
	}},
	{"null-application-list", func(p *rootqualification.Projection) {
		a := &p.ACLs[0]
		a.ApplicationsState, a.Applications = "null", []rootqualification.ApplicationProjection{}
	}},
	{"empty-application-list", func(p *rootqualification.Projection) {
		p.ACLs[0].Applications = []rootqualification.ApplicationProjection{}
	}},
	{"wrong-requirement", func(p *rootqualification.Projection) {
		p.ACLs[0].Applications[0].Requirement = []byte{0xfa, 0xde, 0x0c, 0x01}
	}},
	{"wrong-owner", func(p *rootqualification.Projection) { p.OwnerUID = 0 }},
	{"unknown-authorization", func(p *rootqualification.Projection) {
		p.ACLs[0].AuthorizationNumbers = append(p.ACLs[0].AuthorizationNumbers, 0xfffffff0)
	}},
}

// rootGrantsExactFramePolicy admits exactly one synthetic frame. It is a stand-in
// predicate for the adapter tests only: an adapter that skipped the policy, or
// applied it to another object, would not be caught by the policy's content.
type rootGrantsExactFramePolicy struct {
	t        *testing.T
	admitted []byte
	calls    *[][]byte
}

var errRootGrantsSyntheticRefusal = errors.New("synthetic policy refusal")

func (p rootGrantsExactFramePolicy) Admit(projection rootqualification.Projection) error {
	frame, err := rootqualification.EncodeNativeProjection(projection)
	if err != nil {
		p.t.Fatal(err)
	}
	if p.calls != nil {
		*p.calls = append(*p.calls, frame)
	}
	if !bytes.Equal(frame, p.admitted) {
		return errRootGrantsSyntheticRefusal
	}
	return nil
}

type rootGrantsStoredFake struct {
	account, metadata string
	envelope          []byte
}

// rootGrantsNativeFake is a recording native seam. It has no operation that
// could read an item value; its call log is the evidence for ordering claims.
type rootGrantsNativeFake struct {
	t               *testing.T
	calls           []string
	pair            []byte
	pairAccount     string
	pairCalls       int
	pairChangeAt    int
	pairRowsErr     error
	rootRows        []byte
	rootRowsErr     error
	startupErr      error
	prepareErr      error
	prepareNil      bool
	frame           []byte
	commitAttempted bool
	commitStatus    int
	prepares        int
	added           int
	commits         int
	closes          int
	stored          *rootGrantsStoredFake
	readbackMeta    []byte
	readbackFrame   []byte
	readbackErr     error
}

func rootGrantsRowBytes(rows ...[2]string) []byte {
	var out []byte
	for _, r := range rows {
		out = append(out, r[0]...)
		out = append(out, 0x1f)
		out = append(out, r[1]...)
		out = append(out, 0x1e)
	}
	return out
}

func (f *rootGrantsNativeFake) Startup() error {
	f.calls = append(f.calls, "startup")
	return f.startupErr
}

func (f *rootGrantsNativeFake) PairRows() ([]byte, error) {
	f.calls = append(f.calls, "pair-rows")
	f.pairCalls++
	if f.pairRowsErr != nil {
		return nil, f.pairRowsErr
	}
	pair := f.pair
	if f.pairCalls == f.pairChangeAt {
		pair = bytes.Replace(pair, []byte("2026-01-02"), []byte("2026-01-03"), 1)
	}
	return rootGrantsRowBytes([2]string{f.pairAccount, string(pair)}), nil
}

func (f *rootGrantsNativeFake) RootRows() ([]byte, error) {
	f.calls = append(f.calls, "root-rows")
	if f.rootRowsErr != nil {
		return nil, f.rootRowsErr
	}
	if f.stored != nil {
		return rootGrantsRowBytes([2]string{f.stored.account, f.stored.metadata}), nil
	}
	return bytes.Clone(f.rootRows), nil
}

type rootGrantsAddFake struct{ f *rootGrantsNativeFake }

func (f *rootGrantsNativeFake) PrepareAdd() (rootGrantsNativeAdd, error) {
	f.calls = append(f.calls, "prepare")
	f.prepares++
	if f.prepareErr != nil {
		return nil, f.prepareErr
	}
	if f.prepareNil {
		return nil, nil
	}
	f.added++
	return &rootGrantsAddFake{f: f}, nil
}

func (a *rootGrantsAddFake) ACLFrame() []byte { return bytes.Clone(a.f.frame) }

func (a *rootGrantsAddFake) Commit(account, metadata string, envelope []byte) (bool, int) {
	a.f.calls = append(a.f.calls, "commit")
	a.f.commits++
	if a.f.commitAttempted && a.f.commitStatus == 0 {
		a.f.stored = &rootGrantsStoredFake{account: account, metadata: metadata, envelope: bytes.Clone(envelope)}
	}
	return a.f.commitAttempted, a.f.commitStatus
}

func (a *rootGrantsAddFake) Close() {
	a.f.calls = append(a.f.calls, "close")
	a.f.closes++
}

func (f *rootGrantsNativeFake) Readback(account string) ([]byte, []byte, error) {
	f.calls = append(f.calls, "readback")
	if f.readbackErr != nil {
		return nil, nil, f.readbackErr
	}
	if f.stored == nil || f.stored.account != account {
		return nil, nil, errors.New("no such item")
	}
	meta := []byte(f.stored.metadata)
	if f.readbackMeta != nil {
		meta = f.readbackMeta
	}
	frame := f.readbackFrame
	if frame == nil {
		frame = f.frame
	}
	return bytes.Clone(meta), bytes.Clone(frame), nil
}

type rootGrantsVaultFixture struct {
	plan  *rootGrantsAttachment
	vault *rootGrantsProductionVault
	fake  *rootGrantsNativeFake
	lock  FileLock
	item  rootGrantsSealedItem
	frame []byte
	calls *[][]byte
}

func newRootGrantsVaultFixture(t *testing.T, schema string) *rootGrantsVaultFixture {
	t.Helper()
	request, sealed, item, _ := rootGrantsSealedFixture46(t, schema)
	var q rootGrantsPrivateRequest
	if json.Unmarshal(request, &q) != nil {
		t.Fatal("fixture request")
	}
	plan, err := rootGrantsSyntheticResult46(request, sealed).plan()
	if err != nil {
		t.Fatal(err)
	}
	pairRecord, err := parseRecoveryRecord(q.PairMetadata)
	if err != nil {
		t.Fatal(err)
	}
	frame := rootGrantsSyntheticFrame(t, nil)
	fake := &rootGrantsNativeFake{t: t, pair: bytes.Clone(q.PairMetadata), pairAccount: pairRecord.Account(), frame: frame, commitAttempted: true}
	lock := rootGrantsLockFixture45(t)
	var calls [][]byte
	vault := &rootGrantsProductionVault{
		lockSource: func() (FileLock, error) { return lock, nil },
		native:     fake,
		policy:     rootGrantsExactFramePolicy{t: t, admitted: frame, calls: &calls},
	}
	return &rootGrantsVaultFixture{plan: plan, vault: vault, fake: fake, lock: lock, item: item, frame: frame, calls: &calls}
}

func (x *rootGrantsVaultFixture) lockedVault(t *testing.T) rootGrantsLockedVault {
	t.Helper()
	locked, err := x.vault.LockExistingRootGrants(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(locked.Release)
	return locked
}

func rootGrantsLockHeld(t *testing.T, lock FileLock) bool {
	t.Helper()
	probe, err := os.Open(lock.Path)
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB) != nil {
		return true
	}
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_UN); err != nil {
		t.Fatal(err)
	}
	return false
}

var (
	_ rootGrantsAttachVault = (*rootGrantsProductionVault)(nil)
	_ rootGrantsLockedVault = (*rootGrantsProductionLocked)(nil)
)

// Claim: the native seam and the prepared add can express only the permitted
// operations: two attribute inventories, one exact metadata/ACL readback, one
// two-phase create-only add. Neither names a value read, update or delete.
// Limit: an interface list; the C source guard below covers the cgo side.
func TestRootGrantsVaultSeamSurface(t *testing.T) {
	for _, tc := range []struct {
		typ  reflect.Type
		want []string
	}{
		{reflect.TypeOf((*rootGrantsNative)(nil)).Elem(), []string{"PairRows", "PrepareAdd", "Readback", "RootRows", "Startup"}},
		{reflect.TypeOf((*rootGrantsNativeAdd)(nil)).Elem(), []string{"ACLFrame", "Close", "Commit"}},
	} {
		if tc.typ.NumMethod() != len(tc.want) {
			t.Fatalf("%s widened", tc.typ.Name())
		}
		for i, name := range tc.want {
			if tc.typ.Method(i).Name != name {
				t.Fatalf("%s gained an unadmitted operation %s", tc.typ.Name(), tc.typ.Method(i).Name)
			}
		}
	}
}

// Claim: a legitimate v1/v2 attach through the production adapter holds the
// existing guard, reads public pair metadata, inventories the root namespace,
// re-reads the pair, starts native only then, admits the intended object, adds
// exactly once with the admitted object, reads metadata/ACL back and re-reads
// the pair, in that order, with no value read. The stored packet is byte-exact and
// the guard is released. Limit: fake native, synthetic ACL forms, no OS policy.
func TestRootGrantsVaultAttachStoresThroughAdmittedACL(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			oldPair := bytes.Clone(x.fake.pair)
			result, err := x.plan.commit(context.Background(), x.vault)
			if err != nil || result.Outcome != "stored" || !result.PairUnchanged {
				t.Fatalf("legitimate attach refused: %v", err)
			}
			want := []string{"pair-rows", "root-rows", "pair-rows", "startup", "prepare", "commit", "close", "readback", "pair-rows"}
			if !reflect.DeepEqual(x.fake.calls, want) {
				t.Fatalf("native order: %v", x.fake.calls)
			}
			if x.fake.stored == nil || x.fake.stored.metadata != x.item.metadata || string(x.fake.stored.envelope) != x.item.envelope ||
				x.fake.stored.account != "example-root/root-grants@1" || !bytes.Equal(x.fake.pair, oldPair) {
				t.Fatal("stored packet is not the exact sealed item or the pair changed")
			}
			// The policy saw the intended object before the add and the actual one after.
			if len(*x.calls) != 2 || !bytes.Equal((*x.calls)[0], x.frame) || !bytes.Equal((*x.calls)[1], x.frame) {
				t.Fatal("policy was not applied to both the intended and the actual ACL")
			}
			if rootGrantsLockHeld(t, x.lock) {
				t.Fatal("guard leaked after the attach")
			}
		})
	}
}

// Claim: every refusal before the add is a definite no-effect result with its
// closed reason: no commit call, the prepared add closed exactly once, nothing
// stored. The forbidden synthetic frames are valid KVQP1 frames refused by the
// policy, while the admitted frame (positive control above) is accepted, so
// rejecting everything cannot satisfy both. Limit: reasons are mapped by the
// adapter; whether the real native code produces them is a native lane.
func TestRootGrantsVaultPreAddRefusalsAreDefinite(t *testing.T) {
	type tc struct {
		name, code string
		configure  func(*testing.T, *rootGrantsVaultFixture)
	}
	var cases = []tc{
		{"running-code-refused", "code_not_admitted", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.startupErr = errRootGrantsNativeCode }},
		{"prepare-code-refused", "code_not_admitted", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.prepareErr = errRootGrantsNativeCode }},
		{"prepare-acl-refused", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.prepareErr = errRootGrantsNativeACL }},
		{"prepare-other-failure", "operation_unavailable", func(t *testing.T, x *rootGrantsVaultFixture) {
			x.fake.prepareErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
		}},
		{"prepare-returned-nothing", "operation_unavailable", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.prepareNil = true }},
		{"undecodable-frame", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.frame = []byte("not a KVQP1 frame") }},
		{"empty-frame", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.frame = nil }},
		{"production-default-policy", "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.vault.policy = productionRootGrantsACLPolicy() }},
		{"before-native-failure", "operation_unavailable", func(t *testing.T, x *rootGrantsVaultFixture) {
			x.fake.commitAttempted, x.fake.commitStatus = false, -25308
		}},
	}
	for _, v := range rootGrantsSyntheticVariants {
		v := v
		cases = append(cases, tc{"policy-refuses-" + v.name, "acl_refused", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.frame = rootGrantsSyntheticFrame(t, v.mutate) }})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			c.configure(t, x)
			result, err := x.plan.commit(context.Background(), x.vault)
			rootGrantsAttachFailure13(t, result, err, c.code, "commit", "not_applied")
			if x.fake.stored != nil || x.fake.closes != x.fake.added || x.fake.prepares > 1 {
				t.Fatal("pre-add refusal stored an item or leaked the prepared add")
			}
			if c.name != "before-native-failure" && x.fake.commits != 0 {
				t.Fatal("pre-add refusal reached the add")
			}
			for _, call := range x.fake.calls {
				if call == "readback" {
					t.Fatal("pre-add refusal read back")
				}
			}
			if rootGrantsLockHeld(t, x.lock) {
				t.Fatal("guard leaked")
			}
		})
	}
}

// Claim: after the add was dispatched only a definite duplicate is no-effect;
// every other status, and a contradictory native report, is UNKNOWN and reports
// the public reference. A success report requires the dispatched flag.
// Limit: statuses are injected, not produced by the OS.
func TestRootGrantsVaultPostAttemptClassification(t *testing.T) {
	for _, c := range []struct {
		name               string
		attempted          bool
		status             int
		code, phase, state string
	}{
		{"duplicate-is-no-effect", true, rootGrantsStatusDuplicate, "duplicate", "commit", "not_applied"},
		{"generic-failure-is-unknown", true, -25308, "mutation_unknown", "commit", "unknown"},
		{"auth-failure-after-dispatch-is-unknown", true, -25293, "mutation_unknown", "commit", "unknown"},
		{"success-without-dispatch-is-contradictory", false, 0, "mutation_unknown", "commit", "unknown"},
	} {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			x.fake.commitAttempted, x.fake.commitStatus = c.attempted, c.status
			result, err := x.plan.commit(context.Background(), x.vault)
			rootGrantsAttachFailure13(t, result, err, c.code, c.phase, c.state)
			if x.fake.commits != 1 || x.fake.closes != 1 || x.fake.stored != nil && c.state == "not_applied" {
				t.Fatal("exactly one dispatched add expected")
			}
			// A terminal attempt: the copied plan cannot add again.
			if c.state == "unknown" {
				again, err := x.plan.commit(context.Background(), x.vault)
				rootGrantsAttachFailure13(t, again, err, "mutation_unknown", "commit", "unknown")
				if x.fake.commits != 1 {
					t.Fatal("unknown attempt retried the add")
				}
			}
		})
	}
}

// Claim: once the add happened, a readback that errors, is undecodable, shows an
// ACL the policy refuses, or carries other metadata is UNKNOWN (never stored, no
// rollback, no delete: the seam has no such operation). Limit: fake readback.
func TestRootGrantsVaultReadbackFailuresAreUnknown(t *testing.T) {
	other, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	other.Service = "other-root"
	otherMeta, err := CanonicalRootGrantsRecord(other)
	if err != nil {
		t.Fatal(err)
	}
	type readbackCase struct {
		name      string
		configure func(*testing.T, *rootGrantsVaultFixture)
	}
	cases := []readbackCase{
		{"readback-error", func(t *testing.T, x *rootGrantsVaultFixture) {
			x.fake.readbackErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
		}},
		{"undecodable-frame", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.readbackFrame = []byte("garbage") }},
		{"metadata-is-not-a-record", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.readbackMeta = []byte("{}") }},
		{"metadata-of-another-address", func(t *testing.T, x *rootGrantsVaultFixture) { x.fake.readbackMeta = otherMeta }},
		{"metadata-with-trailing-byte", func(t *testing.T, x *rootGrantsVaultFixture) {
			x.fake.readbackMeta = append([]byte(x.item.metadata), '\n')
		}},
	}
	for _, v := range rootGrantsSyntheticVariants {
		v := v
		cases = append(cases, readbackCase{"actual-acl-" + v.name, func(t *testing.T, x *rootGrantsVaultFixture) {
			x.fake.readbackFrame = rootGrantsSyntheticFrame(t, v.mutate)
		}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
			c.configure(t, x)
			result, err := x.plan.commit(context.Background(), x.vault)
			rootGrantsAttachFailure13(t, result, err, "mutation_unknown", "readback", "unknown")
			if x.fake.commits != 1 || x.fake.stored == nil {
				t.Fatal("readback failure must follow exactly one add")
			}
		})
	}
}

// Claim: a missing existing guard refuses with lock_unavailable BEFORE any native
// call and creates nothing (no file, no directory); after Release every
// operation refuses without a native call, and Release frees the flock once.
// Limit: disposable filesystem and real flock; no Keychain.
func TestRootGrantsVaultGuardLifecycle(t *testing.T) {
	t.Run("missing-guard-creates-nothing", func(t *testing.T) {
		x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
		dir := filepath.Dir(x.lock.Path)
		if err := os.Remove(x.lock.Path); err != nil {
			t.Fatal(err)
		}
		result, err := x.plan.commit(context.Background(), x.vault)
		rootGrantsAttachFailure13(t, result, err, "lock_unavailable", "lock", "not_applied")
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 || len(x.fake.calls) != 0 {
			t.Fatalf("missing guard created state or reached native: %v %v", entries, x.fake.calls)
		}
	})
	t.Run("lock-source-failure", func(t *testing.T) {
		x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
		x.vault.lockSource = func() (FileLock, error) { return FileLock{}, errors.New("PUBLIC_TEST_PRIVATE_SENTINEL") }
		result, err := x.plan.commit(context.Background(), x.vault)
		rootGrantsAttachFailure13(t, result, err, "lock_unavailable", "lock", "not_applied")
		if len(x.fake.calls) != 0 {
			t.Fatal("native reached without a guard")
		}
	})
	t.Run("operations-refuse-after-release", func(t *testing.T) {
		x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
		locked, err := x.vault.LockExistingRootGrants(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if !rootGrantsLockHeld(t, x.lock) {
			t.Fatal("guard not held while locked")
		}
		locked.Release()
		locked.Release() // idempotent
		if rootGrantsLockHeld(t, x.lock) {
			t.Fatal("guard not released")
		}
		address := x.item.address
		if _, err := locked.RecoveryPublicMetadata("example-root", 1); !errors.Is(err, errRootGrantsVaultReleased) {
			t.Fatal("pair read after release")
		}
		if _, err := locked.RootGrantsCollision(address); !errors.Is(err, errRootGrantsVaultReleased) {
			t.Fatal("inventory after release")
		}
		if _, err := locked.RootGrantsPublicMetadata(address); !errors.Is(err, errRootGrantsVaultReleased) {
			t.Fatal("readback after release")
		}
		if err := locked.AddRootGrantsOnly(x.item); rootGrantsAddRefusalCode(err) != "operation_unavailable" {
			t.Fatal("add after release")
		}
		if len(x.fake.calls) != 0 {
			t.Fatal("native reached after release")
		}
	})
	t.Run("nil-and-incomplete-vault", func(t *testing.T) {
		var nilVault *rootGrantsProductionVault
		if _, err := nilVault.LockExistingRootGrants(context.Background()); err == nil {
			t.Fatal("nil vault locked")
		}
		if _, err := (&rootGrantsProductionVault{}).LockExistingRootGrants(context.Background()); err == nil {
			t.Fatal("incomplete vault locked")
		}
	})
}

// Claim: the root inventory admits only canonical records whose physical account
// equals their logical address, with no duplicate, and reports a collision exactly
// for the target address; any other form refuses rather than being ignored.
// Positive controls (empty, other address, target) pair with the forbidden rows.
func TestRootGrantsVaultCollisionInventory(t *testing.T) {
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	target := x.item.address
	other, _ := rootGrantsRecordFixture13(t, "keyvault-recovery/2")
	other.Service = "other-root"
	otherMeta, err := CanonicalRootGrantsRecord(other)
	if err != nil {
		t.Fatal(err)
	}
	own := [2]string{"example-root/root-grants@1", x.item.metadata}
	foreign := [2]string{"other-root/root-grants@1", string(otherMeta)}
	for _, c := range []struct {
		name      string
		raw       []byte
		collision bool
		refused   bool
	}{
		{"empty", nil, false, false},
		{"other-address", rootGrantsRowBytes(foreign), false, false},
		{"target-address", rootGrantsRowBytes(foreign, own), true, false},
		{"unparsable-metadata", rootGrantsRowBytes([2]string{"example-root/root-grants@1", "{}"}), false, true},
		{"account-differs-from-logical-address", rootGrantsRowBytes([2]string{"example-root/root-grants@2", x.item.metadata}), false, true},
		{"duplicate-physical-row", rootGrantsRowBytes(own, own), false, true},
		{"missing-final-separator", bytes.TrimSuffix(rootGrantsRowBytes(own), []byte{0x1e}), false, true},
		{"empty-middle-row", append(append(rootGrantsRowBytes(foreign), 0x1e), rootGrantsRowBytes(own)...), false, true},
		{"three-fields", append(bytes.TrimSuffix(rootGrantsRowBytes(own), []byte{0x1e}), 0x1f, 'x', 0x1e), false, true},
		{"empty-account", rootGrantsRowBytes([2]string{"", x.item.metadata}), false, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			x.fake.rootRows = c.raw
			collision, err := x.lockedVault(t).RootGrantsCollision(target)
			if c.refused != (err != nil) || collision != c.collision {
				t.Fatalf("collision=%v err=%v", collision, err)
			}
		})
	}
	x.fake.rootRowsErr = errors.New("PUBLIC_TEST_PRIVATE_SENTINEL")
	if _, err := x.lockedVault(t).RootGrantsCollision(target); err == nil {
		t.Fatal("native inventory failure was ignored")
	}
}

// Claim: the retained pair is returned as its exact stored bytes, only when the
// complete paired namespace validates and exactly one group has that address;
// unparsable or duplicate rows anywhere refuse instead of being skipped.
func TestRootGrantsVaultPairMetadata(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			x := newRootGrantsVaultFixture(t, schema)
			locked := x.lockedVault(t)
			var q rootGrantsPrivateRequest
			request, _, _, _ := rootGrantsSealedFixture46(t, schema)
			if json.Unmarshal(request, &q) != nil {
				t.Fatal("fixture")
			}
			got, err := locked.RecoveryPublicMetadata(q.Pair.Service, q.Pair.Version)
			if err != nil || !bytes.Equal(got, q.PairMetadata) {
				t.Fatalf("exact stored pair bytes not returned: %v", err)
			}
			if _, err := locked.RecoveryPublicMetadata(q.Pair.Service, q.Pair.Version+1); !errors.Is(err, ErrNotFound) {
				t.Fatal("absent pair was not reported as not found")
			}
			if _, err := locked.RecoveryPublicMetadata("Bad Name", 1); err == nil {
				t.Fatal("invalid address admitted")
			}
			locked.Release() // the cases below take the guard again
			for name, rows := range map[string][]byte{
				"unparsable-row-elsewhere": append(rootGrantsRowBytes([2]string{"x/recovery@1", "{not json"}), rootGrantsRowBytes([2]string{x.fake.pairAccount, string(q.PairMetadata)})...),
				"duplicate-row":            append(rootGrantsRowBytes([2]string{x.fake.pairAccount, string(q.PairMetadata)}), rootGrantsRowBytes([2]string{x.fake.pairAccount, string(q.PairMetadata)})...),
				"account-mismatch":         rootGrantsRowBytes([2]string{"other/recovery@9", string(q.PairMetadata)}),
			} {
				x.fake.pairRowsErr = nil
				raw := rows
				x.vault.native = &rootGrantsRawPairFake{rootGrantsNativeFake: x.fake, raw: raw}
				l := x.lockedVault(t)
				if _, err := l.RecoveryPublicMetadata(q.Pair.Service, q.Pair.Version); err == nil {
					t.Fatalf("%s admitted", name)
				}
				l.Release()
			}
		})
	}
}

// rootGrantsRawPairFake overrides only the pair inventory bytes.
type rootGrantsRawPairFake struct {
	*rootGrantsNativeFake
	raw []byte
}

func (f *rootGrantsRawPairFake) PairRows() ([]byte, error) { return bytes.Clone(f.raw), nil }

// Claim: pair metadata that drifts between the preflight and the pre-add re-read
// stops BEFORE the add (not_applied, inventory_changed); drift after the add is
// UNKNOWN. Both are observed through the production adapter's own re-reads.
func TestRootGrantsVaultPairDriftAroundTheAdd(t *testing.T) {
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	x.fake.pairChangeAt = 2 // the re-read immediately before the add
	result, err := x.plan.commit(context.Background(), x.vault)
	rootGrantsAttachFailure13(t, result, err, "inventory_changed", "commit", "not_applied")
	if x.fake.commits != 0 || x.fake.stored != nil {
		t.Fatal("drifted pair still reached the add")
	}
	y := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	y.fake.pairChangeAt = 3 // the re-read after the readback
	result, err = y.plan.commit(context.Background(), y.vault)
	rootGrantsAttachFailure13(t, result, err, "mutation_unknown", "readback", "unknown")
	if y.fake.commits != 1 {
		t.Fatal("post-add drift must follow exactly one add")
	}
}

// Claim: a packet that is malformed or misaddressed at the storage boundary never
// reaches native code: invalid_envelope, no startup, no prepare, no commit.
func TestRootGrantsVaultRefusesMalformedPacketBeforeNative(t *testing.T) {
	x := newRootGrantsVaultFixture(t, "keyvault-recovery/2")
	locked := x.lockedVault(t)
	good := x.item
	for name, item := range map[string]rootGrantsSealedItem{
		"empty-metadata":   {address: good.address, envelope: good.envelope},
		"empty-envelope":   {address: good.address, metadata: good.metadata},
		"not-a-record":     {address: good.address, metadata: "{}", envelope: good.envelope},
		"not-an-envelope":  {address: good.address, metadata: good.metadata, envelope: "{}"},
		"other-address":    {address: RootGrantsAddress{Service: "example-root", Version: 2}, metadata: good.metadata, envelope: good.envelope},
		"invalid-address":  {address: RootGrantsAddress{Service: "Bad Name", Version: 1}, metadata: good.metadata, envelope: good.envelope},
		"nul-in-metadata":  {address: good.address, metadata: good.metadata + "\x00", envelope: good.envelope},
		"trailing-newline": {address: good.address, metadata: good.metadata + "\n", envelope: good.envelope},
	} {
		if err := locked.AddRootGrantsOnly(item); rootGrantsAddRefusalCode(err) != "invalid_envelope" {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if len(x.fake.calls) != 0 {
		t.Fatalf("malformed packet reached native: %v", x.fake.calls)
	}
}

// Claim: the production build cannot store a root item until the real owner/writer
// allowlist replaces the fail-closed default: the default refuses every
// projection, including the synthetic admitted one, with the policy error.
func TestRootGrantsVaultDefaultPolicyFailsClosed(t *testing.T) {
	policy := productionRootGrantsACLPolicy()
	for _, p := range []rootqualification.Projection{{}, rootGrantsSyntheticProjection()} {
		if err := policy.Admit(p); !errors.Is(err, errRootGrantsACLPolicyUnavailable) {
			t.Fatal("default policy admitted a projection")
		}
	}
}

// rootGrantsStoreSourceViolations lists every way the cgo store source leaves its
// boundary: a forbidden Keychain API, a changed add/query count, a dispatch flag not
// set immediately before the single add of the prepared access object, an entry that
// reaches the Keychain before the running-vault check, or a namespace literal that
// differs from the Go constant.
func rootGrantsStoreSourceViolations(src, recordSrc string) []string {
	var violations []string
	for _, forbidden := range []string{"kSecReturnData", "SecItemUpdate", "SecItemDelete", "SecKeychainItemDelete", "SecKeychainItemModify",
		"SecKeychainItemCopyContent", "SecKeychainItemCopyAttributesAndData", "SecKeychainItemSetAccess", "SecACLSet", "SecACLUpdate", "SecAccessCreate", "kSecMatchItemList"} {
		if strings.Contains(src, forbidden) {
			violations = append(violations, "forbidden operation "+forbidden)
		}
	}
	if strings.Count(src, "SecItemAdd(") != 1 || strings.Count(src, "SecItemCopyMatching(") != 2 || strings.Count(src, "kSecAttrAccess,") != 1 {
		violations = append(violations, "add/query count changed")
	}
	if !strings.Contains(src, "CFDictionarySetValue(query, kSecAttrAccess, plan->access);") ||
		!strings.Contains(src, "*attempted = 1;\n        status = SecItemAdd(query, NULL);") {
		violations = append(violations, "dispatch flag is not immediately before the single add of the prepared access object")
	}
	for _, entry := range []string{"MacKeyVaultRootGrantsPairList", "MacKeyVaultRootGrantsList", "MacKeyVaultRootGrantsAddPrepare", "MacKeyVaultRootGrantsAddCommit", "MacKeyVaultRootGrantsReadback"} {
		start := strings.Index(src, "int "+entry+"(")
		if start < 0 {
			violations = append(violations, "missing entry "+entry)
			continue
		}
		end := strings.Index(src[start:], "\n}\n")
		if end < 0 {
			violations = append(violations, "unterminated entry "+entry)
			continue
		}
		body := src[start : start+end]
		gate := strings.Index(body, "KVRGStartup(")
		if gate < 0 {
			violations = append(violations, entry+" does not verify the running vault")
			continue
		}
		for _, native := range []string{"KVQLogin(", "SecItemCopyMatching(", "SecItemAdd(", "MacKeyVaultNostrList(", "KVQIntendedAccess("} {
			if i := strings.Index(body, native); i >= 0 && i < gate {
				violations = append(violations, entry+" reaches "+native+" before the startup check")
			}
		}
	}
	if literal := rootGrantsNamespaceLiteral(src); literal == "" || !strings.Contains(recordSrc, `"`+literal+`"`) {
		violations = append(violations, "namespace literal differs from RootGrantsNamespace")
	}
	return violations
}

// Claim: the cgo store source keeps its boundary: one create-only SecItemAdd of
// the prepared access object with the dispatched flag set immediately before it,
// every native entry verifying the running vault first, and no value read, update,
// delete or ACL-set API anywhere in the file. Control plants (each must be reported
// with its intended violation) show the guard detects the violations it claims to,
// so an always-silent guard cannot pass. Limit: a source guard, not a proof of the
// OS behavior.
func TestRootGrantsStoreSourceBoundary(t *testing.T) {
	src, record := string(mustRead(t, "root_grants_store_darwin.c")), string(mustRead(t, "root_grants_record.go"))
	if violations := rootGrantsStoreSourceViolations(src, record); len(violations) != 0 {
		t.Fatalf("store left its boundary: %v", violations)
	}
	for _, plant := range []struct {
		name, want string
		mutate     func(string) string
	}{
		{"value-read", "forbidden operation kSecReturnData", func(s string) string {
			return s + "\n/* planted */ CFDictionarySetValue(q, kSecReturnData, kCFBooleanTrue);"
		}},
		{"update", "forbidden operation SecItemUpdate", func(s string) string { return s + "\n/* planted */ SecItemUpdate(q, u);" }},
		{"delete", "forbidden operation SecKeychainItemDelete", func(s string) string { return s + "\n/* planted */ SecKeychainItemDelete(item);" }},
		{"second-add", "add/query count changed", func(s string) string { return s + "\n/* planted */ SecItemAdd(q, NULL);" }},
		{"flag-moved", "dispatch flag is not immediately before", func(s string) string {
			return strings.Replace(s, "*attempted = 1;\n        status = SecItemAdd(", "status = SecItemAdd(", 1)
		}},
		{"other-access-object", "dispatch flag is not immediately before", func(s string) string {
			return strings.Replace(s, "kSecAttrAccess, plan->access", "kSecAttrAccess, other", 1)
		}},
		{"startup-removed", "MacKeyVaultRootGrantsAddPrepare does not verify the running vault", func(s string) string {
			return strings.Replace(s, "    if (!KVRGStartup(&symbols)) return 1;\n", "", 1)
		}},
		{"keychain-before-startup", "MacKeyVaultRootGrantsList reaches KVQLogin( before the startup check", func(s string) string {
			return strings.Replace(s, "    KVQSymbols symbols = {0};\n    if (!KVRGStartup(&symbols)) return errSecAuthFailed;\n    SecKeychainRef keychain = NULL;\n    OSStatus status = KVQLogin(&keychain);\n    if (status != errSecSuccess) return (int)status;\n    CFMutableDictionaryRef query = KVRGQuery(keychain, NULL, 0);",
				"    SecKeychainRef keychain = NULL;\n    OSStatus status = KVQLogin(&keychain);\n    if (status != errSecSuccess) return (int)status;\n    KVQSymbols symbols = {0};\n    if (!KVRGStartup(&symbols)) return errSecAuthFailed;\n    CFMutableDictionaryRef query = KVRGQuery(keychain, NULL, 0);", 1)
		}},
		{"namespace-drift", "namespace literal differs", func(s string) string {
			return strings.Replace(s, "works.relux.mac-keyvault.root-grants.v1", "works.relux.mac-keyvault.root-grants.v2", 1)
		}},
	} {
		planted := plant.mutate(src)
		if planted == src {
			t.Fatalf("%s: the plant was not applied (a skipped plant is not a control)", plant.name)
		}
		found := false
		for _, v := range rootGrantsStoreSourceViolations(planted, record) {
			found = found || strings.Contains(v, plant.want)
		}
		if !found {
			t.Fatalf("%s: the guard did not report %q", plant.name, plant.want)
		}
	}
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

// rootGrantsNamespaceLiteral extracts the quoted namespace from the C source.
func rootGrantsNamespaceLiteral(src string) string {
	const marker = `static const char *KVRGNamespace = "`
	i := strings.Index(src, marker)
	if i < 0 {
		return ""
	}
	rest := src[i+len(marker):]
	return rest[:strings.IndexByte(rest, '"')]
}
