//go:build darwin && cgo && kvqfault

package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"sort"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/rootqualification"
)

// These tests run only with the kvqfault tag (go test -tags kvqfault). They arm one
// native stage at a time and prove that the stage id and the OSStatus the native
// call records are exactly the armed ones. They call the real shared ACL code on
// in-memory objects only: no code check of a signed binary, no Keychain item, no
// add. A stage that the natural run of this system fails before reaching cannot be
// armed and is reported as skipped, never as passed.

// injected is the status armed for a stage: unique per stage and unlike a natural
// Security status, so a status taken from anywhere else cannot match it.
func injected(id int) int { return -61000 - id }

func reportable(stage int) bool {
	_, ok := rootqualification.Stage(stage).Name()
	return stage == 0 || ok
}

// assertReportable fails if a run recorded an id outside the closed reported table:
// the internal projection ids and the reserved id must never leave the native unit.
func assertReportable(t *testing.T, label string, run faultRun) {
	t.Helper()
	if !reportable(run.Stage) {
		t.Fatalf("%s: stage id %d is not a reported stage", label, run.Stage)
	}
	if (run.Stage == 0) != (run.OSStatus == 0) {
		t.Fatalf("%s: stage %d and status %d disagree about whether a failure was recorded", label, run.Stage, run.OSStatus)
	}
}

// Claim: the real in-memory pipeline either completes with no failure recorded, or
// fails with a reported stage of the symbol, access or bindings family and a nonzero
// status. A failure without a record fails this test. The observed verdict is
// logged: it is the natural diagnosis of this system.
func TestNaturalIntendedAccessRunReportsConsistently(t *testing.T) {
	run := runIntendedFault(0, 0, false)
	t.Logf("natural intended-access run: completed=%v stage=%d status=%d result=%d", run.Completed, run.Stage, run.OSStatus, run.Result)
	assertReportable(t, "natural", run)
	if run.Completed {
		if run.Stage != 0 || run.Result != 0 {
			t.Fatalf("a completed run recorded a failure: %+v", run)
		}
		return
	}
	if run.Stage == 0 || run.OSStatus == 0 || run.Result == 0 {
		t.Fatalf("the run failed without a recorded stage and status: %+v", run)
	}
	if run.Stage != 1 && !(run.Stage >= 10 && run.Stage <= 26) {
		t.Fatalf("an intended-access run reported stage %d outside its families", run.Stage)
	}
}

// Claim: arming one stage of the symbol, access-construction or bindings family
// makes the native call record exactly that stage id with exactly the armed
// OSStatus, and the call fails. Stages 25 and 26 are armed with the release
// requirement check masked, so they stay reachable on a system where that check
// fails naturally. Negative control: the reserved id armed here changes nothing
// compared with the natural run. Limit: a stage the natural run fails before
// reaching is skipped and reported, not counted as proven.
func TestFaultedIntendedAccessStagesNameThemselves(t *testing.T) {
	arms := []struct {
		id   int
		mask bool
	}{
		{1, false}, {10, false}, {11, false}, {12, false}, {13, false}, {14, false}, {15, false}, {16, false}, {17, false},
		{20, false}, {21, false}, {22, false}, {23, false}, {24, false}, {25, true}, {26, true},
	}
	proven := 0
	for _, arm := range arms {
		natural := runIntendedFault(0, 0, arm.mask)
		if natural.Stage != 0 && arm.id > natural.Stage {
			t.Logf("SKIPPED stage %d: this system's natural run already fails at stage %d (status %d)", arm.id, natural.Stage, natural.OSStatus)
			continue
		}
		got := runIntendedFault(arm.id, injected(arm.id), arm.mask)
		assertReportable(t, "armed", got)
		if got.Stage != arm.id || got.OSStatus != injected(arm.id) || got.Completed || got.Result == 0 {
			t.Fatalf("armed stage %d: got stage %d status %d completed %v result %d, want stage %d status %d", arm.id, got.Stage, got.OSStatus, got.Completed, got.Result, arm.id, injected(arm.id))
		}
		if arm.id != 1 && got.Result != injected(arm.id) {
			t.Fatalf("armed stage %d: the returned status %d is not the recorded one %d", arm.id, got.Result, injected(arm.id))
		}
		proven++
	}
	t.Logf("intended-access stages proven by injection: %d of %d", proven, len(arms))
	if proven == 0 {
		t.Fatal("no stage could be armed")
	}
	reserved := runIntendedFault(int(rootqualification.StageReserved), injected(99), false)
	natural := runIntendedFault(0, 0, false)
	if reserved != natural {
		t.Fatalf("the reserved id changed the run: %+v versus natural %+v", reserved, natural)
	}
}

// Claim: arming one projection group makes the call record the BEFORE id when the
// first projection fails and the AFTER id when the second does, never the internal
// projection id, with the armed OSStatus. All ten ids are armed and none may be
// skipped: the natural projection of the plain access object completes on this
// system, so every group and the AFTER projection are reachable. Limit: a plain
// in-memory access object is projected, not the intended one.
func TestFaultedProjectionStagesNameBeforeAndAfter(t *testing.T) {
	natural := runProjectFault(0, 0, false, false)
	if !natural.Completed || natural.Stage != 0 {
		t.Fatalf("the natural projection of a plain access object must complete: %+v", natural)
	}
	proven := 0
	for generic := 70; generic <= 74; generic++ {
		for _, after := range []bool{false, true} {
			want := 30 + (generic - 70)
			if after {
				want = 50 + (generic - 70)
			}
			got := runProjectFault(generic, injected(generic), after, false)
			assertReportable(t, "projection", got)
			if got.Stage != want || got.OSStatus != injected(generic) || got.Completed || got.Result != injected(generic) {
				t.Fatalf("armed projection %d after=%v: got stage %d status %d completed %v result %d, want stage %d status %d",
					generic, after, got.Stage, got.OSStatus, got.Completed, got.Result, want, injected(generic))
			}
			proven++
		}
	}
	if proven != 10 {
		t.Fatalf("%d of 10 projection ids proven, none may be skipped", proven)
	}
}

// Claim: the natural projection of a plain access object completes with no failure
// recorded. Before the fix it failed at stage 31 (the list it read held strings).
func TestNaturalProjectionRunCompletes(t *testing.T) {
	run := runProjectFault(0, 0, false, false)
	t.Logf("natural projection run: completed=%v stage=%d status=%d", run.Completed, run.Stage, run.OSStatus)
	if !run.Completed || run.Stage != 0 || run.OSStatus != 0 || run.Result != 0 {
		t.Fatalf("the natural projection must complete: %+v", run)
	}
}

// Claim: the first half of the create call, run unarmed (symbols, intended access,
// BEFORE projection), completes with no failure recorded. This is the point where the
// create call refused on a real system before the fix, reproduced here in process and
// without signing. Beside the negative control below, a projection that cannot read
// the ACL objects fails this test.
func TestNaturalBeforeProjectionOfTheIntendedAccess(t *testing.T) {
	run := runBeforeNatural()
	t.Logf("natural create front half: completed=%v stage=%d status=%d result=%d", run.Completed, run.Stage, run.OSStatus, run.Result)
	if !run.Completed || run.Stage != 0 || run.OSStatus != 0 || run.Result != 0 {
		t.Fatalf("the front half of the create call must complete: %+v", run)
	}
}

// errSecDecode is the Security status the projection returns for a list element that
// is not an ACL object.
const errSecDecode = -26275

// Claim (negative control): a list element that is not an ACL object is still refused,
// at the BEFORE authorizations stage 31 with errSecDecode, so the fix did not weaken the
// check. The element is replaced under the kvqfault tag by a string, the shape
// SecAccessCopyOwnerAndACL returns.
func TestProjectionRefusesAListElementThatIsNotAnACL(t *testing.T) {
	run := runProjectNonACL()
	assertReportable(t, "non-ACL element", run)
	if run.Completed || run.Stage != 31 || run.OSStatus != errSecDecode || run.Result != errSecDecode {
		t.Fatalf("a non-ACL list element must refuse at stage 31 with errSecDecode: %+v", run)
	}
}

// Claim: the projection output is deterministic. The same access object projected twice
// gives byte-identical frames. Two separately built intended access objects give frames
// with the same owner and the same set of ACL projections; their ACL order and bytes
// are logged because the system does not promise an order. Every frame is a valid KVQP1
// projection that the Go decoder accepts and that lists at least one ACL. Limit: one
// machine; it shows determinism of content, not that the observed ACL forms are
// admissible, and any later comparison of observed ACLs must ignore their order.
func TestProjectionIsDeterministic(t *testing.T) {
	decode := func(raw []byte) rootqualification.Projection {
		t.Helper()
		projection, err := rootqualification.DecodeNativeProjection(raw)
		if err != nil || len(projection.ACLs) == 0 {
			t.Fatalf("the frame is not a valid KVQP1 projection (%v, %d ACLs)", err, len(projection.ACLs))
		}
		return projection
	}
	canon := func(p rootqualification.Projection) []string {
		out := make([]string, 0, len(p.ACLs))
		for _, acl := range p.ACLs {
			raw, err := json.Marshal(acl)
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(raw))
		}
		return out
	}
	same, again, run := projectTwice(false)
	if !run.Completed || len(same) == 0 || !bytes.Equal(same, again) {
		t.Fatalf("the same object projected twice must give identical frames: %+v lengths %d %d", run, len(same), len(again))
	}
	first := decode(same)
	t.Logf("same object: %d bytes, %d ACLs, owner %d/%d type %d, identical twice", len(same), len(first.ACLs), first.OwnerUID, first.OwnerGID, first.OwnerType)

	one, two, run := projectTwice(true)
	if !run.Completed || len(one) == 0 || len(two) == 0 {
		t.Fatalf("two separately built objects must project: %+v", run)
	}
	a, b := decode(one), decode(two)
	if a.OwnerUID != b.OwnerUID || a.OwnerGID != b.OwnerGID || a.OwnerType != b.OwnerType {
		t.Fatalf("the owner differs between two builds: %d/%d/%d versus %d/%d/%d", a.OwnerUID, a.OwnerGID, a.OwnerType, b.OwnerUID, b.OwnerGID, b.OwnerType)
	}
	ordered := canon(a)
	unordered := canon(b)
	inOrder := true
	for i := range ordered {
		if i >= len(unordered) || ordered[i] != unordered[i] {
			inOrder = false
		}
	}
	sort.Strings(ordered)
	sort.Strings(unordered)
	if len(ordered) != len(unordered) {
		t.Fatalf("two builds give %d and %d ACLs", len(ordered), len(unordered))
	}
	for i := range ordered {
		if ordered[i] != unordered[i] {
			t.Fatalf("the set of ACL projections differs between two builds at sorted position %d:\n%s\n%s", i, ordered[i], unordered[i])
		}
	}
	firstDifference := -1
	for i := 0; i < len(one) && i < len(two); i++ {
		if one[i] != two[i] {
			firstDifference = i
			break
		}
	}
	t.Logf("two builds: %d and %d bytes, byte-identical=%v, same ACLs in the same order=%v, first differing byte=%d", len(one), len(two), bytes.Equal(one, two), inOrder, firstDifference)
}

// Claim (operation-keyed control): when the projection's read of the ACL list fails, the
// stage id it records is the OWNER/ACL id of the right projection: 30 for the BEFORE
// projection and 50 for the AFTER one, with exactly the status that read returned and
// the call not completed. The fault breaks the operation, not a stage id, and the
// expected ids are literals written here, so a wrong label at that call (a stage id
// shifted by one) fails this test; the stage-keyed arming above cannot see that because
// the label under test is also its arming key. Positive control: the same run with the
// operation unbroken completes.
func TestListReadFaultNamesTheOwnerStageOfTheRightProjection(t *testing.T) {
	if ok := runProjectOpFault(0, 0, false); !ok.Completed || ok.Stage != 0 {
		t.Fatalf("the unbroken run must complete: %+v", ok)
	}
	const opStatus = -61080
	for _, c := range []struct {
		after bool
		want  int
	}{{false, 30}, {true, 50}} {
		got := runProjectOpFault(opProjectACLList, opStatus, c.after)
		assertReportable(t, "list read", got)
		if got.Stage != c.want || got.OSStatus != opStatus || got.Completed || got.Result != opStatus {
			t.Fatalf("a failed ACL-list read (after=%v) must record stage %d with status %d: %+v", c.after, c.want, opStatus, got)
		}
	}
}

// Claim (operation-keyed control): when writing an authorization name into the frame
// fails, the stage id recorded is the authorizations id of the right projection: 31
// (BEFORE) or 51 (AFTER), with errSecDecode, and the call does not complete. The fault
// makes the projection's text writer reject the names; no group-end id is armed, and the
// expected ids are literals written here, so a wrong label at the end of the group (a
// later group named instead) fails this test.
func TestAuthorizationWriteFaultNamesTheAuthorizationsStageOfTheRightProjection(t *testing.T) {
	for _, c := range []struct {
		after bool
		want  int
	}{{false, 31}, {true, 51}} {
		got := runProjectOpFault(opProjectAuthText, 0, c.after)
		assertReportable(t, "authorization write", got)
		if got.Stage != c.want || got.OSStatus != errSecDecode || got.Completed || got.Result != errSecDecode {
			t.Fatalf("a failed authorization write (after=%v) must record stage %d with errSecDecode: %+v", c.after, c.want, got)
		}
	}
}

// Claim: the probe describes the inputs of the authorizations group on this system.
// It logs how many ACLs and names there are and whether the UTF-8 conversion check or
// the projection's own text writer rejects any name (with the first rejected name and
// lengths). Its only assertion is that it examined at least one name, so a probe that
// sees nothing cannot pass for an answer.
func TestProbeAuthorizationsDescribesTheProjectionInput(t *testing.T) {
	probe := probeAuthorizations()
	t.Logf("authorizations probe: %+v", probe)
	if probe.Status != 0 || probe.Counts[0] == 0 || probe.Counts[2] == 0 {
		t.Fatalf("the probe saw no authorization names: %+v", probe)
	}
}

// Claim: the probe describes the list the projection reads. It logs the element
// types of SecAccessCopyOwnerAndACL beside those of SecAccessCopyACLList on this system.
// Its only assertions are that the probe ran and saw the lists, so an empty probe cannot
// pass for an answer.
func TestProbeOwnerACLDescribesTheProjectionList(t *testing.T) {
	values, status := probeOwnerACL()
	t.Logf("owner/ACL probe: status=%d values=%v", status, values)
	if status != 0 || values[3] == 0 || values[13] == 0 {
		t.Fatalf("the probe saw no ACL list: status %d values %v", status, values)
	}
}

// Claim: arming one login-keychain step records exactly that step. The steps after
// the keychain was opened need that open to succeed on this system and are skipped
// otherwise. Positive control: the first steps are always reachable.
func TestFaultedLoginStagesNameThemselves(t *testing.T) {
	natural := runLoginFault(0, 0)
	t.Logf("natural login run: completed=%v stage=%d status=%d", natural.Completed, natural.Stage, natural.OSStatus)
	assertReportable(t, "natural login", natural)
	proven := 0
	for id := 3; id <= 8; id++ {
		if natural.Stage != 0 && id > natural.Stage {
			t.Logf("SKIPPED stage %d: the natural login run already fails at stage %d (status %d)", id, natural.Stage, natural.OSStatus)
			continue
		}
		got := runLoginFault(id, injected(id))
		assertReportable(t, "login", got)
		if got.Stage != id || got.OSStatus != injected(id) || got.Completed || got.Result != injected(id) {
			t.Fatalf("armed login stage %d: got stage %d status %d completed %v result %d", id, got.Stage, got.OSStatus, got.Completed, got.Result)
		}
		proven++
	}
	if proven < 3 {
		t.Fatalf("only %d login stages could be armed, the first three are always reachable", proven)
	}
}

// Claim: the running-code check records its own stage. A Go test binary is not the
// pinned signed vault, so the natural run must fail at stage 2 with a real status;
// arming stage 2 records the armed status; arming a different stage leaves the
// natural status untouched.
func TestSelfCodeStageIsRecorded(t *testing.T) {
	natural := runSelfFault(0, 0)
	assertReportable(t, "natural self", natural)
	if natural.Stage != int(rootqualification.StageSelfCode) || natural.OSStatus == 0 || natural.Result == 0 {
		t.Fatalf("an unsigned test binary must fail the code check at stage 2: %+v", natural)
	}
	armed := runSelfFault(2, injected(2))
	if armed.Stage != 2 || armed.OSStatus != injected(2) || armed.Result != injected(2) {
		t.Fatalf("armed self stage: %+v", armed)
	}
	other := runSelfFault(41, injected(41))
	if other.Stage != natural.Stage || other.OSStatus != natural.OSStatus {
		t.Fatalf("arming another stage changed the self-code verdict: %+v versus %+v", other, natural)
	}
}

// Claim: the first recorded failure wins and a later one never overwrites it; a
// stage of 0 or a status of 0 is not a failure and is not recorded. Beside the
// positive order controls, an implementation that keeps the last note fails.
func TestFirstFailureWinsAndNonFailuresAreNotRecorded(t *testing.T) {
	// a and b are the (stage, status) of the first and the second note.
	cases := []struct {
		name string
		a, b [2]int
		want [2]int
	}{
		{"first of two", [2]int{5, -1}, [2]int{6, -2}, [2]int{5, -1}},
		{"order is not by id", [2]int{6, -2}, [2]int{5, -1}, [2]int{6, -2}},
		{"zero status is skipped", [2]int{5, 0}, [2]int{6, -2}, [2]int{6, -2}},
		{"zero stage is skipped", [2]int{0, -1}, [2]int{6, -2}, [2]int{6, -2}},
		{"nothing at all", [2]int{0, 0}, [2]int{0, 0}, [2]int{0, 0}},
	}
	for _, c := range cases {
		got := noteTwice(c.a[0], c.a[1], c.b[0], c.b[1])
		if got.Stage != c.want[0] || got.OSStatus != c.want[1] {
			t.Errorf("%s: got stage %d status %d, want stage %d status %d", c.name, got.Stage, got.OSStatus, c.want[0], c.want[1])
		}
	}
}

// canonicalACLSet is the order-free form of a projection: every ACL encoded alone with
// the owner row, sorted. Two builds of the same access object list their ACLs in
// different orders, so only this form can be compared.
func canonicalACLSet(t *testing.T, p rootqualification.Projection) []string {
	t.Helper()
	out := make([]string, len(p.ACLs))
	for i, a := range p.ACLs {
		raw, err := rootqualification.EncodeNativeProjection(rootqualification.Projection{
			OwnerUID: p.OwnerUID, OwnerGID: p.OwnerGID, OwnerType: p.OwnerType, ACLs: []rootqualification.ACLProjection{a}})
		if err != nil {
			t.Fatal(err)
		}
		out[i] = hex.EncodeToString(raw)
	}
	sort.Strings(out)
	return out
}

// Claim (the native agreement check, and the public dump): the intended access object
// that the native unit builds in memory, projected exactly as a create call projects it,
// is admitted by the allowlist built for the same descriptor through the intended entry
// point and refused by the stored one, for the public marker and for the production
// descriptor. The marker's native frame equals the attended observation of the signed
// build as an order-free set of ACLs, and the production frame equals that observation
// with the descriptor substituted. The public fields are logged: this is the dump.
// Limit: in memory only, an unsigned test binary; it says nothing about the stored
// item, which only an attended add can show.
func TestNativeIntendedFrameAgreesWithTheAdmittedForm(t *testing.T) {
	observedBefore, _ := loadObservedProjections(t)
	for _, c := range []struct {
		name, descriptor, label string
		want                    rootqualification.Projection
	}{
		{"marker", markerAccessDescriptor, "keyvault-root-acl-qualification:/vault", observedBefore},
		{"production", rootGrantsAccessDescriptor, "keyvault-root-grants:/vault", substituteDescriptor(observedBefore, markerAccessDescriptor, rootGrantsAccessDescriptor)},
	} {
		frame, run := intendedFrame(c.descriptor, c.label)
		if !run.Completed || len(frame) == 0 {
			t.Fatalf("%s: the native run did not complete: %+v", c.name, run)
		}
		projection, err := rootqualification.DecodeNativeProjection(frame)
		if err != nil {
			t.Fatalf("%s: the native frame does not decode: %v", c.name, err)
		}
		sum := sha256.Sum256(frame)
		t.Logf("%s: %d bytes, sha256 %s, owner %d/%d/%d, %d ACLs", c.name, len(frame), hex.EncodeToString(sum[:]), projection.OwnerUID, projection.OwnerGID, projection.OwnerType, len(projection.ACLs))
		for i, a := range projection.ACLs {
			t.Logf("%s acl %d: names %v numbers %v description %q applications %s/%d prompt %d %s %d %d", c.name, i, a.Authorizations, a.AuthorizationNumbers,
				a.Description, a.ApplicationsState, len(a.Applications), a.PromptBits, a.RawPromptState, a.RawPromptVersion, a.RawPromptFlags)
			for _, app := range a.Applications {
				t.Logf("%s acl %d application: %s %d bytes %q", c.name, i, app.RequirementState, len(app.Requirement), app.RequirementText)
			}
		}
		policy, err := rootqualification.NewStoragePolicy(c.descriptor)
		if err != nil {
			t.Fatal(err)
		}
		if err := policy.AdmitIntended(projection); err != nil {
			t.Fatalf("%s: the allowlist refuses the native intended object: %v", c.name, err)
		}
		if err := policy.AdmitStored(projection); err == nil {
			t.Fatalf("%s: the stored entry point admitted the intended object", c.name)
		}
		if got, want := canonicalACLSet(t, projection), canonicalACLSet(t, c.want); !reflect.DeepEqual(got, want) {
			t.Fatalf("%s: the native object differs from the admitted observation:\n got %v\nwant %v", c.name, got, want)
		}
	}
}
