//go:build darwin && cgo && kvqfault

package keyvault

import (
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
// projection id, with the armed OSStatus. The natural verdict of the groups is masked
// so that every id stays reachable even where a group fails naturally on this
// system. Limit: a plain in-memory access object is projected, not the intended one.
func TestFaultedProjectionStagesNameBeforeAndAfter(t *testing.T) {
	natural := runProjectFault(0, 0, false, true)
	if !natural.Completed {
		t.Fatalf("a masked projection of a plain access must complete: %+v", natural)
	}
	for generic := 70; generic <= 74; generic++ {
		for _, after := range []bool{false, true} {
			want := 30 + (generic - 70)
			if after {
				want = 50 + (generic - 70)
			}
			got := runProjectFault(generic, injected(generic), after, true)
			assertReportable(t, "projection", got)
			if got.Stage != want || got.OSStatus != injected(generic) || got.Completed || got.Result != injected(generic) {
				t.Fatalf("armed projection %d after=%v: got stage %d status %d completed %v result %d, want stage %d status %d",
					generic, after, got.Stage, got.OSStatus, got.Completed, got.Result, want, injected(generic))
			}
		}
	}
}

// Claim: the unmasked projection of a plain access either completes with no record or
// fails with a BEFORE-family stage and a nonzero status; a failure without a record
// fails this test. The verdict is logged: it is the natural diagnosis of this system.
func TestNaturalProjectionRunReportsConsistently(t *testing.T) {
	run := runProjectFault(0, 0, false, false)
	t.Logf("natural projection run: completed=%v stage=%d status=%d", run.Completed, run.Stage, run.OSStatus)
	assertReportable(t, "natural projection", run)
	if run.Completed {
		if run.Stage != 0 || run.Result != 0 {
			t.Fatalf("a completed run recorded a failure: %+v", run)
		}
		return
	}
	if run.Stage < 30 || run.Stage > 34 || run.OSStatus == 0 || run.Result == 0 {
		t.Fatalf("a failed projection must name a BEFORE group with a status: %+v", run)
	}
}

// Claim: the first half of the create call, run unarmed (symbols, intended access,
// BEFORE projection), either completes with no record or fails with a reported stage
// and a nonzero status. This reproduces, in process and without signing, the point
// where the create call refused on a real system; the verdict is logged.
func TestNaturalBeforeProjectionOfTheIntendedAccess(t *testing.T) {
	run := runBeforeNatural()
	t.Logf("natural create front half: completed=%v stage=%d status=%d result=%d", run.Completed, run.Stage, run.OSStatus, run.Result)
	assertReportable(t, "natural before", run)
	if run.Completed {
		if run.Stage != 0 || run.Result != 0 {
			t.Fatalf("a completed run recorded a failure: %+v", run)
		}
		return
	}
	if run.Stage == 0 || run.OSStatus == 0 || run.Result == 0 {
		t.Fatalf("the run failed without a recorded stage and status: %+v", run)
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
