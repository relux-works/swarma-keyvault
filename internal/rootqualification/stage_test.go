package rootqualification

import (
	"bytes"
	"strings"
	"testing"
	"time"
)

// goldenStages is the public diagnostic contract written out independently of the
// constants: every reported id with its fixed name. A constant that drifts or is
// shifted by one no longer matches its literal id here.
var goldenStages = []struct {
	stage Stage
	id    int
	name  string
}{
	{StageResolve, 1, "resolve"},
	{StageSelfCode, 2, "self_code"},
	{StageLoginInteraction, 3, "login_interaction"},
	{StageLoginAccountPath, 4, "login_account_path"},
	{StageLoginOpen, 5, "login_open"},
	{StageLoginPathCheck, 6, "login_path_check"},
	{StageLoginStatus, 7, "login_status"},
	{StageLoginLocked, 8, "login_locked"},
	{StageAccessRequirement, 10, "access_requirement"},
	{StageAccessApplication, 11, "access_application"},
	{StageAccessApplicationExact, 12, "access_application_exact"},
	{StageAccessCreate, 13, "access_create"},
	{StageAccessACLList, 14, "access_acl_list"},
	{StageAccessPartitionDescription, 15, "access_partition_description"},
	{StageAccessACLWalk, 16, "access_acl_walk"},
	{StageAccessPartitionACL, 17, "access_partition_acl"},
	{StageBindACLList, 20, "bind_acl_list"},
	{StageBindACLRead, 21, "bind_acl_read"},
	{StageBindReleaseCount, 22, "bind_release_count"},
	{StageBindReleaseRequirementRead, 23, "bind_release_requirement_read"},
	{StageBindReleaseRequirementDiffers, 24, "bind_release_requirement_differs"},
	{StageBindPartition, 25, "bind_partition"},
	{StageBindCounts, 26, "bind_counts"},
	{StageBeforeOwnerACL, 30, "before_owner_acl"},
	{StageBeforeACLAuthorizations, 31, "before_acl_authorizations"},
	{StageBeforeACLContents, 32, "before_acl_contents"},
	{StageBeforeACLRawContents, 33, "before_acl_raw_contents"},
	{StageBeforeACLApplications, 34, "before_acl_applications"},
	{StageBeforeCopy, 35, "before_copy"},
	{StageAddPrepare, 40, "add_prepare"},
	{StageAdd, 41, "add"},
	{StageReadbackRef, 42, "readback_reference"},
	{StageReadbackFind, 43, "readback_find"},
	{StageReadbackMarker, 44, "readback_marker"},
	{StageReadbackAccess, 45, "readback_access"},
	{StageReadbackCopy, 46, "readback_copy"},
	{StageAfterOwnerACL, 50, "after_owner_acl"},
	{StageAfterACLAuth, 51, "after_acl_authorizations"},
	{StageAfterACLContents, 52, "after_acl_contents"},
	{StageAfterACLRaw, 53, "after_acl_raw_contents"},
	{StageAfterACLApps, 54, "after_acl_applications"},
}

// Claim: the Go table assigns each reported stage exactly its published id and
// name, with no duplicate id or name and no extra entry. Limit: this is the Go
// side only; a darwin test compares the same ids with the native enum.
func TestStageTableMatchesPublishedContract(t *testing.T) {
	names := map[string]bool{}
	ids := map[int]bool{}
	for _, g := range goldenStages {
		if int(g.stage) != g.id {
			t.Fatalf("%s has id %d, published id is %d", g.name, int(g.stage), g.id)
		}
		name, ok := g.stage.Name()
		if !ok || name != g.name {
			t.Fatalf("id %d names %q (reported %v), published name is %q", g.id, name, ok, g.name)
		}
		if names[g.name] || ids[g.id] {
			t.Fatalf("duplicate stage %d/%s", g.id, g.name)
		}
		names[g.name], ids[g.id] = true, true
	}
	got := Stages()
	if len(got) != len(goldenStages) {
		t.Fatalf("the table reports %d stages, the contract has %d", len(got), len(goldenStages))
	}
	for i, s := range got {
		if int(s) != goldenStages[i].id {
			t.Fatalf("Stages()[%d] is %d, expected %d (ascending id order)", i, int(s), goldenStages[i].id)
		}
	}
}

// Claim (negative control): an id the native call never emits cannot be reported.
// Every number from 0 to 255 outside the published set, including the reserved id
// 99 and the internal projection ids 70-74, has no name and is dropped by the
// native-result decoder even with a nonzero status. The positive control in the
// same test is that every published id with a nonzero status is kept, so a decoder
// that drops everything fails.
func TestStageIDsThatAreNeverEmittedAreNotReportable(t *testing.T) {
	published := map[int]bool{}
	for _, g := range goldenStages {
		published[g.id] = true
	}
	for id := 0; id <= 255; id++ {
		_, named := Stage(id).Name()
		kept := DiagnosticFromNative(id, -25293)
		if published[id] {
			if !named || kept != (Diagnostic{Stage: Stage(id), OSStatus: -25293}) {
				t.Fatalf("published stage %d was dropped or renamed: %+v", id, kept)
			}
			continue
		}
		if named || kept != (Diagnostic{}) {
			t.Fatalf("stage id %d is never emitted but was reported: %+v", id, kept)
		}
	}
	for _, id := range []int{70, 71, 72, 73, 74, 99, int(StageNone), 256, 1 << 20, -1, -99} {
		if DiagnosticFromNative(id, 5) != (Diagnostic{}) {
			t.Fatalf("id %d must never be reported", id)
		}
	}
}

// Claim: the decoder keeps a failure only with a real nonzero 32-bit OSStatus. A
// zero status, an out-of-range value or a missing stage reports nothing; the
// extreme valid statuses are kept exactly.
func TestDiagnosticFromNativeStatusRules(t *testing.T) {
	cases := []struct {
		name          string
		stage, status int
		want          Diagnostic
	}{
		{"keeps a negative OSStatus", 41, -25299, Diagnostic{Stage: StageAdd, OSStatus: -25299}},
		{"keeps a positive status", 5, 7, Diagnostic{Stage: StageLoginOpen, OSStatus: 7}},
		{"keeps the lowest int32", 2, -2147483648, Diagnostic{Stage: StageSelfCode, OSStatus: -2147483648}},
		{"keeps the highest int32", 2, 2147483647, Diagnostic{Stage: StageSelfCode, OSStatus: 2147483647}},
		{"zero status is not a failure", 41, 0, Diagnostic{}},
		{"below int32 is refused", 41, -2147483649, Diagnostic{}},
		{"above int32 is refused", 41, 2147483648, Diagnostic{}},
		{"no stage is not a failure", 0, -25293, Diagnostic{}},
	}
	for _, c := range cases {
		if got := DiagnosticFromNative(c.stage, c.status); got != c.want {
			t.Errorf("%s: got %+v want %+v", c.name, got, c.want)
		}
	}
	if (Diagnostic{Stage: StageAdd}).Reported() || !(Diagnostic{Stage: StageAdd, OSStatus: 1}).Reported() {
		t.Fatal("Reported must need both a named stage and a nonzero status")
	}
}

// Claim: a native diagnostic changes no receipt byte. For every outcome the
// canonical creation record built with a diagnostic is byte-identical to the one
// built without it, so the closed receipt schema and its digest are unchanged.
// Limit: the record builder only; the stdout/stderr split is tested in the command
// package.
func TestDiagnosticDoesNotEnterTheReceipt(t *testing.T) {
	base := recordFixture(t)
	for _, outcome := range []CreationOutcome{CreationRefused, CreationUnknown, CreationReadback} {
		plain := NativeCreation{Outcome: outcome}
		if outcome == CreationReadback {
			plain = nativeCreationFixture()
		}
		marked := plain
		marked.Diagnostic = Diagnostic{Stage: StageBindReleaseRequirementRead, OSStatus: -25293}
		utc := time.Date(2026, 11, 13, 1, 2, 3, 0, time.UTC)
		a, err := recordFromNative(utc, candidateFixture(), base.ReservationID, base.Pending, plain, base.CreatedIdentity)
		if err != nil {
			t.Fatal(err)
		}
		b, err := recordFromNative(utc, candidateFixture(), base.ReservationID, base.Pending, marked, base.CreatedIdentity)
		if err != nil {
			t.Fatal(err)
		}
		rawA, err := canonicalRecord(a)
		if err != nil {
			t.Fatal(err)
		}
		rawB, err := canonicalRecord(b)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(rawA, rawB) {
			t.Fatalf("outcome %d: the diagnostic changed the receipt bytes", outcome)
		}
		if bytes.Contains(rawB, []byte("diagnostic")) || bytes.Contains(rawB, []byte("os_status")) || strings.Contains(string(rawB), "bind_release") {
			t.Fatalf("outcome %d: the receipt names the diagnostic", outcome)
		}
	}
}
