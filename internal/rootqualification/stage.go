package rootqualification

import "sort"

// Stage identifies the step of the native create call that failed first. The ids
// are a public diagnostic contract (they are printed on stderr next to the
// Security OSStatus): never renumber or reuse one, only append. They equal the
// KVQ_STAGE_* constants of the native unit, which a darwin test compares one by
// one. A stage carries no item data.
type Stage uint8

const (
	StageNone Stage = 0

	StageResolve  Stage = 1
	StageSelfCode Stage = 2

	StageLoginInteraction Stage = 3
	StageLoginAccountPath Stage = 4
	StageLoginOpen        Stage = 5
	StageLoginPathCheck   Stage = 6
	StageLoginStatus      Stage = 7
	StageLoginLocked      Stage = 8

	StageAccessRequirement          Stage = 10
	StageAccessApplication          Stage = 11
	StageAccessApplicationExact     Stage = 12
	StageAccessCreate               Stage = 13
	StageAccessACLList              Stage = 14
	StageAccessPartitionDescription Stage = 15
	StageAccessACLWalk              Stage = 16
	StageAccessPartitionACL         Stage = 17

	StageBindACLList                   Stage = 20
	StageBindACLRead                   Stage = 21
	StageBindReleaseCount              Stage = 22
	StageBindReleaseRequirementRead    Stage = 23
	StageBindReleaseRequirementDiffers Stage = 24
	StageBindPartition                 Stage = 25
	StageBindCounts                    Stage = 26

	StageBeforeOwnerACL          Stage = 30
	StageBeforeACLAuthorizations Stage = 31
	StageBeforeACLContents       Stage = 32
	StageBeforeACLRawContents    Stage = 33
	StageBeforeACLApplications   Stage = 34
	StageBeforeCopy              Stage = 35

	StageAddPrepare     Stage = 40
	StageAdd            Stage = 41
	StageReadbackRef    Stage = 42
	StageReadbackFind   Stage = 43
	StageReadbackMarker Stage = 44
	StageReadbackAccess Stage = 45
	StageReadbackCopy   Stage = 46

	StageAfterOwnerACL    Stage = 50
	StageAfterACLAuth     Stage = 51
	StageAfterACLContents Stage = 52
	StageAfterACLRaw      Stage = 53
	StageAfterACLApps     Stage = 54

	// StageReserved is part of the id space but is never reported. It is the
	// negative control for "an id that is never emitted must not appear".
	StageReserved Stage = 99
)

// stageNames is the closed table of reported stages. Anything not in it (the
// internal projection ids 70-74, the reserved id, an unknown number) is not a
// reportable stage.
var stageNames = map[Stage]string{
	StageResolve:  "resolve",
	StageSelfCode: "self_code",

	StageLoginInteraction: "login_interaction",
	StageLoginAccountPath: "login_account_path",
	StageLoginOpen:        "login_open",
	StageLoginPathCheck:   "login_path_check",
	StageLoginStatus:      "login_status",
	StageLoginLocked:      "login_locked",

	StageAccessRequirement:          "access_requirement",
	StageAccessApplication:          "access_application",
	StageAccessApplicationExact:     "access_application_exact",
	StageAccessCreate:               "access_create",
	StageAccessACLList:              "access_acl_list",
	StageAccessPartitionDescription: "access_partition_description",
	StageAccessACLWalk:              "access_acl_walk",
	StageAccessPartitionACL:         "access_partition_acl",

	StageBindACLList:                   "bind_acl_list",
	StageBindACLRead:                   "bind_acl_read",
	StageBindReleaseCount:              "bind_release_count",
	StageBindReleaseRequirementRead:    "bind_release_requirement_read",
	StageBindReleaseRequirementDiffers: "bind_release_requirement_differs",
	StageBindPartition:                 "bind_partition",
	StageBindCounts:                    "bind_counts",

	StageBeforeOwnerACL:          "before_owner_acl",
	StageBeforeACLAuthorizations: "before_acl_authorizations",
	StageBeforeACLContents:       "before_acl_contents",
	StageBeforeACLRawContents:    "before_acl_raw_contents",
	StageBeforeACLApplications:   "before_acl_applications",
	StageBeforeCopy:              "before_copy",

	StageAddPrepare:     "add_prepare",
	StageAdd:            "add",
	StageReadbackRef:    "readback_reference",
	StageReadbackFind:   "readback_find",
	StageReadbackMarker: "readback_marker",
	StageReadbackAccess: "readback_access",
	StageReadbackCopy:   "readback_copy",

	StageAfterOwnerACL:    "after_owner_acl",
	StageAfterACLAuth:     "after_acl_authorizations",
	StageAfterACLContents: "after_acl_contents",
	StageAfterACLRaw:      "after_acl_raw_contents",
	StageAfterACLApps:     "after_acl_applications",
}

// Name returns the fixed public name of a reported stage.
func (s Stage) Name() (string, bool) {
	name, ok := stageNames[s]
	return name, ok
}

// Stages lists every reported stage in id order.
func Stages() []Stage {
	out := make([]Stage, 0, len(stageNames))
	for s := range stageNames {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// Diagnostic is the first failing step of a native create call and its Security
// OSStatus. The zero value means "nothing to report". It never changes the
// operation's outcome and is not part of any receipt.
type Diagnostic struct {
	Stage    Stage
	OSStatus int32
}

// Reported reports whether the diagnostic names a failure.
func (d Diagnostic) Reported() bool {
	_, ok := d.Stage.Name()
	return ok && d.OSStatus != 0
}

// DiagnosticFromNative admits the two integers the native call returned. Only a
// reported stage with a nonzero status that fits a 32-bit OSStatus is kept; an id
// outside the closed table (the internal projection ids, the reserved id, any
// unknown number) or a zero status yields the zero Diagnostic, so a wrong native
// id can never be printed.
func DiagnosticFromNative(stage, status int) Diagnostic {
	if stage < 1 || stage > 255 || status == 0 || status < -2147483648 || status > 2147483647 {
		return Diagnostic{}
	}
	d := Diagnostic{Stage: Stage(stage), OSStatus: int32(status)}
	if !d.Reported() {
		return Diagnostic{}
	}
	return d
}
