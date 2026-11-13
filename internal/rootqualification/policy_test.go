package rootqualification

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/relux-works/swarma-keyvault/internal/codesignpolicy"
)

// The descriptors of the two access objects the predicate is instantiated for: the
// public-marker item that the attended qualification observed, and the production
// root item. The numbers are the ACL authorizations as the observation recorded them;
// they are written out here, not read from the policy, so a shifted value in the
// policy fails these tests instead of being followed.
const (
	markerDescriptor     = "Root ACL public qualification"
	productionDescriptor = "Root grants key"

	numEncrypt   uint32 = 35
	numChangeACL uint32 = 65536
	numRelease   uint32 = 24 // the release ACL is found through its Decrypt authorization
	numPartition uint32 = 65538
	numIntegrity uint32 = 65539
)

// observedRecord is the public part of the attended observation (testdata/observed).
type observedRecord struct {
	Schema    string `json:"schema"`
	State     string `json:"state"`
	Candidate struct {
		SourceHead string `json:"source_head"`
		SourceTree string `json:"source_tree"`
	} `json:"candidate"`
	Before       Projection `json:"before"`
	BeforeSHA256 string     `json:"before_sha256"`
	After        Projection `json:"after"`
	AfterSHA256  string     `json:"after_sha256"`
}

func loadObserved(t testing.TB) observedRecord {
	t.Helper()
	raw, err := os.ReadFile("testdata/observed/h4-frames.json")
	if err != nil {
		t.Fatal(err)
	}
	var record observedRecord
	if err := json.Unmarshal(raw, &record); err != nil {
		t.Fatal(err)
	}
	return record
}

func newTestPolicy(t testing.TB, descriptor string) *StoragePolicy {
	t.Helper()
	policy, err := NewStoragePolicy(descriptor)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func cloneProjection(t testing.TB, p Projection) Projection {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	var out Projection
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatal(err)
	}
	return out
}

// copyACL is a deep copy; the test data is small and a failure is a test bug.
func copyACL(a ACLProjection) ACLProjection {
	raw, err := json.Marshal(a)
	if err != nil {
		panic(err)
	}
	var out ACLProjection
	if err := json.Unmarshal(raw, &out); err != nil {
		panic(err)
	}
	return out
}

func indexByNumber(p *Projection, number uint32) int {
	for i := range p.ACLs {
		for _, n := range p.ACLs[i].AuthorizationNumbers {
			if n == number {
				return i
			}
		}
	}
	return -1
}

// acl returns the first ACL that carries the authorization; a frame without it is a
// bug of the test case, not of the policy.
func acl(p *Projection, number uint32) *ACLProjection {
	i := indexByNumber(p, number)
	if i < 0 {
		panic(fmt.Sprintf("test frame has no ACL with authorization %d", number))
	}
	return &p.ACLs[i]
}

func removeACL(p *Projection, number uint32) {
	i := indexByNumber(p, number)
	p.ACLs = append(p.ACLs[:i], p.ACLs[i+1:]...)
}

func flipLastChar(s string) string {
	if s == "" {
		return "0"
	}
	last := s[len(s)-1]
	replacement := byte('0')
	if last == '0' {
		replacement = '1'
	}
	return s[:len(s)-1] + string(replacement)
}

func withDescriptor(t testing.TB, p Projection, from, to string) Projection {
	t.Helper()
	out := cloneProjection(t, p)
	for i := range out.ACLs {
		if out.ACLs[i].Description == from {
			out.ACLs[i].Description = to
		}
	}
	return out
}

// canonicalJSON is the form of a projection that two admitted projections must share:
// ACLs sorted, each ACL's lists sorted, nil and empty lists equal, and the Integrity
// ACL's description (the one field the policy admits by pattern) blanked.
func canonicalJSON(t testing.TB, p Projection) string {
	t.Helper()
	q := cloneProjection(t, p)
	items := make([]string, len(q.ACLs))
	for i := range q.ACLs {
		a := &q.ACLs[i]
		if len(a.AuthorizationNumbers) == 1 && a.AuthorizationNumbers[0] == numIntegrity {
			a.Description = ""
		}
		a.Authorizations = append([]string{}, a.Authorizations...)
		sort.Strings(a.Authorizations)
		a.AuthorizationNumbers = append([]uint32{}, a.AuthorizationNumbers...)
		sort.Slice(a.AuthorizationNumbers, func(x, y int) bool { return a.AuthorizationNumbers[x] < a.AuthorizationNumbers[y] })
		apps := make([]ApplicationProjection, len(a.Applications))
		for k, app := range a.Applications {
			if app.Requirement == nil {
				app.Requirement = []byte{}
			}
			apps[k] = app
		}
		a.Applications = apps
		raw, err := json.Marshal(*a)
		if err != nil {
			t.Fatal(err)
		}
		items[i] = string(raw)
	}
	sort.Strings(items)
	return fmt.Sprintf("%d,%d,%d|%s", q.OwnerUID, q.OwnerGID, q.OwnerType, strings.Join(items, "|"))
}

func requireRefusal(t testing.TB, err error, form string, reason PolicyReason) {
	t.Helper()
	var refusal *PolicyError
	if !errors.As(err, &refusal) || !errors.Is(err, ErrPolicyRefused) || refusal.Form != form || refusal.Reason != reason {
		t.Fatalf("want a %s-form refusal for %q, got %v", form, reason, err)
	}
}

// "before" is the intended object and uses the intended entry point; "after" is the
// stored item and uses the stored one.
func frameFor(obs observedRecord, kind string) Projection {
	if kind == "before" {
		return obs.Before
	}
	return obs.After
}

func formName(kind string) string {
	if kind == "before" {
		return "intended"
	}
	return "stored"
}

type storagePolicy interface {
	AdmitIntended(Projection) error
	AdmitStored(Projection) error
}

func admitFor(policy storagePolicy, kind string, p Projection) error {
	if kind == "before" {
		return policy.AdmitIntended(p)
	}
	return policy.AdmitStored(p)
}

// Claim: the recorded observation is an observation: both frames re-encode to
// exactly the byte count and SHA-256 that the attended run recorded, and the record
// names the source head and tree of the build that produced it. A hand-edited
// fixture cannot pass for evidence. Limit: it shows the fixture is the recorded
// one, not that the recording was honest (the provenance is reviewed).
func TestObservedFixturesReproduceTheirRecordedHashes(t *testing.T) {
	obs := loadObserved(t)
	if obs.Schema != "keyvault-root-acl-qualification-created/1" || obs.State != "created" {
		t.Fatalf("unexpected record: %q %q", obs.Schema, obs.State)
	}
	hexObject := regexp.MustCompile(`^[0-9a-f]{40}$`)
	if !hexObject.MatchString(obs.Candidate.SourceHead) || !hexObject.MatchString(obs.Candidate.SourceTree) {
		t.Fatalf("source head or tree is not a git object name: %q %q", obs.Candidate.SourceHead, obs.Candidate.SourceTree)
	}
	for _, c := range []struct {
		name   string
		p      Projection
		sum    string
		length int
	}{{"before", obs.Before, obs.BeforeSHA256, 1437}, {"after", obs.After, obs.AfterSHA256, 2199}} {
		raw, err := EncodeNativeProjection(c.p)
		if err != nil || len(raw) != c.length {
			t.Fatalf("%s: %d bytes, %v", c.name, len(raw), err)
		}
		sum, err := ProjectionSHA256(c.p)
		if err != nil || sum != c.sum {
			t.Fatalf("%s: SHA-256 %s, recorded %s (%v)", c.name, sum, c.sum, err)
		}
		if _, err := DecodeNativeProjection(raw); err != nil {
			t.Fatalf("%s: the re-encoded frame does not decode: %v", c.name, err)
		}
	}
}

// Claim: the pinned partition description is the hex encoding of a property list
// whose only string is the team partition of the signing policy, and it is the
// description that both observed frames carry. The team comes from the signing
// policy package, not from the policy under test. Limit: it does not show that the
// operating system will keep emitting this document.
func TestPartitionDescriptionIsTheTeamPartitionList(t *testing.T) {
	raw, err := hex.DecodeString(policyPartitionDescription)
	if err != nil {
		t.Fatal(err)
	}
	document := string(raw)
	strs := regexp.MustCompile(`<string>([^<]*)</string>`).FindAllStringSubmatch(document, -1)
	if len(strs) != 1 || strs[0][1] != "teamid:"+codesignpolicy.Team || !strings.Contains(document, "<key>Partitions</key>") {
		t.Fatalf("the pinned description is not the team partition list: %q", document)
	}
	obs := loadObserved(t)
	for _, p := range []Projection{obs.Before, obs.After} {
		seen := 0
		for _, a := range p.ACLs {
			if len(a.AuthorizationNumbers) == 1 && a.AuthorizationNumbers[0] == numPartition {
				seen++
				if a.Description != policyPartitionDescription {
					t.Fatalf("an observed partition ACL carries another description: %q", a.Description)
				}
			}
		}
		if seen == 0 {
			t.Fatal("a frame has no partition ACL")
		}
	}
}

// Claim: the pinned requirement is the contract's vault requirement: the text is the
// designated requirement of the signing policy for the owning vault (minus its
// "designated =>" prefix), the compiled blob is a requirement blob that names the
// vault and not the helper, and the observed release ACL of both frames carries
// exactly these bytes and this text. Limit: the blob's meaning is checked by the
// native in-process test, not here.
func TestPinnedVaultRequirementIsTheContractRequirement(t *testing.T) {
	text, err := codesignpolicy.Requirement(codesignpolicy.Vault)
	if err != nil || !strings.HasPrefix(text, "designated => ") {
		t.Fatalf("the signing policy gave %q, %v", text, err)
	}
	if strings.TrimPrefix(text, "designated => ") != policyVaultRequirementText {
		t.Fatalf("the pinned text differs from the contract:\n%s\n%s", policyVaultRequirementText, text)
	}
	blob, err := hex.DecodeString(policyVaultRequirementHex)
	if err != nil || len(blob) < 8 || !bytes.Equal(blob[:4], []byte{0xfa, 0xde, 0x0c, 0x00}) {
		t.Fatalf("the pinned blob is not a requirement blob: %v", err)
	}
	if !bytes.Contains(blob, []byte("works.relux.keyvault")) || bytes.Contains(blob, []byte("enclave")) {
		t.Fatal("the pinned blob does not name exactly the vault")
	}
	obs := loadObserved(t)
	for _, p := range []Projection{obs.Before, obs.After} {
		a := acl(&p, numRelease)
		if len(a.Applications) != 1 || !bytes.Equal(a.Applications[0].Requirement, blob) || a.Applications[0].RequirementText != policyVaultRequirementText {
			t.Fatal("an observed release ACL does not carry the pinned requirement")
		}
	}
}

// Claim (positive controls): the predicate admits every form the pipeline emits:
// the observed intended frame through the intended entry point and the observed
// stored frame through the stored one, for the instance built with the marker's
// descriptor. The production instance admits the same two frames with the
// descriptor substituted. Limit: the production substitution is a PREDICTION from the
// marker's observation, not an observation of a production item; it is confirmed by
// the native in-process test (intended) and by the rehearsal (stored).
func TestPolicyAdmitsEveryObservedForm(t *testing.T) {
	obs := loadObserved(t)
	marker := newTestPolicy(t, markerDescriptor)
	if err := marker.AdmitIntended(obs.Before); err != nil {
		t.Fatalf("the observed intended form is refused: %v", err)
	}
	if err := marker.AdmitStored(obs.After); err != nil {
		t.Fatalf("the observed stored form is refused: %v", err)
	}
	production := newTestPolicy(t, productionDescriptor)
	predictedBefore := withDescriptor(t, obs.Before, markerDescriptor, productionDescriptor)
	predictedAfter := withDescriptor(t, obs.After, markerDescriptor, productionDescriptor)
	if err := production.AdmitIntended(predictedBefore); err != nil {
		t.Fatalf("the predicted production intended form is refused: %v", err)
	}
	if err := production.AdmitStored(predictedAfter); err != nil {
		t.Fatalf("the predicted production stored form is refused: %v", err)
	}
	// The descriptor binds each instance: the other instance's frame is refused for
	// the description, never admitted.
	requireRefusal(t, production.AdmitIntended(obs.Before), "intended", ReasonDescription)
	requireRefusal(t, production.AdmitStored(obs.After), "stored", ReasonDescription)
	requireRefusal(t, marker.AdmitIntended(predictedBefore), "intended", ReasonDescription)
	requireRefusal(t, marker.AdmitStored(predictedAfter), "stored", ReasonDescription)
}

func permutations(n int) [][]int {
	index := make([]int, n)
	for i := range index {
		index[i] = i
	}
	var out [][]int
	var generate func(k int)
	generate = func(k int) {
		if k == 1 {
			out = append(out, append([]int(nil), index...))
			return
		}
		generate(k - 1)
		for i := 0; i < k-1; i++ {
			if k%2 == 0 {
				index[i], index[k-1] = index[k-1], index[i]
			} else {
				index[0], index[k-1] = index[k-1], index[0]
			}
			generate(k - 1)
		}
	}
	generate(n)
	return out
}

// Claim: the predicate does not depend on the order in which the system lists the
// ACLs (two builds of the same access object list them differently): every
// permutation of both observed frames is admitted, and equivalent spellings of the
// same form are admitted too (reversed name and number lists, a nil instead of an
// empty list for an ACL with no application list, another well-formed Integrity
// description). The positive twin of the forbidden cases below. Limit: orders only,
// not forms.
func TestPolicyIsOrderIndependentAndAdmitsEquivalentSpellings(t *testing.T) {
	obs := loadObserved(t)
	marker := newTestPolicy(t, markerDescriptor)
	for _, kind := range []string{"before", "after"} {
		base := frameFor(obs, kind)
		for _, order := range permutations(len(base.ACLs)) {
			p := cloneProjection(t, base)
			for to, from := range order {
				p.ACLs[to] = copyACL(base.ACLs[from])
			}
			if err := admitFor(marker, kind, p); err != nil {
				t.Fatalf("%s frame in order %v is refused: %v", kind, order, err)
			}
		}
		spelled := cloneProjection(t, base)
		release := acl(&spelled, numRelease)
		for i, j := 0, len(release.Authorizations)-1; i < j; i, j = i+1, j-1 {
			release.Authorizations[i], release.Authorizations[j] = release.Authorizations[j], release.Authorizations[i]
			release.AuthorizationNumbers[i], release.AuthorizationNumbers[j] = release.AuthorizationNumbers[j], release.AuthorizationNumbers[i]
		}
		acl(&spelled, numEncrypt).Applications = nil
		if err := admitFor(marker, kind, spelled); err != nil {
			t.Fatalf("%s frame with equivalent spellings is refused: %v", kind, err)
		}
	}
	stored := cloneProjection(t, obs.After)
	acl(&stored, numIntegrity).Description = strings.Repeat("ab", 32)
	if err := marker.AdmitStored(stored); err != nil {
		t.Fatalf("another well-formed Integrity description is refused: %v", err)
	}
}

// Claim: the two forms are not interchangeable. The intended frame is refused by the
// stored entry point for the partition count, the stored frame is refused by the
// intended entry point for its Integrity authorization, and a nil policy refuses with
// the unavailable reason. A union of the two forms would pass neither of the first two.
func TestTheTwoFormsAreNotInterchangeable(t *testing.T) {
	obs := loadObserved(t)
	marker := newTestPolicy(t, markerDescriptor)
	requireRefusal(t, marker.AdmitStored(obs.Before), "stored", ReasonPartition)
	requireRefusal(t, marker.AdmitIntended(obs.After), "intended", ReasonAuthorizations)
	var none *StoragePolicy
	requireRefusal(t, none.AdmitIntended(obs.Before), "intended", ReasonUnavailable)
	requireRefusal(t, none.AdmitStored(obs.After), "stored", ReasonUnavailable)
	requireRefusal(t, marker.AdmitIntended(Projection{}), "intended", ReasonMultiplicity)
	requireRefusal(t, marker.AdmitStored(Projection{}), "stored", ReasonMultiplicity)
}

// Claim: a descriptor that cannot be an access-object description is refused when the
// policy is built, so no instance can be constructed with an empty, overlong,
// control-character or non-ASCII description; the two real descriptors build.
func TestPolicyDescriptorIsValidated(t *testing.T) {
	for _, bad := range []string{"", strings.Repeat("a", 129), "a\nb", "tab\there", "café", "\x7f"} {
		if _, err := NewStoragePolicy(bad); !errors.Is(err, ErrPolicyDescriptor) {
			t.Fatalf("descriptor %q built a policy: %v", bad, err)
		}
	}
	for _, good := range []string{markerDescriptor, productionDescriptor, strings.Repeat("a", 128)} {
		if _, err := NewStoragePolicy(good); err != nil {
			t.Fatalf("descriptor %q refused: %v", good, err)
		}
	}
}

// forbiddenCase is one deliberately wrong projection: the observed frame of the
// given kind with one edit, and the reason the predicate must give. frames says which
// frames the edit applies to ("before" uses the intended entry point, "after" the
// stored one).
type forbiddenCase struct {
	name   string
	frames []string
	reason PolicyReason
	edit   func(p *Projection)
}

var bothFrames = []string{"before", "after"}

func forbiddenCases(obs observedRecord) []forbiddenCase {
	helperApp := ApplicationProjection{RequirementState: "present", Requirement: []byte{1, 2, 3},
		RequirementText: `identifier "works.relux.keyvault.enclave" and anchor apple generic`}
	integrityOfStored := func() ACLProjection {
		p := obs.After
		return copyACL(*acl(&p, numIntegrity))
	}
	return []forbiddenCase{
		// Owner row.
		{"owner uid", bothFrames, ReasonOwner, func(p *Projection) { p.OwnerUID = 1 }},
		{"owner uid 501", bothFrames, ReasonOwner, func(p *Projection) { p.OwnerUID = 501 }},
		{"owner gid", bothFrames, ReasonOwner, func(p *Projection) { p.OwnerGID = 20 }},
		{"owner type", bothFrames, ReasonOwner, func(p *Projection) { p.OwnerType = 1 }},

		// The ACL set.
		{"extra Encrypt ACL", bothFrames, ReasonMultiplicity, func(p *Projection) { p.ACLs = append(p.ACLs, copyACL(*acl(p, numEncrypt))) }},
		{"extra release ACL", bothFrames, ReasonMultiplicity, func(p *Projection) { p.ACLs = append(p.ACLs, copyACL(*acl(p, numRelease))) }},
		{"extra ChangeACL ACL", bothFrames, ReasonMultiplicity, func(p *Projection) { p.ACLs = append(p.ACLs, copyACL(*acl(p, numChangeACL))) }},
		{"no Encrypt ACL", bothFrames, ReasonMultiplicity, func(p *Projection) { removeACL(p, numEncrypt) }},
		{"no ChangeACL ACL", bothFrames, ReasonMultiplicity, func(p *Projection) { removeACL(p, numChangeACL) }},
		{"no release ACL", bothFrames, ReasonMultiplicity, func(p *Projection) { removeACL(p, numRelease) }},
		{"ChangeACL replaced by a second Encrypt ACL", bothFrames, ReasonMultiplicity, func(p *Projection) {
			*acl(p, numChangeACL) = copyACL(*acl(p, numEncrypt))
		}},
		{"an ACL with no authorization at all", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numEncrypt)
			a.Authorizations, a.AuthorizationNumbers = []string{}, []uint32{}
		}},
		{"an Integrity ACL on the intended object", []string{"before"}, ReasonAuthorizations, func(p *Projection) {
			p.ACLs = append(p.ACLs, integrityOfStored())
		}},
		{"no Integrity ACL on the stored item", []string{"after"}, ReasonMultiplicity, func(p *Projection) { removeACL(p, numIntegrity) }},
		{"two Integrity ACLs on the stored item", []string{"after"}, ReasonMultiplicity, func(p *Projection) {
			p.ACLs = append(p.ACLs, copyACL(*acl(p, numIntegrity)))
		}},

		// Partition ACLs: exactly one in the intended object, exactly two in the stored item.
		{"no partition ACL", bothFrames, ReasonPartition, func(p *Projection) {
			for indexByNumber(p, numPartition) >= 0 {
				removeACL(p, numPartition)
			}
		}},
		{"one partition ACL fewer", bothFrames, ReasonPartition, func(p *Projection) { removeACL(p, numPartition) }},
		{"one partition ACL more", bothFrames, ReasonPartition, func(p *Projection) { p.ACLs = append(p.ACLs, copyACL(*acl(p, numPartition))) }},
		{"a partition ACL with another description", bothFrames, ReasonPartition, func(p *Projection) {
			acl(p, numPartition).Description = flipLastChar(acl(p, numPartition).Description)
		}},
		{"a partition ACL with the bare team string", bothFrames, ReasonPartition, func(p *Projection) {
			acl(p, numPartition).Description = "teamid:262RZ595FP"
		}},
		{"a partition ACL with an empty description", bothFrames, ReasonPartition, func(p *Projection) { acl(p, numPartition).Description = "" }},
		{"a partition ACL with a null description", bothFrames, ReasonPartition, func(p *Projection) {
			a := acl(p, numPartition)
			a.DescriptionState, a.Description = "null", ""
		}},
		{"a partition ACL with an unreadable description", bothFrames, ReasonPartition, func(p *Projection) {
			a := acl(p, numPartition)
			a.DescriptionState, a.Description = "unreadable", ""
		}},
		{"a partition ACL that names an application", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numPartition)
			a.ApplicationsState, a.Applications = "present", []ApplicationProjection{helperApp}
		}},
		{"a partition ACL with an empty application list", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numPartition)
			a.ApplicationsState, a.Applications = "present", []ApplicationProjection{}
		}},
		{"a partition authorization added to the release ACL", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numRelease)
			a.Authorizations = append(a.Authorizations, "ACLAuthorizationPartitionID")
			a.AuthorizationNumbers = append(a.AuthorizationNumbers, numPartition)
		}},

		// Authorizations.
		{"Encrypt ACL with another number", bothFrames, ReasonAuthorizations, func(p *Projection) { acl(p, numEncrypt).AuthorizationNumbers = []uint32{36} }},
		{"an allow-any ACL in place of Encrypt", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numEncrypt)
			a.Authorizations, a.AuthorizationNumbers = []string{"ACLAuthorizationAny"}, []uint32{4294967295}
		}},
		{"release ACL with an unknown number added", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numRelease)
			a.AuthorizationNumbers = append(a.AuthorizationNumbers, 999)
		}},
		{"release ACL without its last number", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numRelease)
			a.AuthorizationNumbers = a.AuthorizationNumbers[:len(a.AuthorizationNumbers)-1]
		}},
		{"release ACL with a number repeated in place of another", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numRelease)
			a.AuthorizationNumbers[2] = a.AuthorizationNumbers[0]
		}},
		{"release ACL with the any authorization named", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numRelease)
			a.Authorizations = append(a.Authorizations, "ACLAuthorizationAny")
		}},
		{"release ACL with a name changed", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numRelease)
			a.Authorizations[len(a.Authorizations)-1] += "X"
		}},
		{"Encrypt ACL with unreadable names", bothFrames, ReasonAuthorizations, func(p *Projection) {
			a := acl(p, numEncrypt)
			a.AuthorizationNamesState, a.Authorizations = "unreadable", []string{}
		}},

		// Contents and description.
		{"Encrypt ACL with unreadable contents", bothFrames, ReasonContents, func(p *Projection) { acl(p, numEncrypt).ContentsState = "unreadable" }},
		{"release ACL with unreadable contents", bothFrames, ReasonContents, func(p *Projection) { acl(p, numRelease).ContentsState = "unreadable" }},
		{"Encrypt ACL with a null description", bothFrames, ReasonDescription, func(p *Projection) {
			a := acl(p, numEncrypt)
			a.DescriptionState, a.Description = "null", ""
		}},
		{"release ACL with an unreadable description", bothFrames, ReasonDescription, func(p *Projection) {
			a := acl(p, numRelease)
			a.DescriptionState, a.Description = "unreadable", ""
		}},
		{"Encrypt ACL with another description", bothFrames, ReasonDescription, func(p *Projection) { acl(p, numEncrypt).Description = "Other descriptor" }},
		{"ChangeACL ACL with an empty description", bothFrames, ReasonDescription, func(p *Projection) { acl(p, numChangeACL).Description = "" }},
		{"release ACL with the other instance's descriptor", bothFrames, ReasonDescription, func(p *Projection) {
			acl(p, numRelease).Description = productionDescriptor
		}},
		{"Integrity description of 63 characters", []string{"after"}, ReasonDescription, func(p *Projection) {
			a := acl(p, numIntegrity)
			a.Description = a.Description[:63]
		}},
		{"Integrity description in capitals", []string{"after"}, ReasonDescription, func(p *Projection) {
			a := acl(p, numIntegrity)
			a.Description = strings.ToUpper(a.Description)
		}},
		{"Integrity description that is not hex", []string{"after"}, ReasonDescription, func(p *Projection) {
			acl(p, numIntegrity).Description = strings.Repeat("z", 64)
		}},
		{"Integrity description empty", []string{"after"}, ReasonDescription, func(p *Projection) { acl(p, numIntegrity).Description = "" }},
		{"Integrity description null", []string{"after"}, ReasonDescription, func(p *Projection) {
			a := acl(p, numIntegrity)
			a.DescriptionState, a.Description = "null", ""
		}},

		// Prompt behaviour.
		{"prompt bits set", bothFrames, ReasonPrompt, func(p *Projection) { acl(p, numEncrypt).PromptBits = 1 }},
		{"raw prompt unreadable", bothFrames, ReasonPrompt, func(p *Projection) {
			a := acl(p, numEncrypt)
			a.RawPromptState, a.RawPromptVersion, a.RawPromptFlags = "unreadable", 0, 0
		}},
		{"raw prompt version 1", bothFrames, ReasonPrompt, func(p *Projection) { acl(p, numEncrypt).RawPromptVersion = 1 }},
		{"raw prompt version 258 on the release ACL", bothFrames, ReasonPrompt, func(p *Projection) { acl(p, numRelease).RawPromptVersion = 258 }},
		{"raw prompt flags set", bothFrames, ReasonPrompt, func(p *Projection) { acl(p, numEncrypt).RawPromptFlags = 1 }},

		// Applications: only the vault may use the item.
		{"release ACL with no application restriction", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numRelease)
			a.ApplicationsState, a.Applications = "null", []ApplicationProjection{}
		}},
		{"release ACL with an empty application list", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numRelease)
			a.ApplicationsState, a.Applications = "present", []ApplicationProjection{}
		}},
		{"release ACL with an unreadable application list", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numRelease)
			a.ApplicationsState, a.Applications = "unreadable", []ApplicationProjection{}
		}},
		{"release ACL with the vault twice", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications = append(a.Applications, a.Applications[0])
		}},
		{"release ACL with the helper added", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications = append(a.Applications, helperApp)
		}},
		{"release ACL with the helper in place of the vault", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0] = helperApp
		}},
		{"release requirement naming the helper, bytes unchanged", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0].RequirementText = strings.Replace(a.Applications[0].RequirementText, `"works.relux.keyvault"`, `"works.relux.keyvault.enclave"`, 1)
		}},
		{"release requirement with a flipped byte", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0].Requirement[0] ^= 0xff
		}},
		{"release requirement truncated by one byte", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0].Requirement = a.Applications[0].Requirement[:len(a.Applications[0].Requirement)-1]
		}},
		{"release requirement widened by an or", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0].RequirementText += " or anchor apple"
		}},
		{"release requirement reduced to the team", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0].RequirementText = `anchor apple generic and certificate leaf[subject.OU] = "262RZ595FP"`
		}},
		{"release requirement missing", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0] = ApplicationProjection{RequirementState: "missing", Requirement: []byte{}}
		}},
		{"release requirement unreadable", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0] = ApplicationProjection{RequirementState: "unreadable", Requirement: []byte{}}
		}},
		{"release requirement of an unexpected type", bothFrames, ReasonRequirement, func(p *Projection) {
			a := acl(p, numRelease)
			a.Applications[0] = ApplicationProjection{RequirementState: "unexpected-type", Requirement: []byte{}}
		}},
		{"Encrypt ACL restricted to an application", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numEncrypt)
			a.ApplicationsState, a.Applications = "present", []ApplicationProjection{helperApp}
		}},
		{"Encrypt ACL with an unreadable application list", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numEncrypt)
			a.ApplicationsState, a.Applications = "unreadable", []ApplicationProjection{}
		}},
		{"ChangeACL ACL with no application list", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numChangeACL)
			a.ApplicationsState, a.Applications = "null", []ApplicationProjection{}
		}},
		{"ChangeACL ACL naming an application", bothFrames, ReasonApplications, func(p *Projection) {
			a := acl(p, numChangeACL)
			a.Applications = []ApplicationProjection{helperApp}
		}},
		{"Integrity ACL with an application list", []string{"after"}, ReasonApplications, func(p *Projection) {
			a := acl(p, numIntegrity)
			a.ApplicationsState, a.Applications = "present", []ApplicationProjection{}
		}},
	}
}

// Claim (forbidden forms, each with its own intended refusal): every deliberately
// wrong projection is refused, for the reason the case names and for the form that
// was asked, never merely "an error". Each case is the observed frame with exactly
// one edit, and the test checks that the edit changed something, so a case that
// silently edits nothing cannot pass. Limit: the cases are the ones listed; a form
// that no case reaches is covered only by the single-edit sweep below.
func TestPolicyRefusesEveryForbiddenForm(t *testing.T) {
	obs := loadObserved(t)
	marker := newTestPolicy(t, markerDescriptor)
	runs := 0
	seen := map[PolicyReason]bool{}
	for _, c := range forbiddenCases(obs) {
		for _, kind := range c.frames {
			base := frameFor(obs, kind)
			mutated := cloneProjection(t, base)
			c.edit(&mutated)
			before, _ := json.Marshal(base)
			after, _ := json.Marshal(mutated)
			if bytes.Equal(before, after) {
				t.Fatalf("%s (%s): the edit changed nothing", c.name, kind)
			}
			requireRefusal(t, admitFor(marker, kind, mutated), formName(kind), c.reason)
			seen[c.reason] = true
			runs++
		}
	}
	// The vocabulary is closed and every reason except "unavailable" (a nil policy,
	// tested above) is reached by at least one case.
	for _, reason := range []PolicyReason{ReasonOwner, ReasonAuthorizations, ReasonContents, ReasonDescription, ReasonPartition, ReasonPrompt, ReasonApplications, ReasonRequirement, ReasonMultiplicity} {
		if !seen[reason] {
			t.Fatalf("no forbidden case reaches the reason %q", reason)
		}
	}
	if runs < 100 {
		t.Fatalf("only %d forbidden runs", runs)
	}
	t.Logf("%d forbidden runs refused, each for its named reason", runs)
}

// Plants for the instrument controls: wrong implementations that the harness has to
// catch. A union of the two forms and an implementation that admits or refuses
// everything are the failure directions the tests must not let through.
type admitAllPolicy struct{}

func (admitAllPolicy) AdmitIntended(Projection) error { return nil }
func (admitAllPolicy) AdmitStored(Projection) error   { return nil }

type rejectAllPolicy struct{}

func (rejectAllPolicy) AdmitIntended(Projection) error { return ErrPolicyRefused }
func (rejectAllPolicy) AdmitStored(Projection) error   { return ErrPolicyRefused }

type unionPolicy struct{ real *StoragePolicy }

func (u unionPolicy) AdmitIntended(p Projection) error {
	if u.real.AdmitIntended(p) == nil || u.real.AdmitStored(p) == nil {
		return nil
	}
	return ErrPolicyRefused
}
func (u unionPolicy) AdmitStored(p Projection) error { return u.AdmitIntended(p) }

// scorePolicy runs the whole harness against one implementation: how many observed
// forms it refuses (positive controls) and how many forbidden forms it admits.
func scorePolicy(t testing.TB, obs observedRecord, policy storagePolicy) (missedPositives, admittedForbidden, forbiddenRuns int) {
	t.Helper()
	if policy.AdmitIntended(obs.Before) != nil {
		missedPositives++
	}
	if policy.AdmitStored(obs.After) != nil {
		missedPositives++
	}
	for _, c := range forbiddenCases(obs) {
		for _, kind := range c.frames {
			mutated := cloneProjection(t, frameFor(obs, kind))
			c.edit(&mutated)
			forbiddenRuns++
			if admitFor(policy, kind, mutated) == nil {
				admittedForbidden++
			}
		}
	}
	// The other form's frame offered to each entry point.
	forbiddenRuns += 2
	if policy.AdmitStored(obs.Before) == nil {
		admittedForbidden++
	}
	if policy.AdmitIntended(obs.After) == nil {
		admittedForbidden++
	}
	return missedPositives, admittedForbidden, forbiddenRuns
}

// Claim (instrument controls): the harness detects the wrong implementations it
// exists to detect. The real predicate scores zero on both counts. An admit-all plant
// is caught by every forbidden run. A reject-all plant is caught by both positive
// controls. A union of the two forms is caught by the cross-form runs. A harness that
// let any of these through would prove nothing about the predicate.
func TestHarnessDetectsPlantedWrongImplementations(t *testing.T) {
	obs := loadObserved(t)
	actual := newTestPolicy(t, markerDescriptor)
	if missed, admitted, _ := scorePolicy(t, obs, actual); missed != 0 || admitted != 0 {
		t.Fatalf("the real predicate scores %d missed positives and %d admitted forbidden forms", missed, admitted)
	}
	missed, admitted, runs := scorePolicy(t, obs, admitAllPolicy{})
	if missed != 0 || admitted != runs {
		t.Fatalf("admit-all plant: %d missed positives, %d of %d forbidden runs admitted", missed, admitted, runs)
	}
	missed, admitted, _ = scorePolicy(t, obs, rejectAllPolicy{})
	if missed != 2 || admitted != 0 {
		t.Fatalf("reject-all plant: %d missed positives, %d admitted", missed, admitted)
	}
	missed, admitted, _ = scorePolicy(t, obs, unionPolicy{real: actual})
	if missed != 0 || admitted < 2 {
		t.Fatalf("union plant: %d missed positives, %d admitted (the cross-form runs must catch it)", missed, admitted)
	}
}

// The contract's own predicates, written from what the native bindings enforce and
// what the signing policy states, and NOT from the policy's table: every ACL state
// readable; no allow-any authorization; any ACL that grants a release-class
// authorization names exactly one application and it is the vault's requirement;
// no application is the helper or the foreign executable; every partition ACL carries
// exactly the team partition list; one partition ACL in the intended object, one or
// two in the stored item.
func contractViolation(p Projection, vaultText string, stored bool) string {
	releaseNames := map[string]bool{"ACLAuthorizationDecrypt": true, "ACLAuthorizationDerive": true, "ACLAuthorizationExportClear": true,
		"ACLAuthorizationExportWrapped": true, "ACLAuthorizationMAC": true, "ACLAuthorizationSign": true}
	team := regexp.MustCompile(`<string>([^<]*)</string>`)
	partitions := 0
	for _, a := range p.ACLs {
		if a.AuthorizationNamesState != "readable" || a.ContentsState != "readable" || a.DescriptionState != "present" || a.RawPromptState != "readable" {
			return "an unreadable or absent state"
		}
		release, partition := false, false
		for _, n := range a.Authorizations {
			if n == "ACLAuthorizationAny" {
				return "an allow-any authorization"
			}
			if releaseNames[n] {
				release = true
			}
			if n == "ACLAuthorizationPartitionID" {
				partition = true
			}
		}
		if release {
			if a.ApplicationsState != "present" || len(a.Applications) != 1 {
				return "a release ACL without exactly one application"
			}
			app := a.Applications[0]
			if app.RequirementState != "present" || app.RequirementText != vaultText {
				return "a release application that is not the vault requirement"
			}
		}
		for _, app := range a.Applications {
			if strings.Contains(app.RequirementText, "enclave") || strings.Contains(app.RequirementText, "qualification-foreign") {
				return "the helper or the foreign executable admitted"
			}
		}
		if partition {
			if len(a.Authorizations) != 1 {
				return "a partition authorization mixed with others"
			}
			partitions++
			raw, err := hex.DecodeString(a.Description)
			if err != nil {
				return "a partition description that is not hex"
			}
			found := team.FindAllStringSubmatch(string(raw), -1)
			if len(found) != 1 || found[0][1] != "teamid:"+codesignpolicy.Team {
				return "a partition description that is not exactly the team partition"
			}
		}
	}
	if partitions < 1 || partitions > 2 || (!stored && partitions != 1) {
		return "the number of partition ACLs"
	}
	return ""
}

func contractVaultText(t testing.TB) string {
	t.Helper()
	text, err := codesignpolicy.Requirement(codesignpolicy.Vault)
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimPrefix(text, "designated => ")
}

type singleEdit struct {
	name       string
	equivalent bool
	projection Projection
}

// singleEdits is a broad, mechanical sweep: every owner field, every ACL dropped or
// duplicated, and every field of every ACL changed in several ways, one edit at a time,
// plus the equivalent respellings that must stay admitted.
func singleEdits(t testing.TB, base Projection) []singleEdit {
	t.Helper()
	var out []singleEdit
	add := func(name string, equivalent bool, f func(p *Projection)) {
		p := cloneProjection(t, base)
		f(&p)
		out = append(out, singleEdit{name: name, equivalent: equivalent, projection: p})
	}
	add("identity", true, func(p *Projection) {})
	add("owner uid + 1", false, func(p *Projection) { p.OwnerUID++ })
	add("owner gid + 1", false, func(p *Projection) { p.OwnerGID++ })
	add("owner type + 1", false, func(p *Projection) { p.OwnerType++ })
	add("reverse the ACL order", true, func(p *Projection) {
		for i, j := 0, len(p.ACLs)-1; i < j; i, j = i+1, j-1 {
			p.ACLs[i], p.ACLs[j] = p.ACLs[j], p.ACLs[i]
		}
	})
	for i := range base.ACLs {
		i := i
		tag := fmt.Sprintf("acl %d: ", i)
		a := base.ACLs[i]
		add(tag+"drop", false, func(p *Projection) { p.ACLs = append(p.ACLs[:i], p.ACLs[i+1:]...) })
		add(tag+"duplicate", false, func(p *Projection) { p.ACLs = append(p.ACLs, copyACL(p.ACLs[i])) })
		add(tag+"names unreadable", false, func(p *Projection) {
			p.ACLs[i].AuthorizationNamesState, p.ACLs[i].Authorizations = "unreadable", []string{}
		})
		for j := range a.Authorizations {
			j := j
			add(fmt.Sprintf("%sdrop name %d", tag, j), false, func(p *Projection) {
				p.ACLs[i].Authorizations = append(p.ACLs[i].Authorizations[:j], p.ACLs[i].Authorizations[j+1:]...)
			})
		}
		add(tag+"add the any name", false, func(p *Projection) {
			p.ACLs[i].Authorizations = append(p.ACLs[i].Authorizations, "ACLAuthorizationAny")
		})
		add(tag+"add an unknown name", false, func(p *Projection) { p.ACLs[i].Authorizations = append(p.ACLs[i].Authorizations, "X") })
		for j := range a.AuthorizationNumbers {
			j := j
			add(fmt.Sprintf("%sdrop number %d", tag, j), false, func(p *Projection) {
				p.ACLs[i].AuthorizationNumbers = append(p.ACLs[i].AuthorizationNumbers[:j], p.ACLs[i].AuthorizationNumbers[j+1:]...)
			})
			add(fmt.Sprintf("%snumber %d + 1", tag, j), false, func(p *Projection) { p.ACLs[i].AuthorizationNumbers[j]++ })
		}
		add(tag+"add number 1", false, func(p *Projection) { p.ACLs[i].AuthorizationNumbers = append(p.ACLs[i].AuthorizationNumbers, 1) })
		add(tag+"add number 0xffffffff", false, func(p *Projection) {
			p.ACLs[i].AuthorizationNumbers = append(p.ACLs[i].AuthorizationNumbers, 0xffffffff)
		})
		add(tag+"contents unreadable", false, func(p *Projection) { p.ACLs[i].ContentsState = "unreadable" })
		add(tag+"description null", false, func(p *Projection) { p.ACLs[i].DescriptionState, p.ACLs[i].Description = "null", "" })
		add(tag+"description unreadable", false, func(p *Projection) { p.ACLs[i].DescriptionState, p.ACLs[i].Description = "unreadable", "" })
		for _, value := range []string{"", "x", markerDescriptor + " ", productionDescriptor, strings.ToUpper(a.Description), flipLastChar(a.Description)} {
			value := value
			add(fmt.Sprintf("%sdescription %q", tag, value), false, func(p *Projection) { p.ACLs[i].Description = value })
		}
		add(tag+"prompt bits 1", false, func(p *Projection) { p.ACLs[i].PromptBits = 1 })
		add(tag+"raw prompt unreadable", false, func(p *Projection) {
			p.ACLs[i].RawPromptState, p.ACLs[i].RawPromptVersion, p.ACLs[i].RawPromptFlags = "unreadable", 0, 0
		})
		add(tag+"raw prompt version + 1", false, func(p *Projection) { p.ACLs[i].RawPromptVersion++ })
		add(tag+"raw prompt flags + 1", false, func(p *Projection) { p.ACLs[i].RawPromptFlags++ })
		for _, state := range []string{"null", "present", "unreadable"} {
			state := state
			add(tag+"applications "+state, false, func(p *Projection) {
				p.ACLs[i].ApplicationsState, p.ACLs[i].Applications = state, []ApplicationProjection{}
			})
		}
		add(tag+"an extra helper application", false, func(p *Projection) {
			p.ACLs[i].ApplicationsState = "present"
			p.ACLs[i].Applications = append(p.ACLs[i].Applications, ApplicationProjection{RequirementState: "present", Requirement: []byte{9},
				RequirementText: `identifier "works.relux.keyvault.enclave"`})
		})
		for j := range a.Applications {
			j := j
			add(fmt.Sprintf("%sdrop application %d", tag, j), false, func(p *Projection) {
				p.ACLs[i].Applications = append(p.ACLs[i].Applications[:j], p.ACLs[i].Applications[j+1:]...)
			})
			add(fmt.Sprintf("%sduplicate application %d", tag, j), false, func(p *Projection) {
				p.ACLs[i].Applications = append(p.ACLs[i].Applications, p.ACLs[i].Applications[j])
			})
			for _, state := range []string{"missing", "unreadable", "unexpected-type"} {
				state := state
				add(fmt.Sprintf("%sapplication %d %s", tag, j, state), false, func(p *Projection) {
					p.ACLs[i].Applications[j] = ApplicationProjection{RequirementState: state, Requirement: []byte{}}
				})
			}
			add(fmt.Sprintf("%sapplication %d flipped byte", tag, j), false, func(p *Projection) { p.ACLs[i].Applications[j].Requirement[0] ^= 0xff })
			add(fmt.Sprintf("%sapplication %d text widened", tag, j), false, func(p *Projection) { p.ACLs[i].Applications[j].RequirementText += " or anchor apple" })
			add(fmt.Sprintf("%sapplication %d helper text", tag, j), false, func(p *Projection) {
				p.ACLs[i].Applications[j].RequirementText = strings.Replace(p.ACLs[i].Applications[j].RequirementText, `"works.relux.keyvault"`, `"works.relux.keyvault.enclave"`, 1)
			})
		}
		if len(a.AuthorizationNumbers) == 1 && a.AuthorizationNumbers[0] == numIntegrity {
			add(tag+"another well-formed Integrity description", true, func(p *Projection) { p.ACLs[i].Description = strings.Repeat("0f", 32) })
		}
	}
	return out
}

// Claim (closedness, checked against two oracles that are not the policy's table):
// for every single edit of an observed frame, offered to both entry points, the
// predicate either refuses it or the edit is an equivalent respelling of the observed
// form. Whatever it admits (a) satisfies the contract predicates written above and
// (b) equals the observed frame once ACL order and the Integrity description are
// normalized. A frame of the other form is never admitted by a single edit. The
// equivalent respellings are positive controls: all of them must be admitted, so a
// predicate that refuses everything fails here too. Limit: single edits only; the
// forbidden cases above cover chosen combinations.
func TestEverySingleEditIsRefusedOrEquivalent(t *testing.T) {
	obs := loadObserved(t)
	marker := newTestPolicy(t, markerDescriptor)
	vaultText := contractVaultText(t)
	total, admitted, equivalents := 0, 0, 0
	for _, kind := range []string{"before", "after"} {
		base := frameFor(obs, kind)
		baseCanonical := canonicalJSON(t, base)
		for _, edit := range singleEdits(t, base) {
			total++
			for _, entry := range []string{"before", "after"} {
				err := admitFor(marker, entry, edit.projection)
				if edit.equivalent && entry == kind {
					equivalents++
					if err != nil {
						t.Fatalf("%s frame, %q: an equivalent respelling is refused: %v", kind, edit.name, err)
					}
				}
				if err != nil {
					continue
				}
				admitted++
				if entry != kind {
					t.Fatalf("%s frame, %q: admitted by the %s entry point", kind, edit.name, formName(entry))
				}
				if violation := contractViolation(edit.projection, vaultText, entry == "after"); violation != "" {
					t.Fatalf("%s frame, %q: admitted although it has %s", kind, edit.name, violation)
				}
				if canonicalJSON(t, edit.projection) != baseCanonical {
					t.Fatalf("%s frame, %q: admitted but it is not the observed form", kind, edit.name)
				}
			}
		}
	}
	if total < 250 || equivalents < 4 || admitted < equivalents {
		t.Fatalf("the sweep is too small to mean anything: %d edits, %d admitted, %d equivalents", total, admitted, equivalents)
	}
	t.Logf("%d single edits; %d admitted, all equivalent to the observed form", total, admitted)
}

// Fuzzing the decoder and the predicate together: for any bytes that decode as a
// KVQP1 frame, neither entry point panics, the answer is stable, and a frame that is
// admitted satisfies the contract predicates. The seed corpus is the two observed
// frames, which also run as ordinary tests.
func FuzzPolicyAdmit(f *testing.F) {
	obs := loadObserved(f)
	for _, p := range []Projection{obs.Before, obs.After} {
		raw, err := EncodeNativeProjection(p)
		if err != nil {
			f.Fatal(err)
		}
		f.Add(raw)
	}
	marker := newTestPolicy(f, markerDescriptor)
	vaultText := contractVaultText(f)
	f.Fuzz(func(t *testing.T, raw []byte) {
		p, err := DecodeNativeProjection(raw)
		if err != nil {
			return
		}
		for _, stored := range []bool{false, true} {
			var first, second error
			if stored {
				first, second = marker.AdmitStored(p), marker.AdmitStored(p)
			} else {
				first, second = marker.AdmitIntended(p), marker.AdmitIntended(p)
			}
			if (first == nil) != (second == nil) {
				t.Fatal("the answer is not stable")
			}
			if first == nil {
				if violation := contractViolation(p, vaultText, stored); violation != "" {
					t.Fatalf("admitted although it has %s", violation)
				}
			}
		}
	})
}

// Claim (regression, review blocker): a policy that was not built by NewStoragePolicy
// refuses the empty projection at both entry points with the closed "unavailable"
// reason, before any matching. The zero value has owner row 0, 0, 0 and no required
// entries, so without the check the empty ACL set (which the decoder can represent)
// matches it vacuously and is admitted. A policy built by the constructor still
// refuses the empty projection, for the real reason (a missing required ACL), so the
// two refusals are not confused. Limit: it covers the in-package ways to build an
// unusable value, not memory corruption.
func TestZeroValuePolicyRefusesTheEmptyProjectionAtBothEntryPoints(t *testing.T) {
	var zero StoragePolicy
	requireRefusal(t, zero.AdmitIntended(Projection{}), "intended", ReasonUnavailable)
	requireRefusal(t, zero.AdmitStored(Projection{}), "stored", ReasonUnavailable)
	requireRefusal(t, (&zero).AdmitIntended(Projection{}), "intended", ReasonUnavailable)
	requireRefusal(t, (&zero).AdmitStored(Projection{}), "stored", ReasonUnavailable)
	built := newTestPolicy(t, markerDescriptor)
	requireRefusal(t, built.AdmitIntended(Projection{}), "intended", ReasonMultiplicity)
	requireRefusal(t, built.AdmitStored(Projection{}), "stored", ReasonMultiplicity)
}

// Claim (regression, review blocker): the zero-value policy refuses the observed forms
// too, at both entry points and in both directions (each frame through each entry
// point), so an uninitialized policy cannot admit the real intended or stored frame
// either. Positive control: a constructed policy still admits the observed intended
// frame through the intended entry point and the stored frame through the stored one.
func TestZeroValuePolicyRefusesTheObservedFormsAtBothEntryPoints(t *testing.T) {
	obs := loadObserved(t)
	var zero StoragePolicy
	for _, frame := range []struct {
		name string
		p    Projection
	}{{"observed intended frame", obs.Before}, {"observed stored frame", obs.After}} {
		requireRefusal(t, zero.AdmitIntended(frame.p), "intended", ReasonUnavailable)
		requireRefusal(t, zero.AdmitStored(frame.p), "stored", ReasonUnavailable)
	}
	built := newTestPolicy(t, markerDescriptor)
	if err := built.AdmitIntended(obs.Before); err != nil {
		t.Fatalf("the constructed policy refuses the observed intended frame: %v", err)
	}
	if err := built.AdmitStored(obs.After); err != nil {
		t.Fatalf("the constructed policy refuses the observed stored frame: %v", err)
	}
}

// Claim (regression, review blocker): a partly filled policy is unusable too: each
// struct that lacks the descriptor, the requirement, the intended form or the stored
// form refuses the empty projection and both observed frames at both entry points as
// "unavailable". A policy that is usable for one form only is not trusted for either.
func TestPartlyBuiltPolicyRefusesEverythingAtBothEntryPoints(t *testing.T) {
	obs := loadObserved(t)
	good := newTestPolicy(t, markerDescriptor)
	for _, c := range []struct {
		name   string
		policy *StoragePolicy
	}{
		{"descriptor only", &StoragePolicy{descriptor: markerDescriptor}},
		{"descriptor and requirement only", &StoragePolicy{descriptor: markerDescriptor, requirement: good.requirement}},
		{"intended form only", &StoragePolicy{descriptor: markerDescriptor, requirement: good.requirement, intended: good.intended}},
		{"stored form only", &StoragePolicy{descriptor: markerDescriptor, requirement: good.requirement, stored: good.stored}},
		{"forms without a descriptor", &StoragePolicy{requirement: good.requirement, intended: good.intended, stored: good.stored}},
		{"forms without a requirement", &StoragePolicy{descriptor: markerDescriptor, intended: good.intended, stored: good.stored}},
	} {
		for _, p := range []Projection{{}, obs.Before, obs.After} {
			if err := c.policy.AdmitIntended(p); err == nil {
				t.Fatalf("%s: admitted at the intended entry point", c.name)
			}
			requireRefusal(t, c.policy.AdmitIntended(p), "intended", ReasonUnavailable)
			requireRefusal(t, c.policy.AdmitStored(p), "stored", ReasonUnavailable)
		}
	}
}
