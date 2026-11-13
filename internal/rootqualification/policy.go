package rootqualification

import (
	"bytes"
	"encoding/hex"
	"errors"
	"sort"
)

// The owner and writer admission predicate for a root-storage item.
//
// It is a positive allowlist derived from forms that the attended native
// qualification actually observed (testdata/observed, recorded on macOS 26.5.1,
// arm64, for the public-marker item created by the signed build at source head
// c2a03e7f9797ef0d4e817fc7f4a6fb44461f55d1). Nothing else is admitted, nothing is
// learned at run time, and a form that was not observed is refused. A different
// macOS version may emit other forms; the predicate then refuses until the table
// is extended from new evidence and reviewed.
//
// Two forms exist because the object that is built in memory and the item that the
// Keychain stores are not the same ACL set: the Keychain adds an Integrity ACL and a
// second partition ACL and reorders them. They are admitted separately, through two
// entry points, and never as a union.

// ErrPolicyRefused is matched by every refusal of the predicate.
var ErrPolicyRefused = errors.New("root storage ACL policy refused")

// ErrPolicyDescriptor refuses a descriptor that cannot be an access-object description.
var ErrPolicyDescriptor = errors.New("root storage ACL policy descriptor refused")

var errPolicyTable = errors.New("root storage ACL policy table is unusable")

// PolicyReason is the closed vocabulary of refusals; a test asserts the intended
// reason, not merely an error.
type PolicyReason string

const (
	// ReasonUnavailable is the refusal of a nil or uninitialized policy.
	ReasonUnavailable    PolicyReason = "unavailable"
	ReasonOwner          PolicyReason = "owner"
	ReasonAuthorizations PolicyReason = "authorizations"
	ReasonContents       PolicyReason = "contents"
	ReasonDescription    PolicyReason = "description"
	ReasonPartition      PolicyReason = "partition"
	ReasonPrompt         PolicyReason = "prompt"
	ReasonApplications   PolicyReason = "applications"
	ReasonRequirement    PolicyReason = "requirement"
	ReasonMultiplicity   PolicyReason = "multiplicity"
)

// PolicyError is the refusal: which form was asked and the first reason.
type PolicyError struct {
	Form   string
	Reason PolicyReason
}

func (e *PolicyError) Error() string {
	return "root storage ACL policy refused: " + e.Form + " form, " + string(e.Reason)
}

func (e *PolicyError) Is(target error) bool { return target == ErrPolicyRefused }

// Observed values. The partition description is the hex encoding of the property
// list whose only entry is the team partition (the policy tests decode it and check
// the team id). The requirement is the compiled designated requirement of the
// owning vault, as bytes and as text.
const (
	policyPromptBits    uint32 = 0
	policyPromptVersion uint32 = 257
	policyPromptFlags   uint32 = 0

	policyVaultRequirementText = `identifier "works.relux.keyvault" and anchor apple generic and certificate leaf = H"d71190abe54185f908169ee9ca538d4066942c0f" and certificate 1[field.1.2.840.113635.100.6.2.1] /* exists */`
	policyVaultRequirementHex  = "fade0c0000000074000000010000000600000006000000060000000200000014776f726b732e72656c75782e6b65797661756c740000000f000000040000000000000014d71190abe54185f908169ee9ca538d4066942c0f0000000e000000010000000a2a864886f76364060201000000000000"
	policyPartitionDescription = "3c3f786d6c2076657273696f6e3d22312e302220656e636f64696e673d225554462d38223f3e0a3c21444f435459504520706c697374205055424c494320222d2f2f4170706c652f2f44544420504c49535420312e302f2f454e222022687474703a2f2f7777772e6170706c652e636f6d2f445444732f50726f70657274794c6973742d312e302e647464223e0a3c706c6973742076657273696f6e3d22312e30223e0a3c646963743e0a093c6b65793e506172746974696f6e733c2f6b65793e0a093c61727261793e0a09093c737472696e673e7465616d69643a323632525a35393546503c2f737472696e673e0a093c2f61727261793e0a3c2f646963743e0a3c2f706c6973743e0a"
)

type policyDescription uint8

const (
	describedByDescriptor policyDescription = iota + 1
	describedAsPartition
	describedAsHash
)

type policyApplications uint8

const (
	applicationsNull policyApplications = iota + 1
	applicationsEmpty
	applicationsVault
)

// policyShape is one admitted ACL: its authorization set, how its description is
// bound, and which application list it carries.
type policyShape struct {
	names        []string
	numbers      []uint32
	description  policyDescription
	applications policyApplications
}

type policyEntry struct {
	shape    policyShape
	min, max int
}

// policyForm is one admitted form. ownerRow is the owner triple (uid, gid, type) that
// the access object's ACL projection reports, a system-reported value observed as
// 0, 0, 0 in both forms; it is not the identity of any account.
type policyForm struct {
	name     string
	ownerRow [3]uint32
	entries  []policyEntry
}

// StoragePolicy is immutable after construction.
type StoragePolicy struct {
	descriptor  string
	requirement []byte
	intended    policyForm
	stored      policyForm
}

func newPolicyShape(names []string, numbers []uint32, description policyDescription, applications policyApplications) policyShape {
	n := append([]string(nil), names...)
	sort.Strings(n)
	u := append([]uint32(nil), numbers...)
	sort.Slice(u, func(i, j int) bool { return u[i] < u[j] })
	return policyShape{names: n, numbers: u, description: description, applications: applications}
}

// NewStoragePolicy builds the predicate for access objects whose non-partition ACLs
// carry the given description. The production descriptor and the public-marker
// descriptor are two instances of the same predicate.
func NewStoragePolicy(descriptor string) (*StoragePolicy, error) {
	if len(descriptor) == 0 || len(descriptor) > 128 {
		return nil, ErrPolicyDescriptor
	}
	for i := 0; i < len(descriptor); i++ {
		if descriptor[i] < 0x20 || descriptor[i] > 0x7e {
			return nil, ErrPolicyDescriptor
		}
	}
	requirement, err := hex.DecodeString(policyVaultRequirementHex)
	if err != nil || len(requirement) == 0 || policyVaultRequirementText == "" {
		return nil, errPolicyTable
	}
	encrypt := newPolicyShape([]string{"ACLAuthorizationEncrypt"}, []uint32{35}, describedByDescriptor, applicationsNull)
	change := newPolicyShape([]string{"ACLAuthorizationChangeACL"}, []uint32{65536}, describedByDescriptor, applicationsEmpty)
	release := newPolicyShape([]string{"ACLAuthorizationDecrypt", "ACLAuthorizationDerive", "ACLAuthorizationExportClear",
		"ACLAuthorizationExportWrapped", "ACLAuthorizationMAC", "ACLAuthorizationSign"}, []uint32{24, 28, 37, 38, 59, 115}, describedByDescriptor, applicationsVault)
	partition := newPolicyShape([]string{"ACLAuthorizationPartitionID"}, []uint32{65538}, describedAsPartition, applicationsNull)
	integrity := newPolicyShape([]string{"ACLAuthorizationIntegrity"}, []uint32{65539}, describedAsHash, applicationsNull)
	return &StoragePolicy{
		descriptor:  descriptor,
		requirement: requirement,
		// The object as built in memory: four ACLs, one partition ACL.
		intended: policyForm{name: "intended", ownerRow: [3]uint32{0, 0, 0}, entries: []policyEntry{
			{encrypt, 1, 1}, {change, 1, 1}, {release, 1, 1}, {partition, 1, 1},
		}},
		// The item as the Keychain stores it: six ACLs, an Integrity ACL, and the
		// partition ACL twice (both occurrences identical).
		stored: policyForm{name: "stored", ownerRow: [3]uint32{0, 0, 0}, entries: []policyEntry{
			{encrypt, 1, 1}, {change, 1, 1}, {release, 1, 1}, {partition, 2, 2}, {integrity, 1, 1},
		}},
	}, nil
}

// usable reports whether the policy was built by NewStoragePolicy. A nil pointer, the
// zero value or a partly filled struct has no required entries, so matching against
// it would admit the empty ACL set (which the decoder can represent) and every
// observed form vacuously. Such a policy is refused before any matching.
func (p *StoragePolicy) usable() bool {
	return p != nil && p.descriptor != "" && len(p.requirement) > 0 &&
		len(p.intended.entries) > 0 && len(p.stored.entries) > 0
}

// AdmitIntended admits the projection of the access object built in memory before
// the add. Nil only for the observed intended form, and only from a policy built by
// NewStoragePolicy: an uninitialized policy refuses everything as unavailable.
func (p *StoragePolicy) AdmitIntended(projection Projection) error {
	if !p.usable() {
		return &PolicyError{Form: "intended", Reason: ReasonUnavailable}
	}
	return p.admit(&p.intended, projection)
}

// AdmitStored admits the projection of the stored item's ACL read back from the
// Keychain. Nil only for the observed stored form, and only from a policy built by
// NewStoragePolicy: an uninitialized policy refuses everything as unavailable.
func (p *StoragePolicy) AdmitStored(projection Projection) error {
	if !p.usable() {
		return &PolicyError{Form: "stored", Reason: ReasonUnavailable}
	}
	return p.admit(&p.stored, projection)
}

func (p *StoragePolicy) admit(form *policyForm, projection Projection) error {
	refuse := func(reason PolicyReason) error { return &PolicyError{Form: form.name, Reason: reason} }
	if projection.OwnerUID != form.ownerRow[0] || projection.OwnerGID != form.ownerRow[1] || projection.OwnerType != form.ownerRow[2] {
		return refuse(ReasonOwner)
	}
	counts := make([]int, len(form.entries))
	for i := range projection.ACLs {
		index, reason := p.match(form, &projection.ACLs[i])
		if reason != "" {
			return refuse(reason)
		}
		counts[index]++
	}
	for i, entry := range form.entries {
		if counts[i] < entry.min || counts[i] > entry.max {
			if entry.shape.description == describedAsPartition {
				return refuse(ReasonPartition)
			}
			return refuse(ReasonMultiplicity)
		}
	}
	return nil
}

func equalNumbers(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalNames(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func lowerHexOfLength(s string, n int) bool {
	if len(s) != n {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// match finds the entry whose authorization set equals the ACL's and checks every
// other field against it. The authorization numbers are the key; the names are a
// readable cross-check and must agree.
func (p *StoragePolicy) match(form *policyForm, acl *ACLProjection) (int, PolicyReason) {
	numbers := append([]uint32(nil), acl.AuthorizationNumbers...)
	sort.Slice(numbers, func(i, j int) bool { return numbers[i] < numbers[j] })
	index := -1
	for i := range form.entries {
		if equalNumbers(form.entries[i].shape.numbers, numbers) {
			index = i
			break
		}
	}
	if index < 0 {
		return 0, ReasonAuthorizations
	}
	shape := &form.entries[index].shape
	if acl.AuthorizationNamesState != "readable" {
		return index, ReasonAuthorizations
	}
	names := append([]string(nil), acl.Authorizations...)
	sort.Strings(names)
	if !equalNames(shape.names, names) {
		return index, ReasonAuthorizations
	}
	if acl.ContentsState != "readable" {
		return index, ReasonContents
	}
	descriptionReason := ReasonDescription
	if shape.description == describedAsPartition {
		descriptionReason = ReasonPartition
	}
	if acl.DescriptionState != "present" {
		return index, descriptionReason
	}
	switch shape.description {
	case describedByDescriptor:
		if acl.Description != p.descriptor {
			return index, descriptionReason
		}
	case describedAsPartition:
		if acl.Description != policyPartitionDescription {
			return index, descriptionReason
		}
	case describedAsHash:
		if !lowerHexOfLength(acl.Description, 64) {
			return index, descriptionReason
		}
	default:
		return index, descriptionReason
	}
	if acl.PromptBits != policyPromptBits || acl.RawPromptState != "readable" ||
		acl.RawPromptVersion != policyPromptVersion || acl.RawPromptFlags != policyPromptFlags {
		return index, ReasonPrompt
	}
	return index, p.applicationsReason(shape.applications, acl)
}

func (p *StoragePolicy) applicationsReason(kind policyApplications, acl *ACLProjection) PolicyReason {
	switch kind {
	case applicationsNull:
		if acl.ApplicationsState != "null" || len(acl.Applications) != 0 {
			return ReasonApplications
		}
	case applicationsEmpty:
		if acl.ApplicationsState != "present" || len(acl.Applications) != 0 {
			return ReasonApplications
		}
	case applicationsVault:
		if acl.ApplicationsState != "present" || len(acl.Applications) != 1 {
			return ReasonApplications
		}
		app := &acl.Applications[0]
		if app.RequirementState != "present" || !bytes.Equal(app.Requirement, p.requirement) || app.RequirementText != policyVaultRequirementText {
			return ReasonRequirement
		}
	default:
		return ReasonApplications
	}
	return ""
}
