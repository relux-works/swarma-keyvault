package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type rootGrantsTrustGrantFixture struct {
	grant          RootGrantsGrantV3
	grantBytes     []byte
	contract       RootGrantsTrustContract
	contractBytes  []byte
	authority      rootGrantsTrustAuthorityV2
	authorityBytes []byte
	metadata       []byte
	owner          string
	at             time.Time
}

func rootGrantsTrustGrantV3Fixture(t *testing.T, notBefore int64) rootGrantsTrustGrantFixture {
	t.Helper()
	f := grantV3FullFixture(t)
	contract, _ := rootGrantsTrustContractFixture(t, f, []string{"instruct", "review"})
	contract.NotBefore = notBefore
	contractBytes, err := CanonicalRootGrantsTrustContract(contract)
	if err != nil {
		t.Fatal("canonical trust fixture", err)
	}
	contractHash := rootGrantsHashHex(contractBytes)
	grant := f.g
	grant.Network, grant.Genesis = f.p.Network, f.p.Genesis
	grant.AgentName, grant.LandlordName = contract.AgentName, contract.LandlordName
	grant.IssuerKey, grant.GranteeKey, grant.GranteeName = f.r.PublicKey, contract.GranteeKey, f.p.GranteeName
	grant.ContractSHA256, grant.Scope = contractHash, []string{}
	grant.NotBefore, grant.NotAfter, grant.Budget = contract.NotBefore, contract.NotAfter, nil
	grant.Consent.ConsentEvent.Tags[1][1] = contractHash
	grantV3TestConsent(t, &grant)
	authority := rootGrantsTrustAuthorityV2ForContractFixture(t, f, contract, contractBytes)
	authority.Scope = rootGrantsTrustDerivedGrantV3Scope(contract.Actions)
	authorityBytes, err := json.Marshal(authority)
	if err != nil {
		t.Fatal("marshal trust authority fixture", err)
	}
	return rootGrantsTrustGrantFixture{
		grant: grant, grantBytes: rootGrantsRaw13(t, grant), contract: contract,
		contractBytes: contractBytes, authority: authority, authorityBytes: authorityBytes,
		metadata: rootGrantsRaw13(t, f.r), owner: f.p.OwnerPrincipal, at: time.Unix(100, 0),
	}
}

func rootGrantsTrustGrantV3FailureCode(err error) string {
	var failure *RootGrantsGrantV3Failure
	if errors.As(err, &failure) && failure != nil {
		return failure.Code
	}
	var refusal *Refusal
	if errors.As(err, &refusal) && refusal != nil {
		return strings.TrimPrefix(refusal.Code, "recovery_")
	}
	return ""
}

func rootGrantsTrustGrantV3ExpectRefusal(t *testing.T, fixture rootGrantsTrustGrantFixture,
	code string) {
	t.Helper()
	inputs := [][]byte{fixture.grantBytes, fixture.contractBytes, fixture.authorityBytes, fixture.metadata}
	before := make([][]byte, len(inputs))
	for i := range inputs {
		before[i] = bytes.Clone(inputs[i])
	}
	plan, err := PrepareRootGrantsGrantV3(fixture.grantBytes, fixture.contractBytes,
		fixture.authorityBytes, fixture.metadata, fixture.owner, fixture.at)
	if plan != nil || rootGrantsTrustGrantV3FailureCode(err) != code {
		t.Fatalf("expected %s with no plan, got plan=%v err=%v", code, plan != nil, err)
	}
	for i := range inputs {
		if !bytes.Equal(inputs[i], before[i]) {
			t.Fatal("refused public input was mutated")
		}
	}
}

// Claim: an approved trust/2 Grant with no derived v3 actions prepares the
// existing prefixed Grant digest, and the exact contract digest signature is
// valid only for the consent purpose, not for final Grant v3.
func TestRootGrantsGrantV3TrustPlanAndPurposeSeparation(t *testing.T) {
	f := rootGrantsTrustGrantV3Fixture(t, 100)
	plan, err := PrepareRootGrantsGrantV3(f.grantBytes, f.contractBytes, f.authorityBytes,
		f.metadata, f.owner, f.at)
	if err != nil || plan == nil {
		t.Fatalf("approved synthetic trust Grant refused: %v", err)
	}
	if !bytes.Equal(plan.contract, f.contractBytes) || !bytes.Equal(plan.authority, f.authorityBytes) ||
		!bytes.Equal(plan.record, f.metadata) {
		t.Fatal("plan did not retain the exact approved public snapshots")
	}
	if digest, digestErr := rootGrantsGrantV3Digest(f.grantBytes); digestErr != nil || digest != plan.message {
		t.Fatal("trust branch changed the existing prefixed Grant v3 digest")
	}
	if len(f.grant.Scope) != 0 || f.grant.Scope == nil {
		t.Fatal("the instruct/review-only fixture must carry an explicit empty v3 scope")
	}

	grantDigest, err := rootGrantsGrantV3Digest(f.grantBytes)
	if err != nil {
		t.Fatal(err)
	}
	var scalar, aux [32]byte
	scalar[31] = 3 // Public synthetic fixture key matching the full issuer K.
	grantSignature, err := signNostrWithAux(scalar[:], grantDigest[:], aux)
	clear(scalar[:])
	if err != nil || plan.VerifySignature(grantSignature) != nil {
		t.Fatal("valid final Grant v3 signature failed its own purpose")
	}
	contractDigest := sha256.Sum256(f.contractBytes)
	scalar[31] = 3
	contractSignature, err := signNostrWithAux(scalar[:], contractDigest[:], aux)
	clear(scalar[:])
	if err != nil || plan.VerifySignature(contractSignature) == nil {
		t.Fatal("contract-purpose signature was accepted as a final Grant v3 signature")
	}
	if !rootGrantsVerifyHash(f.grant.IssuerKey, hex.EncodeToString(contractDigest[:]), f.grant.Consent.LandlordSig) {
		t.Fatal("valid contract-purpose consent signature failed its own purpose")
	}
	if rootGrantsVerifyHash(f.grant.IssuerKey, hex.EncodeToString(contractDigest[:]), hex.EncodeToString(grantSignature)) {
		t.Fatal("final Grant v3 signature was accepted for the raw contract digest")
	}
}

// Claim: trust binding refusals leave inputs untouched and return no plan; the
// adjacent approved empty-scope fixture above prevents reject-everything success.
func TestRootGrantsGrantV3TrustBindingRefusals(t *testing.T) {
	t.Run("contract-hash-before-consent", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		f.grant.ContractSHA256 = strings.Repeat("0", 64)
		f.grantBytes = rootGrantsRaw13(t, f.grant) // Existing consent now also fails; binding order owns contract hash.
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "contract_mismatch")
	})
	t.Run("empty-scope-is-not-wildcard", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		f.grant.Scope = []string{"repository.push"}
		f.grantBytes = rootGrantsRaw13(t, f.grant)
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "contract_mismatch")
	})
	t.Run("nonzero-budget", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		budget := int64(1)
		f.grant.Budget = &budget
		f.grantBytes = rootGrantsRaw13(t, f.grant)
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "contract_mismatch")
	})
	t.Run("common-field-mismatch", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		f.grant.LandlordName = "id/different-owner"
		f.grantBytes = rootGrantsRaw13(t, f.grant)
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "contract_mismatch")
	})
	t.Run("unapproved-but-valid-contract", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		f.contract.Note = "unapproved public fixture"
		var err error
		f.contractBytes, err = CanonicalRootGrantsTrustContract(f.contract)
		if err != nil {
			t.Fatal("canonical changed trust fixture", err)
		}
		f.grant.ContractSHA256 = rootGrantsHashHex(f.contractBytes)
		f.grant.Consent.ConsentEvent.Tags[1][1] = f.grant.ContractSHA256
		grantV3TestConsent(t, &f.grant)
		f.grantBytes = rootGrantsRaw13(t, f.grant)
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "authority_mismatch")
	})
	t.Run("trust-1-does-not-fall-through-to-rental", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		f.authority.ApprovedContract.Profile = "swarma-trust-contract/1"
		f.authorityBytes, _ = json.Marshal(f.authority)
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "unsupported_version")
	})
	t.Run("wrong-derived-authority-scope", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		f.authority.Scope = []string{"repository.push"}
		f.authorityBytes, _ = json.Marshal(f.authority)
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "authority_mismatch")
	})
	t.Run("authority-window-expired", func(t *testing.T) {
		f := rootGrantsTrustGrantV3Fixture(t, 100)
		f.at = time.Unix(2000, 0)
		rootGrantsTrustGrantV3ExpectRefusal(t, f, "authority_mismatch")
	})
}

// Claim: a future grant start remains issuable within the authority window;
// signing time must be within authority validity and before grant expiry only.
func TestRootGrantsGrantV3TrustFutureStartIsAllowed(t *testing.T) {
	f := rootGrantsTrustGrantV3Fixture(t, 500)
	if plan, err := PrepareRootGrantsGrantV3(f.grantBytes, f.contractBytes, f.authorityBytes,
		f.metadata, f.owner, f.at); err != nil || plan == nil {
		t.Fatalf("future grant start was rejected at valid authority time: %v", err)
	}
}

// Claim: the fixed-source loader accepts an owner-owned, mode-0600 approved
// public fixture and refuses missing, symlinked, or overly open source files.
func TestRootGrantsTrustAuthorityV2FixedSourceLoader(t *testing.T) {
	_, authorityBytes := rootGrantsTrustAuthorityV2WireFixture(t)
	f := grantV3FullFixture(t)
	address := RootGrantsAddress{Service: f.r.Service, Version: f.r.Version}
	dir := t.TempDir()
	path := filepath.Join(dir, "authority.json")
	if err := os.WriteFile(path, authorityBytes, 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := rootGrantsLoadAuthorityFile(path, address)
	if err != nil || !bytes.Equal(loaded, authorityBytes) {
		t.Fatalf("valid fixed-source seam refused exact public authority bytes: %v", err)
	}
	clear(loaded)
	if _, err := rootGrantsLoadAuthorityFile(filepath.Join(dir, "missing.json"), address); err == nil {
		t.Fatal("missing authority source unexpectedly loaded")
	}
	openPath := filepath.Join(dir, "open.json")
	if err := os.WriteFile(openPath, authorityBytes, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := rootGrantsLoadAuthorityFile(openPath, address); err == nil {
		t.Fatal("overly open authority source unexpectedly loaded")
	}
	linkPath := filepath.Join(dir, "symlink.json")
	if err := os.Symlink(path, linkPath); err != nil {
		t.Fatal(err)
	}
	if _, err := rootGrantsLoadAuthorityFile(linkPath, address); err == nil {
		t.Fatal("symlinked authority source unexpectedly loaded")
	}
}
