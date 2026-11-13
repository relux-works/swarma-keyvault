package keyvault

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

type rootGrantsSignVaultFake struct {
	snapshot RootGrantsSigningSnapshot
	err      error
	calls    int
	address  RootGrantsAddress
	digest   string
	mutate   func(*RootGrantsSigningSnapshot)
}

func (v *rootGrantsSignVaultFake) ReadRootGrantsForSigning(ctx context.Context, address RootGrantsAddress, digest string) (RootGrantsSigningSnapshot, error) {
	v.calls++
	v.address, v.digest = address, digest
	if err := ctx.Err(); err != nil {
		return RootGrantsSigningSnapshot{}, err
	}
	if v.mutate != nil {
		v.mutate(&v.snapshot)
	}
	return v.snapshot, v.err
}

func rootGrantsSignSnapshotFixture(t *testing.T, schema string) (RootGrantsSigningSnapshot, RootGrantsAuthority) {
	t.Helper()
	r, pair := rootGrantsRecordFixture13(t, schema)
	metadata, err := CanonicalRootGrantsRecord(r)
	if err != nil {
		t.Fatal(err)
	}
	envelope := rootGrantsEnvelopeFixture13(t, r)
	sealed, err := CanonicalRootGrantsEnvelope(envelope, r)
	if err != nil {
		t.Fatal(err)
	}
	policy := RootGrantsAuthority{Schema: "namecoin-root-grants-authority/1", OwnerPrincipal: "owner:id/example-owner",
		LandlordName: "id/example-landlord", Network: "regtest", Genesis: "0f9188f13cb7b2c71f2a335e3a4fc328bf5beb436012afca590b1a11466e2206",
		Record: RootGrantsAuthorityRecord{Service: r.Service, Version: r.Version, MetadataSHA256: rootGrantsHashHex(metadata), PublicKey: r.PublicKey, SealScript: r.SealScript}}
	return RootGrantsSigningSnapshot{Metadata: metadata, Envelope: sealed, PairMetadata: pair}, policy
}

// The read-only vault contract consumes one explicit address/digest, owns no
// value output and clones only sealed/public bytes. The frozen ciphertext helper
// is intentionally from an unrelated role: passing shape is never authenticity.
func TestRootGrantsGrantV3VaultSnapshotRead(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		snapshot, policy := rootGrantsSignSnapshotFixture(t, schema)
		want := RootGrantsSigningSnapshot{Metadata: bytes.Clone(snapshot.Metadata), Envelope: bytes.Clone(snapshot.Envelope), PairMetadata: bytes.Clone(snapshot.PairMetadata)}
		address := RootGrantsAddress{Service: policy.Record.Service, Version: policy.Record.Version}
		vault := &rootGrantsSignVaultFake{snapshot: snapshot}
		got, record, err := rootGrantsSnapshotForSigning(context.Background(), vault, address, policy)
		if err != nil || vault.calls != 1 || vault.address != address || vault.digest != policy.Record.MetadataSHA256 || record.PublicKey != policy.Record.PublicKey {
			t.Fatalf("eligible retained record refused: %v", err)
		}
		clear(got.Metadata)
		clear(got.Envelope)
		clear(got.PairMetadata)
		if !rootGrantsSigningSnapshotsEqual(vault.snapshot, want) {
			t.Fatal("returned snapshot aliases the vault-owned buffers")
		}
	}
}

// Address, context, metadata, envelope and retained-pair mismatches refuse with
// no caller-held result. The neighboring exact snapshots remain admissible.
func TestRootGrantsGrantV3VaultSnapshotRefusals(t *testing.T) {
	for _, schema := range []string{"keyvault-recovery/1", "keyvault-recovery/2"} {
		t.Run(schema, func(t *testing.T) {
			snapshot, policy := rootGrantsSignSnapshotFixture(t, schema)
			address := RootGrantsAddress{Service: policy.Record.Service, Version: policy.Record.Version}
			for _, c := range []struct {
				name, code string
				ctx        context.Context
				address    RootGrantsAddress
				policyEdit func(*RootGrantsAuthority)
				mutate     func(*RootGrantsSigningSnapshot)
			}{
				{"changed-address-before-read", "authority_mismatch", context.Background(), RootGrantsAddress{Service: "other", Version: address.Version}, nil, nil},
				{"canceled-before-read", "canceled", canceledContext(t), address, nil, nil},
				{"metadata-byte", "public_pin_mismatch", context.Background(), address, func(p *RootGrantsAuthority) { p.Record.PublicKey = rootGrantsOtherXOnly }, nil},
				{"empty-envelope", "invalid_envelope", context.Background(), address, nil, func(s *RootGrantsSigningSnapshot) { s.Envelope = nil }},
				{"bad-envelope-canonical", "invalid_envelope", context.Background(), address, nil, func(s *RootGrantsSigningSnapshot) { s.Envelope = append(s.Envelope, '\n') }},
				{"retained-pair-byte", "retained_record_mismatch", context.Background(), address, nil, func(s *RootGrantsSigningSnapshot) { s.PairMetadata[0] ^= 1 }},
			} {
				t.Run(c.name, func(t *testing.T) {
					p := policy
					if c.policyEdit != nil {
						c.policyEdit(&p)
					}
					vault := &rootGrantsSignVaultFake{snapshot: RootGrantsSigningSnapshot{Metadata: bytes.Clone(snapshot.Metadata), Envelope: bytes.Clone(snapshot.Envelope), PairMetadata: bytes.Clone(snapshot.PairMetadata)}, mutate: c.mutate}
					got, _, err := rootGrantsSnapshotForSigning(c.ctx, vault, c.address, p)
					rootGrantsWantRefusal(t, err, c.code)
					if got.Metadata != nil || got.Envelope != nil || got.PairMetadata != nil {
						t.Fatal("refusal returned a partial snapshot")
					}
					if c.address != address && vault.calls != 0 || c.ctx.Err() != nil && vault.calls != 0 {
						t.Fatal("invalid address/canceled attempt reached the vault")
					}
				})
			}
		})
	}
}

type rootGrantsCanceledContext struct{ context.Context }

func (rootGrantsCanceledContext) Err() error { return context.Canceled }

func canceledContext(t *testing.T) context.Context {
	t.Helper()
	return rootGrantsCanceledContext{Context: context.Background()}
}

// The vault's opaque error text never crosses the signing boundary.
func TestRootGrantsGrantV3VaultErrorIsClosed(t *testing.T) {
	snapshot, policy := rootGrantsSignSnapshotFixture(t, "keyvault-recovery/2")
	vault := &rootGrantsSignVaultFake{snapshot: snapshot, err: errors.New("PUBLIC_TEST_ERROR_SENTINEL")}
	got, _, err := rootGrantsSnapshotForSigning(context.Background(), vault,
		RootGrantsAddress{Service: policy.Record.Service, Version: policy.Record.Version}, policy)
	var failure *RootGrantsGrantV3Failure
	if !errors.As(err, &failure) || failure == nil || failure.Code != "operation_unavailable" || failure.Phase != "read" || failure.Outcome != "not_applied" {
		t.Fatalf("opaque vault failure was not mapped to a closed refusal: %v", err)
	}
	if got.Metadata != nil || got.Envelope != nil || got.PairMetadata != nil || vault.calls != 1 {
		t.Fatal("opaque vault error leaked a partial result")
	}
}
