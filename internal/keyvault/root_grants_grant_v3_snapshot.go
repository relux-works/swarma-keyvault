package keyvault

import (
	"bytes"
	"context"
)

// RootGrantsSigningSnapshot is public metadata plus the existing sealed device
// envelope. The only approved future producer is the existing-guard native vault
// read described in out/VAULT-INTERFACE-NEED.md. This type proves no decryption,
// presence, key match or native ACL admission by itself.
type RootGrantsSigningSnapshot struct {
	Metadata     []byte
	Envelope     []byte
	PairMetadata []byte
}

type RootGrantsGrantV3SigningVault interface {
	ReadRootGrantsForSigning(context.Context, RootGrantsAddress, string) (RootGrantsSigningSnapshot, error)
}

type rootGrantsSigningVault = RootGrantsGrantV3SigningVault

func rootGrantsSnapshotForSigning(ctx context.Context, vault rootGrantsSigningVault, address RootGrantsAddress,
	policy RootGrantsAuthority) (RootGrantsSigningSnapshot, RootGrantsRecord, error) {
	var empty RootGrantsSigningSnapshot
	if ctx == nil || vault == nil {
		return empty, RootGrantsRecord{}, recoveryRefuse("invalid_arguments")
	}
	if err := ctx.Err(); err != nil {
		return empty, RootGrantsRecord{}, recoveryRefuse(rootGrantsGrantV3ContextCode(err))
	}
	if address != (RootGrantsAddress{Service: policy.Record.Service, Version: policy.Record.Version}) {
		return empty, RootGrantsRecord{}, recoveryRefuse("authority_mismatch")
	}
	snapshot, err := vault.ReadRootGrantsForSigning(ctx, address, policy.Record.MetadataSHA256)
	if err != nil {
		if contextErr := ctx.Err(); contextErr != nil {
			return empty, RootGrantsRecord{}, recoveryRefuse(rootGrantsGrantV3ContextCode(contextErr))
		}
		return empty, RootGrantsRecord{}, rootGrantsGrantV3Failed(rootGrantsGrantV3RefusalCode(err), "read", false)
	}
	owned := RootGrantsSigningSnapshot{Metadata: bytes.Clone(snapshot.Metadata), Envelope: bytes.Clone(snapshot.Envelope), PairMetadata: bytes.Clone(snapshot.PairMetadata)}
	record, err := rootGrantsValidateSigningSnapshot(owned, policy)
	if err != nil {
		clear(owned.Metadata)
		clear(owned.Envelope)
		clear(owned.PairMetadata)
		return empty, RootGrantsRecord{}, err
	}
	if err := ctx.Err(); err != nil {
		clear(owned.Metadata)
		clear(owned.Envelope)
		clear(owned.PairMetadata)
		return empty, RootGrantsRecord{}, recoveryRefuse(rootGrantsGrantV3ContextCode(err))
	}
	return owned, record, nil
}

func rootGrantsValidateSigningSnapshot(snapshot RootGrantsSigningSnapshot, policy RootGrantsAuthority) (RootGrantsRecord, error) {
	if len(snapshot.Metadata) == 0 || len(snapshot.Metadata) > 32768 || len(snapshot.Envelope) == 0 || len(snapshot.Envelope) > 65536 ||
		len(snapshot.PairMetadata) == 0 || len(snapshot.PairMetadata) > 32768 {
		return RootGrantsRecord{}, recoveryRefuse("invalid_envelope")
	}
	record, err := ParseRootGrantsRecord(snapshot.Metadata)
	if err != nil || record.Service != policy.Record.Service || record.Version != policy.Record.Version ||
		rootGrantsHashHex(snapshot.Metadata) != policy.Record.MetadataSHA256 || record.PublicKey != policy.Record.PublicKey ||
		record.SealScript != policy.Record.SealScript {
		return RootGrantsRecord{}, recoveryRefuse("public_pin_mismatch")
	}
	if _, err := ParseRootGrantsEnvelope(snapshot.Envelope, record); err != nil {
		return RootGrantsRecord{}, recoveryRefuse("invalid_envelope")
	}
	if rootGrantsMatchPair(snapshot.PairMetadata, record.Pair) != nil {
		return RootGrantsRecord{}, recoveryRefuse("retained_record_mismatch")
	}
	return record, nil
}

func rootGrantsSigningSnapshotsEqual(first, current RootGrantsSigningSnapshot) bool {
	return bytes.Equal(first.Metadata, current.Metadata) && bytes.Equal(first.Envelope, current.Envelope) && bytes.Equal(first.PairMetadata, current.PairMetadata)
}
