package keyvault

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
	"github.com/relux-works/swarma-keyvault/internal/namecoinwire"
)

const process2MaxPairCiphertextBytes = 65536

// RecoveryProcess2Input contains only public selection and canonical ciphertext
// material. The caller must source it through the existing fixed selected
// profile and vault-owned pair read; this value proves neither source provenance
// nor native admission, Keychain ACL state, owner presence, or consent.
type RecoveryProcess2Input struct {
	Selection  namecoinpsbt.NativeSelection
	AccountPin []byte
	Sidecar    []byte
	Record     []byte
	Pair       []byte
}

// BuildRecoveryProcess2Frame validates the entire selected pair before
// projecting only its Namecoin envelope and exact public metadata into one
// bounded process/2 frame. It never accepts or returns plaintext or the
// Nostr-only ciphertext. The returned frame is sensitive transport data and
// must not be logged or persisted by a production caller.
func BuildRecoveryProcess2Frame(input RecoveryProcess2Input) ([]byte, error) {
	invalidRecord := func() ([]byte, error) { return nil, recoveryRefuse("invalid_record") }
	invalidEnvelope := func() ([]byte, error) { return nil, recoveryRefuse("invalid_envelope") }
	if len(input.AccountPin) == 0 || len(input.AccountPin) > 32768 || len(input.Sidecar) == 0 || len(input.Sidecar) > namecoinprocess.Process2MaxSidecarBytes ||
		len(input.Record) == 0 || len(input.Record) > namecoinprocess.Process2MaxRecordBytes || len(input.Pair) == 0 || len(input.Pair) > process2MaxPairCiphertextBytes {
		return invalidRecord()
	}
	if input.Selection.Schema != "keyvault-namecoin-native-selection/1" {
		return invalidRecord()
	}
	r, err := parseRecoveryRecord(input.Record)
	if err != nil {
		return invalidRecord()
	}
	ciphertext, err := parseRecoveryCiphertext(input.Pair, r)
	if err != nil {
		return invalidEnvelope()
	}
	selected := input.Selection.Selection
	if selected.Group != r.Account() || selected.Account != r.PurposeAccount(r.Namecoin) || selected.Policy.Revision == "" {
		return invalidRecord()
	}

	pinHash, err := hex.DecodeString(selected.AccountPinSHA256)
	if err != nil || len(pinHash) != 32 || hex.EncodeToString(pinHash) != selected.AccountPinSHA256 {
		return invalidRecord()
	}
	actualPinHash := sha256.Sum256(input.AccountPin)
	if !bytes.Equal(actualPinHash[:], pinHash) {
		return invalidRecord()
	}
	pin, err := namecoinwire.DecodeAccountPin(input.AccountPin)
	if err != nil || pin.Group != selected.Group || pin.Account != selected.Account || pin.AccountXPub != r.Namecoin.XPub ||
		pin.MasterFingerprint == "" || r.Namecoin.Origin != "["+pin.MasterFingerprint+"/"+pin.AccountPath[len("m/"):]+"]" {
		return invalidRecord()
	}

	var publicPin [32]byte
	copy(publicPin[:], pinHash)
	if input.Selection.Sidecar.Binding.Group != selected.Group || input.Selection.Sidecar.Binding.Account != selected.Account ||
		input.Selection.Sidecar.Binding.PublicPin != publicPin || input.Selection.Sidecar.Binding.Policy != selected.Policy.Revision {
		return invalidRecord()
	}
	wantSidecar, err := namecoinjournal.EncodeSidecar(input.Selection.Sidecar)
	if err != nil || !bytes.Equal(wantSidecar, input.Sidecar) {
		return invalidRecord()
	}
	sidecar, err := namecoinjournal.DecodeSidecar(input.Sidecar, input.Selection.Sidecar)
	if err != nil || sidecar.NostrAccount != r.PurposeAccount(r.Nostr) {
		return invalidRecord()
	}
	groupID, err := hex.DecodeString(r.GroupID)
	if err != nil || len(groupID) != 16 || !bytes.Equal(groupID, sidecar.GroupID[:]) {
		return invalidRecord()
	}
	nostrPublic, err := hex.DecodeString(r.Nostr.PublicKey)
	if err != nil || len(nostrPublic) != len(sidecar.NostrPublicPin) || !bytes.Equal(nostrPublic, sidecar.NostrPublicPin[:]) {
		return invalidRecord()
	}
	if sidecar.VerifyPairedBytes(input.Record, input.Pair) != nil {
		return invalidEnvelope()
	}

	namecoin := ciphertext.Namecoin
	var point [65]byte
	var sealed [181]byte
	copy(point[:], namecoin.Point)
	copy(sealed[:], namecoin.Ciphertext)
	envelope := namecoinprocess.OpaqueEnvelope{
		Blob:          bytes.Clone(namecoin.EnclaveBlob),
		WrappingPoint: point,
		Ciphertext:    sealed,
		Binding:       recoveryBinding(r, r.Namecoin),
	}
	metadata := namecoinprocess.Process2Metadata{
		Service:          recoveryAdoptionService,
		PhysicalAccount:  r.Account(),
		AccountPinSHA256: actualPinHash,
		Sidecar:          bytes.Clone(input.Sidecar),
		Record:           bytes.Clone(input.Record),
	}
	frame, err := namecoinprocess.EncodeProcess2CustodyFrame(namecoinprocess.Process2CustodyFrame{Metadata: metadata, Envelope: envelope})
	if err != nil {
		return invalidEnvelope()
	}
	return frame, nil
}
