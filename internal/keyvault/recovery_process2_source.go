package keyvault

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"

	"github.com/relux-works/swarma-keyvault/internal/namecoinjournal"
	"github.com/relux-works/swarma-keyvault/internal/namecoinprocess"
	"github.com/relux-works/swarma-keyvault/internal/namecoinpsbt"
)

// PrepareNamecoinProcess2 reads only the selected complete pair under the
// existing vault mutation guard. It creates no lock, item, key or journal.
// The CLI receives only the Namecoin projection, never the paired value.
func PrepareNamecoinProcess2(ctx context.Context, prepared namecoinprocess.Prepared) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || prepared.Mode() != namecoinprocess.SignPSBT {
		return nil, recoveryRefuse("invalid_record")
	}
	lock, err := DefaultFileLock()
	if err != nil {
		return nil, recoveryRefuse("lock_unavailable")
	}
	guard, err := lockRootGrantsExisting(ctx, lock)
	if err != nil {
		return nil, err
	}
	defer guard.Release()
	return projectSelectedRecoveryProcess2(ctx, prepared.NativeSelection(), prepared.PinBytes(), recoveryNativeProcess2Pair)
}

type recoveryProcess2PairReader func(context.Context, string, [32]byte) ([]byte, []byte, error)

func projectSelectedRecoveryProcess2(ctx context.Context, selected namecoinpsbt.NativeSelection, pin []byte, read recoveryProcess2PairReader) ([]byte, error) {
	if ctx == nil || ctx.Err() != nil || read == nil || selected.Schema != "keyvault-namecoin-native-selection/1" ||
		len(pin) == 0 || len(pin) > 32768 || hex.EncodeToString(selected.Sidecar.Binding.PublicPin[:]) != selected.Selection.AccountPinSHA256 ||
		sha256.Sum256(pin) != selected.Sidecar.Binding.PublicPin || selected.Sidecar.Binding.Group != selected.Selection.Group ||
		selected.Sidecar.Binding.Account != selected.Selection.Account || selected.Sidecar.Binding.Policy != selected.Selection.Policy.Revision {
		return nil, recoveryRefuse("invalid_record")
	}
	sidecar, err := namecoinjournal.EncodeSidecar(selected.Sidecar)
	if err != nil {
		return nil, recoveryRefuse("invalid_record")
	}
	record, pair, err := read(ctx, selected.Selection.Group, selected.Sidecar.MetadataHash)
	defer clear(pair)
	if err != nil {
		return nil, err
	}
	if ctx.Err() != nil {
		return nil, recoveryRefuse("auth_refused")
	}
	return BuildRecoveryProcess2Frame(RecoveryProcess2Input{Selection: selected, AccountPin: pin, Sidecar: sidecar, Record: record, Pair: pair})
}

// AdmitNamecoinProcess2Child checks only the handle retained by RunProcess2,
// synchronously before that runner permits wait/reap or releases fd5. The third
// argument is an attempt binding, never a CDHash or caller-selected code pin.
func AdmitNamecoinProcess2Child(ctx context.Context, child *os.Process, _ [32]byte) error {
	return admitNamecoinProcess2Child(ctx, child, recoveryHelperCDHash, VerifyNamecoinProcessHelper)
}

func admitNamecoinProcess2Child(ctx context.Context, child *os.Process, pinned string, verify func(int, []byte) error) error {
	pin, err := hex.DecodeString(pinned)
	if ctx == nil || ctx.Err() != nil || child == nil || child.Pid <= 0 || verify == nil || err != nil ||
		(len(pin) != 20 && len(pin) != 32) || hex.EncodeToString(pin) != pinned {
		return recoveryRefuse("helper_not_admitted")
	}
	if err := verify(child.Pid, pin); err != nil || ctx.Err() != nil {
		return recoveryRefuse("helper_not_admitted")
	}
	return nil
}
