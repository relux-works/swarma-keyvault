package codesigntest

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const RecoveryObservationPrefix = "codesigntest recovery observation: "

// CheckRecoveryEvidence checks the actual native status reported by each child
// verifier and the helper's own request receipt in the retained directory.
func CheckRecoveryEvidence(out []byte, run string) error {
	dirs, err := filepath.Glob(filepath.Join(run, "identity-*"))
	if err != nil || len(dirs) != 1 {
		return errors.New("expected one retained recovery identity directory")
	}
	if err := ownedDir(dirs[0], true); err != nil {
		return err
	}
	for _, mode := range []string{"hardened", "no-runtime", "wrong-hash", "debug-entitlement"} {
		if !bytes.Contains(out, []byte("--- PASS: TestRecoveryActualChildCodeBoundary/"+mode+" (")) {
			return fmt.Errorf("recovery native identity mode %s did not pass", mode)
		}
		accepted := mode == "hardened"
		status := -25293
		if accepted {
			status = 0
		}
		prefix := RecoveryObservationPrefix + mode + " "
		want := fmt.Sprintf("%sstatus=%d accepted=%t\n", prefix, status, accepted)
		if bytes.Count(out, []byte(prefix)) != 1 || !bytes.Contains(out, []byte(want)) {
			return fmt.Errorf("recovery native status for %s did not match its expected outcome", mode)
		}
		dir := filepath.Join(dirs[0], mode)
		if err := ownedDir(dir, true); err != nil {
			return err
		}
		if accepted {
			receipt, err := readState(dir, "pass.received")
			if err != nil || string(receipt) != "request received" {
				return errors.New("admitted recovery fixture did not record request receipt")
			}
		} else if _, err := os.Lstat(filepath.Join(dir, "pass.received")); !os.IsNotExist(err) {
			return fmt.Errorf("refused recovery fixture %s has a receipt or unknown request state", mode)
		}
	}
	return nil
}
